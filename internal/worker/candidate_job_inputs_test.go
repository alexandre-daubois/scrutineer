package worker

import (
	"encoding/json"
	"strings"
	"testing"

	"scrutineer/internal/db"
)

const retryCandidateReport = `{"findings":[{"id":"F1","title":"SQLi","severity":"Low","cwe":"CWE-89","location":"a.rb:1","trace":"t"}]}`

// A candidate whose staged threat model digest differs from the one its baseline
// recorded fails through the job path with nothing recorded, while a matching digest runs to done.
func TestCandidateJobInputs_stagedInputsMustMatchTheBaseline(t *testing.T) {
	for _, tc := range []struct {
		name             string
		baselineModel    string
		wantStatus       db.ScanStatus
		wantError        string
		wantObservations int
	}{
		{"same threat model", candidateJobThreatModel, db.ScanDone, "", 2},
		{"other threat model", "Attackers reach the admin panel.", db.ScanFailed, "differs from what baseline scan", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			j := newCandidateJob(t, fakeRunner{skillRes: SkillResult{Commit: "abc", Report: candidateReport}})
			if err := j.w.DB.Model(j.baseline).Update("staged_inputs_sha256", stagedDigest(t, tc.baselineModel)).Error; err != nil {
				t.Fatal(err)
			}

			got := j.run(t, j.candidate.ID)

			if got.Status != tc.wantStatus || !strings.Contains(got.Error, tc.wantError) {
				t.Fatalf("candidate = %s %q, want %s with %q", got.Status, got.Error, tc.wantStatus, tc.wantError)
			}
			if obs := candidateObservations(t, j.w, j.candidate.ID); len(obs) != tc.wantObservations {
				t.Errorf("candidate observations = %d, want %d", len(obs), tc.wantObservations)
			}
		})
	}
}

// A run is checked against the scan config it applies, not a recipe sealed at
// an earlier claim, on the candidate side and on the baseline side alike.
func TestCandidateJobInputs_resumedRunChecksTheLiveScanConfig(t *testing.T) {
	const edited = "attack_surface: admin panel"
	for _, tc := range []struct {
		name           string
		scanConfig     string
		baselineConfig string
		wantStatus     db.ScanStatus
		wantError      string
	}{
		{"scan config unchanged", candidateJobScanConfig, candidateJobScanConfig, db.ScanDone, ""},
		{"candidate resumed under an edited config", edited, candidateJobScanConfig, db.ScanFailed, "differs from what baseline scan"},
		{"baseline resumed and finished under the edited config", edited, edited, db.ScanDone, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			j := newCandidateJob(t, fakeRunner{skillRes: SkillResult{Commit: "abc", Report: candidateReport}})
			digest, err := stagedInputsDigest(tc.baselineConfig, j.repo.ThreatModel, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := j.w.DB.Model(j.baseline).Update("staged_inputs_sha256", digest).Error; err != nil {
				t.Fatal(err)
			}
			sealed, err := buildScanRecipe(j.candidate, "", j.repo.ThreatModel, j.repo.ScanConfig)
			if err != nil {
				t.Fatal(err)
			}
			if err := j.w.DB.Model(j.candidate).Update("recipe", sealed).Error; err != nil {
				t.Fatal(err)
			}
			if err := j.w.DB.Model(&db.Repository{}).Where("id = ?", j.repo.ID).Update("scan_config", tc.scanConfig).Error; err != nil {
				t.Fatal(err)
			}

			got := j.run(t, j.candidate.ID)

			if got.Status != tc.wantStatus || !strings.Contains(got.Error, tc.wantError) {
				t.Fatalf("candidate = %s %q, want %s with %q", got.Status, got.Error, tc.wantStatus, tc.wantError)
			}
		})
	}
}

// A retried candidate runs to done with observations of its own, leaving the
// failed first run's observations and the repository findings as they were.
func TestCandidateJobInputs_retryRecordsItsOwnObservations(t *testing.T) {
	j := newCandidateJob(t, fakeRunner{skillRes: SkillResult{Commit: "abc", Report: retryCandidateReport}})
	if err := j.w.parseFindingsOutput(&db.Skill{}, j.baseline,
		`{"findings":[{"id":"F1","title":"SQLi","severity":"High","cwe":"CWE-89","location":"a.rb:1"}]}`, func(Event) {}); err != nil {
		t.Fatal(err)
	}
	var before db.Finding
	if err := j.w.DB.First(&before).Error; err != nil {
		t.Fatal(err)
	}
	if err := j.w.parseCandidateOutput(&db.Skill{OutputKind: "findings"}, j.candidate, candidateReport, func(Event) {}); err != nil {
		t.Fatal(err)
	}
	if err := j.w.DB.Model(j.candidate).Update("status", db.ScanFailed).Error; err != nil {
		t.Fatal(err)
	}
	retry := &db.Scan{RepositoryID: j.repo.ID, Kind: JobSkill, SkillName: j.candidate.SkillName, SkillID: j.candidate.SkillID,
		Status: db.ScanQueued, Model: j.candidate.Model, Commit: "abc", Experiment: "trial",
		CandidateOfScanID: &j.baseline.ID, ParentScanID: &j.candidate.ID}
	if err := j.w.DB.Create(retry).Error; err != nil {
		t.Fatal(err)
	}

	got := j.run(t, retry.ID)

	if got.Status != db.ScanDone {
		t.Fatalf("retry status = %s (%q), want done", got.Status, got.Error)
	}
	if rows := candidateObservations(t, j.w, retry.ID); len(rows) != 1 || rows[0].Severity != "Low" || rows[0].Fingerprint != before.Fingerprint {
		t.Errorf("retry observations = %+v, want its one Low SQLi on the baseline finding's fingerprint", rows)
	}
	if rows := candidateObservations(t, j.w, j.candidate.ID); len(rows) != 2 || rows[0].Severity != "High" || rows[1].Title != "Path traversal" {
		t.Errorf("first run observations after retry = %+v, want its own two rows untouched", rows)
	}
	var findings []db.Finding
	if err := j.w.DB.Find(&findings).Error; err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].SeenCount != before.SeenCount || findings[0].LastSeenScanID != before.LastSeenScanID ||
		findings[0].MissedCount != before.MissedCount || findings[0].Severity != before.Severity {
		t.Errorf("findings after retry = %+v, want the baseline row unchanged", findings)
	}
}

// The claim seals the candidate's recipe with its experiment, configuration
// snapshot and baseline, and the run stores the report on the candidate row only.
func TestCandidateJobInputs_claimSealsRecipeAndReportStaysOnTheCandidate(t *testing.T) {
	const experimentConfig = `{"model":"model-b","effort":"low"}`
	const baselineReport = `{"findings":[]}`
	j := newCandidateJob(t, fakeRunner{skillRes: SkillResult{Commit: "abc", Report: candidateReport}})
	if err := j.w.DB.Model(j.candidate).Update("experiment_config", experimentConfig).Error; err != nil {
		t.Fatal(err)
	}
	if err := j.w.DB.Model(j.baseline).Update("report", baselineReport).Error; err != nil {
		t.Fatal(err)
	}

	got := j.run(t, j.candidate.ID)

	if got.Status != db.ScanDone {
		t.Fatalf("candidate status = %s (%q), want done", got.Status, got.Error)
	}
	var recipe struct {
		Experiment        string          `json:"experiment"`
		ExperimentConfig  json.RawMessage `json:"experiment_config"`
		CandidateOfScanID *uint           `json:"candidate_of_scan_id"`
	}
	if err := json.Unmarshal([]byte(got.Recipe), &recipe); err != nil {
		t.Fatalf("candidate recipe %q: %v", got.Recipe, err)
	}
	if recipe.Experiment != "trial" {
		t.Errorf("recipe experiment = %q, want trial", recipe.Experiment)
	}
	if string(recipe.ExperimentConfig) != experimentConfig {
		t.Errorf("recipe experiment_config = %s, want %s", recipe.ExperimentConfig, experimentConfig)
	}
	if recipe.CandidateOfScanID == nil || *recipe.CandidateOfScanID != j.baseline.ID {
		t.Errorf("recipe candidate_of_scan_id = %v, want %d", recipe.CandidateOfScanID, j.baseline.ID)
	}
	if got.Report != candidateReport {
		t.Errorf("candidate report = %q, want the candidate's own report", got.Report)
	}
	var baseline db.Scan
	if err := j.w.DB.Select("report").First(&baseline, j.baseline.ID).Error; err != nil {
		t.Fatal(err)
	}
	if baseline.Report != baselineReport {
		t.Errorf("baseline report = %q, want %q unchanged", baseline.Report, baselineReport)
	}
}
