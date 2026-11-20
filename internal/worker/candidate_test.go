package worker

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"scrutineer/internal/db"
)

func candidatePair(t *testing.T, w *Worker, repo db.Repository) (baseline, candidate *db.Scan) {
	t.Helper()
	baseline = &db.Scan{RepositoryID: repo.ID, Kind: JobSkill, SkillName: "security-deep-dive", Status: db.ScanDone,
		Model: "model-a", Commit: "abc", Experiment: "trial"}
	if err := w.DB.Create(baseline).Error; err != nil {
		t.Fatal(err)
	}
	candidate = &db.Scan{RepositoryID: repo.ID, Kind: JobSkill, SkillName: "deep-dive-v2", Status: db.ScanRunning,
		Model: "model-b", Commit: "abc", Experiment: "trial", CandidateOfScanID: &baseline.ID}
	if err := w.DB.Create(candidate).Error; err != nil {
		t.Fatal(err)
	}
	return baseline, candidate
}

func candidateObservations(t *testing.T, w *Worker, scanID uint) []db.CandidateObservation {
	t.Helper()
	var rows []db.CandidateObservation
	if err := w.DB.Where("scan_id = ?", scanID).Order("id").Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	return rows
}

const candidateReport = `{"findings":[
	{"id":"F1","title":"SQLi","severity":"High","cwe":"CWE-89","location":"a.rb:1","trace":"t"},
	{"id":"F2","title":"Path traversal","severity":"Critical","cwe":"CWE-22","location":"b.rb:9","trace":"t"}]}`

func TestCandidate_existingAndNewVulnerabilitiesStayOutOfFindings(t *testing.T) {
	w, repo := observationWorker(t)
	baseline, candidate := candidatePair(t, w, repo)
	created := 0
	w.OnFindingCreated = func(*db.Scan, *db.Finding) { created++ }
	if err := w.parseFindingsOutput(&db.Skill{}, baseline,
		`{"findings":[{"id":"F1","title":"SQLi","severity":"High","cwe":"CWE-89","location":"a.rb:1"}]}`, func(Event) {}); err != nil {
		t.Fatal(err)
	}
	var before db.Finding
	w.DB.First(&before)
	created = 0

	if err := w.parseSkillOutputKind(t.Context(), &db.Skill{Name: "deep-dive-v2", OutputKind: "findings", FailOn: "low"}, candidate, candidateReport, func(Event) {}); err != nil {
		t.Fatalf("candidate parse: %v", err)
	}

	var findings []db.Finding
	w.DB.Find(&findings)
	if len(findings) != 1 || findings[0].SeenCount != before.SeenCount || findings[0].LastSeenScanID != before.LastSeenScanID ||
		findings[0].MissedCount != before.MissedCount || findings[0].Status != before.Status {
		t.Fatalf("findings after candidate = %+v, want the baseline row unchanged", findings)
	}
	if created != 0 {
		t.Errorf("OnFindingCreated fired %d times for a candidate", created)
	}
	if obs := observationsOf(t, w, before.ID); len(obs) != 1 || obs[0].ScanID != baseline.ID {
		t.Errorf("finding observations = %+v, want only the baseline's", obs)
	}
	got := candidateObservations(t, w, candidate.ID)
	if len(got) != 2 {
		t.Fatalf("candidate observations = %d, want 2", len(got))
	}
	if got[0].Fingerprint != before.Fingerprint {
		t.Errorf("existing vulnerability fingerprint %q, want the baseline finding's %q despite the different skill", got[0].Fingerprint, before.Fingerprint)
	}
	if got[1].Title != "Path traversal" || got[1].Severity != "Critical" || got[1].RepositoryID != repo.ID || !strings.Contains(got[1].Evidence, `"trace"`) {
		t.Errorf("new vulnerability observation = %+v", got[1])
	}
}

func TestCandidate_reingestKeepsAssessmentAndRetryKeepsEarlierRun(t *testing.T) {
	w, repo := observationWorker(t)
	baseline, first := candidatePair(t, w, repo)
	skill := &db.Skill{OutputKind: "findings"}
	if err := w.parseCandidateOutput(skill, first, candidateReport, func(Event) {}); err != nil {
		t.Fatal(err)
	}
	w.DB.Model(&db.CandidateObservation{}).Where("scan_id = ?", first.ID).Update("assessment", db.CandidateConfirmed)
	if err := w.parseCandidateOutput(skill, first, candidateReport, func(Event) {}); err != nil {
		t.Fatal(err)
	}
	rows := candidateObservations(t, w, first.ID)
	if len(rows) != 2 || rows[0].Assessment != db.CandidateConfirmed {
		t.Fatalf("re-ingested observations = %+v, want 2 rows keeping their assessment", rows)
	}

	retry := &db.Scan{RepositoryID: repo.ID, Kind: JobSkill, SkillName: "security-deep-dive", Status: db.ScanRunning,
		Commit: "abc", Experiment: "trial", CandidateOfScanID: &baseline.ID, ParentScanID: &first.ID}
	w.DB.Create(retry)
	if err := w.parseCandidateOutput(skill, retry, `{"findings":[{"id":"F1","title":"SQLi","severity":"Low","cwe":"CWE-89","location":"a.rb:1"}]}`, func(Event) {}); err != nil {
		t.Fatal(err)
	}
	if rows := candidateObservations(t, w, first.ID); len(rows) != 2 || rows[0].Severity != "High" {
		t.Errorf("first run after retry = %+v, want its own rows untouched", rows)
	}
	if rows := candidateObservations(t, w, retry.ID); len(rows) != 1 || rows[0].Severity != "Low" {
		t.Errorf("retry observations = %+v", rows)
	}
}

func TestCandidate_refusesOutputKindsOtherThanFindings(t *testing.T) {
	w, repo := observationWorker(t)
	_, candidate := candidatePair(t, w, repo)
	err := w.parseSkillOutputKind(t.Context(), &db.Skill{Name: "verify", OutputKind: "verify"}, candidate, `{}`, func(Event) {})
	if err == nil || !strings.Contains(err.Error(), "only record findings") {
		t.Fatalf("err = %v, want a refusal", err)
	}
}

func TestCandidate_streamedFindingLandsInCandidateObservations(t *testing.T) {
	w, repo := observationWorker(t)
	_, candidate := candidatePair(t, w, repo)
	w.OnFindingCreated = func(*db.Scan, *db.Finding) { t.Error("OnFindingCreated fired for a streamed candidate finding") }
	f, err := w.PersistStreamedFinding(candidate, []byte(`{"id":"F1","title":"SQLi","severity":"High","location":"a.rb:1","trace":"User input reaches the query unescaped."}`))
	if err != nil {
		t.Fatal(err)
	}
	if f.ID != 0 {
		t.Errorf("streamed candidate finding id = %d, want 0", f.ID)
	}
	var n int64
	w.DB.Model(&db.Finding{}).Count(&n)
	if n != 0 {
		t.Errorf("findings = %d, want 0", n)
	}
	if rows := candidateObservations(t, w, candidate.ID); len(rows) != 1 || rows[0].Title != "SQLi" {
		t.Errorf("candidate observations = %+v", rows)
	}
}

func TestCandidate_followUpHooksDoNotFire(t *testing.T) {
	w, repo := observationWorker(t)
	baseline, candidate := candidatePair(t, w, repo)
	var fired []string
	w.OnScanFinalized = func(*db.Scan) { fired = append(fired, "finalized") }
	w.OnScanFailed = func(*db.Scan) { fired = append(fired, "failed") }
	w.OnScanGroupSettled = func(*db.Scan) { fired = append(fired, "settled") }

	candidate.Status, candidate.ScanGroup = db.ScanDone, "grp"
	if !w.maybeFireScanFinalized(candidate, nil) {
		t.Error("a done candidate should still report finalized")
	}
	w.maybeFireScanGroupSettled(candidate)
	candidate.Status = db.ScanFailed
	w.maybeFireScanFailed(candidate)
	if len(fired) != 0 {
		t.Fatalf("hooks fired for a candidate: %v", fired)
	}

	w.maybeFireScanFinalized(baseline, nil)
	baseline.Status = db.ScanFailed
	w.maybeFireScanFailed(baseline)
	if strings.Join(fired, ",") != "finalized,failed" {
		t.Errorf("baseline hooks = %v, want finalized,failed", fired)
	}
}

func TestCandidate_inputsMustMatchTheBaseline(t *testing.T) {
	recipe := func(t *testing.T, scan *db.Scan, threatModel, scanConfig string) string {
		t.Helper()
		r, err := buildScanRecipe(scan, "claude", threatModel, scanConfig)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	for _, tc := range []struct {
		name               string
		commit, tm, config string
		want               string
	}{
		{"same inputs", "abc", "tm", "cfg", ""},
		{"other commit", "def", "tm", "cfg", "source commit"},
		{"edited threat model", "abc", "tm2", "cfg", "threat model changed"},
		{"edited scan config", "abc", "tm", "", "scan config changed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, repo := observationWorker(t)
			baseline, candidate := candidatePair(t, w, repo)
			w.DB.Model(baseline).Update("recipe", recipe(t, baseline, "tm", "cfg"))
			candidate.Commit = tc.commit
			candidate.Recipe = recipe(t, candidate, tc.tm, tc.config)
			err := w.checkCandidateInputs(candidate)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("err = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestCandidate_neverServesAsDiffBaselineOrPrerequisite(t *testing.T) {
	w, repo := observationWorker(t)
	baseline, candidate := candidatePair(t, w, repo)
	w.DB.Model(candidate).Updates(map[string]any{"status": db.ScanDone, "skill_name": "security-deep-dive"})

	next := &db.Scan{ID: candidate.ID + 1, RepositoryID: repo.ID, SkillName: "security-deep-dive"}
	got, ok := w.diffBaseline(next)
	if !ok || got.ID != baseline.ID {
		t.Errorf("diff baseline = %d (%v), want ordinary scan %d", got.ID, ok, baseline.ID)
	}

	w.DB.Model(baseline).Update("status", db.ScanFailed)
	state, err := w.scopedPrereqStatus(&db.Scan{RepositoryID: repo.ID}, "security-deep-dive", []db.ScanStatus{db.ScanQueued, db.ScanRunning})
	if err != nil {
		t.Fatal(err)
	}
	if state == prereqSatisfied {
		t.Error("a done candidate satisfied a prerequisite")
	}
	if _, err := w.candidateBaseline(&db.Scan{CandidateOfScanID: new(uint(9999))}); err == nil {
		t.Error("a missing baseline should fail the candidate")
	}
}

// The candidate fails on a clone error and leaves the repository unflagged. An ordinary scan still gets its unreachable report.
func TestCandidate_cloneFailureFailsWithoutFlaggingTheRepository(t *testing.T) {
	w, repo := observationWorker(t)
	baseline, candidate := candidatePair(t, w, repo)
	unreachable := &RepoUnreachableError{URL: repo.URL, Err: errors.New("could not fetch commit")}

	if _, ok := w.handleCloneError(candidate, unreachable, func(Event) {}); ok {
		t.Error("a candidate clone failure became a finished report")
	}
	var got db.Repository
	w.DB.First(&got, repo.ID)
	if got.CloneError != "" {
		t.Errorf("clone_error = %q after a candidate clone failure, want empty", got.CloneError)
	}

	if _, ok := w.handleCloneError(baseline, unreachable, func(Event) {}); !ok {
		t.Error("an ordinary scan's clone failure lost its unreachable report")
	}
	w.DB.First(&got, repo.ID)
	if got.CloneError == "" {
		t.Error("an ordinary scan's clone failure did not flag the repository")
	}
}

// context.json gives a candidate its baseline's ref, not the commit it is pinned to.
func TestCandidate_contextCarriesTheBaselineRef(t *testing.T) {
	w, repo := observationWorker(t)
	baseline, candidate := candidatePair(t, w, repo)
	w.DB.Model(baseline).Update("ref", "2.4.x")
	candidate.Ref, candidate.Repository = baseline.Commit, repo
	skill := db.Skill{Name: "deep-dive-v2", Body: "# Test", Source: "ui"}

	work := t.TempDir()
	doc, err := w.stageWorkspace(t.Context(), work, filepath.Join(work, ".claude", "skills", skill.Name), candidate, &skill)
	if err != nil {
		t.Fatal(err)
	}
	if doc.Scrutineer.ScanRef != "2.4.x" {
		t.Errorf("scan_ref = %q, want the baseline's ref 2.4.x", doc.Scrutineer.ScanRef)
	}
	if candidate.Ref != baseline.Commit {
		t.Errorf("staging rewrote the candidate's pinned ref to %q", candidate.Ref)
	}

	orphan := *candidate
	orphan.CandidateOfScanID = new(uint(9999))
	work = t.TempDir()
	if _, err := w.stageWorkspace(t.Context(), work, filepath.Join(work, ".claude", "skills", skill.Name), &orphan, &skill); err == nil {
		t.Error("a candidate without its baseline staged a workspace")
	}
}
