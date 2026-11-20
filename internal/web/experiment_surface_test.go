package web

import (
	"fmt"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"scrutineer/internal/config"
	"scrutineer/internal/db"
	"scrutineer/internal/worker"
)

var (
	experimentPickerRE       = regexp.MustCompile(`(?s)<select[^>]*aria-label="Candidate experiment"[^>]*>(.*?)</select>`)
	experimentPickerOptionRE = regexp.MustCompile(`<option value="[^"]*">([^<]*)</option>`)
)

// experimentPickerOptions returns the visible text of each option of the repository page's Candidate experiment picker.
func experimentPickerOptions(t *testing.T, page string) []string {
	t.Helper()
	m := experimentPickerRE.FindStringSubmatch(page)
	if m == nil {
		t.Fatal("repository page has no Candidate experiment picker")
	}
	var options []string
	for _, o := range experimentPickerOptionRE.FindAllStringSubmatch(m[1], -1) {
		options = append(options, o[1])
	}
	return options
}

// The Run skill form lists every configured experiment once, sorted, in the Candidate experiment picker, and renders no picker when none is configured.
func TestRepoShow_experimentPickerListsConfiguredExperimentsSorted(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	fx := seedExperimentFixture(t, s)
	for _, name := range []string{"zeta", "alpha", "mid", "beta", "omega", "kappa", "delta"} {
		s.ScanExperiments[name] = config.ScanExperiment{Effort: "low"}
	}
	want := []string{"No experiment", "alpha", "beta", "delta", "kappa", "mid", "omega", "trial", "zeta"}
	// Map iteration order changes from one render to the next.
	for range 3 {
		if got := experimentPickerOptions(t, getRepoPage(t, s, fx.repo.ID)); !slices.Equal(got, want) {
			t.Fatalf("picker options = %q, want %q", got, want)
		}
	}

	s.ScanExperiments = nil
	page := getRepoPage(t, s, fx.repo.ID)
	if !strings.Contains(page, "Run skill") || strings.Contains(page, `aria-label="Candidate experiment"`) {
		t.Error("with no scan_experiments the Run skill form still renders a Candidate experiment picker")
	}
}

// The scan page shows the candidate banner on a candidate, the experiment banner on an ordinary scan launched with one and neither on a plain scan, and offers Export as markdown everywhere but on the candidate.
func TestScanShow_experimentBannersAndExport(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	fx := seedExperimentFixture(t, s)
	baseline := finishedBaseline(t, s, fx)
	s.DB.Model(&baseline).Update("findings_count", 1)
	candidate := db.Scan{RepositoryID: fx.repo.ID, Kind: worker.JobSkill, Status: db.ScanDone, SkillID: &fx.variant.ID, SkillName: fx.variant.Name,
		FindingsCount: 1, Experiment: "trial", ExperimentConfig: baseline.ExperimentConfig, CandidateOfScanID: &baseline.ID}
	plain := db.Scan{RepositoryID: fx.repo.ID, Kind: worker.JobSkill, Status: db.ScanDone, SkillID: &fx.findings.ID, SkillName: fx.findings.Name, FindingsCount: 1}
	s.DB.Create(&candidate)
	s.DB.Create(&plain)

	candidateBanner := fmt.Sprintf("Candidate scan for experiment trial Compared against scan #%d .", baseline.ID)
	experimentBanner := "Experiment trial A candidate run of this configuration starts on the same commit once this scan records its findings."
	for name, tc := range map[string]struct {
		id                            uint
		candidate, experiment, export bool
	}{
		"candidate": {candidate.ID, true, false, false},
		"baseline":  {baseline.ID, false, true, true},
		"plain":     {plain.ID, false, false, true},
	} {
		t.Run(name, func(t *testing.T) {
			page := getRepoPagePath(t, s, fmt.Sprintf("/scans/%d", tc.id))
			text := html.UnescapeString(experimentText(page))
			if got := strings.Contains(text, candidateBanner); got != tc.candidate {
				t.Errorf("candidate banner shown = %v, want %v", got, tc.candidate)
			}
			comparison := fmt.Sprintf(`href="/scans/%d/experiment">Open the comparison</a>`, tc.id)
			if got := strings.Contains(page, comparison); got != (tc.candidate || tc.experiment) {
				t.Errorf("Open the comparison link to /scans/%d/experiment shown = %v, want %v", tc.id, got, tc.candidate || tc.experiment)
			}
			if got := strings.Contains(text, experimentBanner); got != tc.experiment {
				t.Errorf("experiment banner shown = %v, want %v", got, tc.experiment)
			}
			if got := strings.Contains(text, "Export as markdown"); got != tc.export {
				t.Errorf("Export as markdown offered = %v, want %v", got, tc.export)
			}
		})
	}
}

type experimentExecution struct {
	Profile, EgressPolicy, RescanMode string
	MaxCostUSD                        float64
	DiffBaseScanID                    uint
}

func executionOf(sc db.Scan) experimentExecution {
	e := experimentExecution{Profile: sc.Profile, EgressPolicy: sc.EgressPolicy, RescanMode: sc.RescanMode, MaxCostUSD: sc.MaxCostUSD}
	if sc.DiffBaseScanID != nil {
		e.DiffBaseScanID = *sc.DiffBaseScanID
	}
	return e
}

// A candidate refused for an unconfigured model keeps its baseline's runner profile, egress policy, cost cap and rescan mode, and retrying it once the model is configured queues a candidate with the same settings.
func TestEnqueueCandidate_refusedCandidateKeepsExecutionSettingsThroughRetry(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	fx := seedExperimentFixture(t, s)
	s.ScanEgressPolicies = []string{"registries"}
	diffBase := db.Scan{RepositoryID: fx.repo.ID, Kind: worker.JobSkill, Status: db.ScanDone, SkillID: &fx.findings.ID, SkillName: fx.findings.Name, Commit: "feedbeef"}
	s.DB.Create(&diffBase)
	baseline := finishedBaseline(t, s, fx)
	s.DB.Model(&baseline).Updates(map[string]any{"profile": "gpu-runner", "egress_policy": "registries", "max_cost_usd": 2.5,
		"rescan_mode": db.ScanRescanModeDiff, "diff_base_scan_id": diffBase.ID,
		"experiment_config": experimentSnapshot(t, config.ScanExperiment{Model: "trial-model"})})
	baseline = reloadScan(t, s, baseline.ID)
	want := executionOf(baseline)
	if want.Profile == "" || want.EgressPolicy == "" || want.MaxCostUSD == 0 || want.RescanMode != db.ScanRescanModeDiff || want.DiffBaseScanID == 0 {
		t.Fatalf("baseline settings = %+v, want every execution setting set", want)
	}

	s.enqueueCandidate(&baseline)
	requireRefusedCandidate(t, s, baseline.ID, "trial-model")
	refused := candidatesOf(t, s, baseline.ID)[0]
	if got := executionOf(refused); got != want {
		t.Errorf("refused candidate settings = %+v, want the baseline's %+v", got, want)
	}

	withTestModels(t, append(slices.Clone(Models), Model{Name: "Trial", ID: "trial-model"}))
	if w := postForm(t, s, fmt.Sprintf("/scans/%d/retry", refused.ID), url.Values{}); w.Code != http.StatusSeeOther {
		t.Fatalf("retry status %d: %s", w.Code, w.Body)
	}
	got := candidatesOf(t, s, baseline.ID)
	if len(got) != 2 || got[1].Status != db.ScanQueued || got[1].ParentScanID == nil || *got[1].ParentScanID != refused.ID {
		t.Fatalf("candidates = %+v, want a queued retry of #%d", got, refused.ID)
	}
	if settings := executionOf(got[1]); settings != want {
		t.Errorf("retried candidate settings = %+v, want the baseline's %+v", settings, want)
	}
}

// Assessment-derived counts read 0, not unavailable, when the side they rest on has nothing to assess.
func TestScanExperiment_countsReadZeroWithNothingToAssess(t *testing.T) {
	for name, tc := range map[string]struct {
		prepare func(s *Server, baseline, candidate db.Scan, extra db.CandidateObservation)
		want    map[string]string
	}{
		"no candidate-only observation": {
			func(s *Server, _, _ db.Scan, extra db.CandidateObservation) { s.DB.Delete(&extra) },
			map[string]string{"Candidate only": "0", "Additional confirmed": "0", "Confirmed, already known": "0", "Missed by candidate, confirmed": "unavailable"},
		},
		"no baseline observation": {
			func(s *Server, baseline, _ db.Scan, _ db.CandidateObservation) {
				s.DB.Where("scan_id = ?", baseline.ID).Delete(&db.FindingObservation{})
			},
			map[string]string{"Baseline false positives": "0", "Missed by candidate, confirmed": "0", "Additional confirmed": "unavailable"},
		},
		"every baseline observation shared": {
			func(s *Server, baseline, candidate db.Scan, _ db.CandidateObservation) {
				s.DB.Create(&db.CandidateObservation{ScanID: candidate.ID, RepositoryID: baseline.RepositoryID, Fingerprint: "fp-missed", Title: "XSS", Severity: "Medium"})
			},
			map[string]string{"Baseline only": "0", "Missed by candidate, confirmed": "0", "Baseline false positives": "unavailable"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			s, done := newTestServer(t)
			defer done()
			baseline, candidate, extra := seedComparison(t, s)
			tc.prepare(s, baseline, candidate, extra)

			page := getRepoPagePath(t, s, fmt.Sprintf("/scans/%d/experiment", baseline.ID))
			for label, want := range tc.want {
				if got := experimentMeasurement(t, page, label); got != want {
					t.Errorf("%s = %q, want %q", label, got, want)
				}
			}
		})
	}
}

// A confirmed candidate-only observation counts as Confirmed, already known only when the repository finding with its fingerprint was created before the candidate scan, and as Additional confirmed otherwise.
func TestScanExperiment_knownConfirmedFollowsTheFindingCreationTime(t *testing.T) {
	for name, tc := range map[string]struct {
		finding           bool
		offset            time.Duration
		additional, known string
	}{
		"finding created before the candidate": {true, -time.Hour, "0", "1"},
		"finding created after the candidate":  {true, time.Hour, "1", "0"},
		"no repository finding":                {false, 0, "1", "0"},
	} {
		t.Run(name, func(t *testing.T) {
			s, done := newTestServer(t)
			defer done()
			baseline, candidate, extra := seedComparison(t, s)
			if tc.finding {
				other := db.Scan{RepositoryID: baseline.RepositoryID, Kind: worker.JobSkill, Status: db.ScanDone, SkillName: baseline.SkillName}
				s.DB.Create(&other)
				s.DB.Create(&db.Finding{RepositoryID: baseline.RepositoryID, ScanID: other.ID, Title: extra.Title, Severity: extra.Severity,
					Fingerprint: extra.Fingerprint, Status: db.FindingNew, CreatedAt: candidate.CreatedAt.Add(tc.offset)})
			}
			assessObservation(t, s, extra.ID, url.Values{"assessment": {db.CandidateConfirmed}})

			page := getRepoPagePath(t, s, fmt.Sprintf("/scans/%d/experiment", baseline.ID))
			if got := experimentMeasurement(t, page, "Additional confirmed"); got != tc.additional {
				t.Errorf("Additional confirmed = %q, want %q", got, tc.additional)
			}
			if got := experimentMeasurement(t, page, "Confirmed, already known"); got != tc.known {
				t.Errorf("Confirmed, already known = %q, want %q", got, tc.known)
			}
		})
	}
}

// POST /scans/{id}/baseline-effort upserts minutes and a note on a baseline finding by fingerprint, which the comparison sums and renders back into that row's form, and refuses a fingerprint the baseline did not report, non-numeric minutes, a candidate and a scan without an experiment.
func TestScanBaselineEffort_recordsAndRefuses(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	baseline, candidate, _ := seedComparison(t, s)
	plain := db.Scan{RepositoryID: baseline.RepositoryID, Kind: worker.JobSkill, Status: db.ScanDone, SkillID: baseline.SkillID, SkillName: baseline.SkillName}
	s.DB.Create(&plain)
	s.DB.Create(&db.FindingObservation{ScanID: plain.ID, RepositoryID: plain.RepositoryID, Fingerprint: "fp-shared", Title: "SQLi", Severity: "High"})
	path := func(id uint) string { return fmt.Sprintf("/scans/%d/baseline-effort", id) }
	efforts := func() []db.ExperimentBaselineEffort {
		t.Helper()
		var rows []db.ExperimentBaselineEffort
		s.DB.Order("id").Find(&rows)
		return rows
	}

	w := postForm(t, s, path(baseline.ID), url.Values{"fingerprint": {"fp-missed"}, "effort_minutes": {"30"}, "note": {"first pass"},
		"candidate": {fmt.Sprint(candidate.ID)}})
	if want := fmt.Sprintf("/scans/%d/experiment?candidate=%d", baseline.ID, candidate.ID); w.Code != http.StatusSeeOther || w.Header().Get("Location") != want {
		t.Fatalf("first post = %d %q, want 303 to %s: %s", w.Code, w.Header().Get("Location"), want, w.Body)
	}
	if w := postForm(t, s, path(baseline.ID), url.Values{"fingerprint": {"fp-missed"}, "effort_minutes": {"45"}, "note": {" reproduced "}}); w.Code != http.StatusSeeOther {
		t.Fatalf("second post status %d: %s", w.Code, w.Body)
	}
	rows := efforts()
	if len(rows) != 1 || rows[0].BaselineScanID != baseline.ID || rows[0].Fingerprint != "fp-missed" ||
		rows[0].EffortMinutes == nil || *rows[0].EffortMinutes != 45 || rows[0].Note != "reproduced" {
		t.Fatalf("baseline efforts = %+v, want one fp-missed row of 45 minutes noted reproduced", rows)
	}

	page := getRepoPagePath(t, s, fmt.Sprintf("/scans/%d/experiment", baseline.ID))
	if got := experimentMeasurement(t, page, "Baseline analyst effort"); got != "45 min on 1 of 2" {
		t.Errorf("Baseline analyst effort = %q, want 45 min on 1 of 2", got)
	}
	if _, inputs := experimentFormState(experimentFindingRow(t, page, "XSS")); inputs["effort_minutes"] != "45" || inputs["note"] != "reproduced" {
		t.Errorf("XSS row form = %q, want 45 minutes and the note", inputs)
	}
	if _, inputs := experimentFormState(experimentFindingRow(t, page, "SQLi")); inputs["effort_minutes"] != "" || inputs["note"] != "" {
		t.Errorf("SQLi row form = %q, want empty minutes and note", inputs)
	}

	for name, tc := range map[string]struct {
		id          uint
		fingerprint string
		minutes     string
		want        int
	}{
		"fingerprint the baseline did not report": {baseline.ID, "fp-new", "10", http.StatusUnprocessableEntity},
		"non-numeric minutes":                     {baseline.ID, "fp-shared", "lots", http.StatusUnprocessableEntity},
		"candidate scan":                          {candidate.ID, "fp-shared", "10", http.StatusBadRequest},
		"scan without an experiment":              {plain.ID, "fp-shared", "10", http.StatusBadRequest},
	} {
		if w := postForm(t, s, path(tc.id), url.Values{"fingerprint": {tc.fingerprint}, "effort_minutes": {tc.minutes}}); w.Code != tc.want {
			t.Errorf("%s: status %d, want %d", name, w.Code, tc.want)
		}
	}
	if rows := efforts(); len(rows) != 1 || *rows[0].EffortMinutes != 45 {
		t.Errorf("baseline efforts after refused posts = %+v, want only the 45 minute row", rows)
	}
}

// Cost, this candidate run shows the selected run's own cost, and unavailable for a run that recorded no cost or an unpriced one.
func TestScanExperiment_costOfTheSelectedCandidateRun(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	baseline, candidate, _ := seedComparison(t, s)
	s.DB.Model(&candidate).Update("cost_usd", 1.25)
	run := func(sc db.Scan) db.Scan {
		sc.RepositoryID, sc.Kind, sc.Status, sc.SkillName = baseline.RepositoryID, worker.JobSkill, db.ScanDone, candidate.SkillName
		sc.Experiment, sc.ExperimentConfig, sc.CandidateOfScanID = "trial", baseline.ExperimentConfig, &baseline.ID
		s.DB.Create(&sc)
		return sc
	}
	other := run(db.Scan{CostUSD: 0.5})
	unpriced := run(db.Scan{InputTokens: 800, OutputTokens: 200})
	bare := run(db.Scan{})

	for name, tc := range map[string]struct {
		id   uint
		want string
	}{
		"priced":       {candidate.ID, "$1.25"},
		"other priced": {other.ID, "$0.50"},
		"unpriced":     {unpriced.ID, "unavailable"},
		"no cost":      {bare.ID, "unavailable"},
	} {
		page := getRepoPagePath(t, s, fmt.Sprintf("/scans/%d/experiment?candidate=%d", baseline.ID, tc.id))
		if got := experimentMeasurement(t, page, "Cost, this candidate run"); got != tc.want {
			t.Errorf("%s run selected: Cost, this candidate run = %q, want %q", name, got, tc.want)
		}
	}
}
