package web

import (
	"fmt"
	"html"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"scrutineer/internal/config"
	"scrutineer/internal/db"
	"scrutineer/internal/worker"
)

var (
	experimentInputRE    = regexp.MustCompile(`<input[^>]*name="([^"]+)"[^>]*value="([^"]*)"`)
	experimentSelectedRE = regexp.MustCompile(`<option value="([^"]*)" selected>`)
)

// experimentFindingRow returns the HTML of the comparison row whose finding is titled title.
func experimentFindingRow(t *testing.T, page, title string) string {
	t.Helper()
	anchor := ">" + title + "</span>"
	if n := strings.Count(page, anchor); n != 1 {
		t.Fatalf("comparison has %d rows titled %q, want 1", n, title)
	}
	i := strings.Index(page, anchor)
	row, _, _ := strings.Cut(page[strings.LastIndex(page[:i], "<tr>"):], "</tr>")
	return row
}

// experimentEvidence returns the visible text of the side's evidence details in row, empty when it has none.
func experimentEvidence(row, side string) string {
	_, rest, ok := strings.Cut(row, ">"+side+" evidence</summary>")
	if !ok {
		return ""
	}
	details, _, _ := strings.Cut(rest, "</details>")
	return html.UnescapeString(experimentText(details))
}

func experimentCells(row string) []string {
	var cells []string
	for _, cell := range strings.Split(row, "<td")[1:] {
		cells = append(cells, html.UnescapeString(experimentText("<td"+cell)))
	}
	return cells
}

// experimentFormState returns the selected assessment and the input values of the assessment form in row.
func experimentFormState(row string) (selected []string, inputs map[string]string) {
	for _, m := range experimentSelectedRE.FindAllStringSubmatch(row, -1) {
		selected = append(selected, m[1])
	}
	inputs = map[string]string{}
	for _, m := range experimentInputRE.FindAllStringSubmatch(row, -1) {
		inputs[m[1]] = html.UnescapeString(m[2])
	}
	return selected, inputs
}

// experimentRunRow returns the HTML of the Runs row of candidate scan id.
func experimentRunRow(t *testing.T, page string, id uint) string {
	t.Helper()
	anchor := fmt.Sprintf(`href="/scans/%d/experiment?candidate=%d">#%d</a>`, id, id, id)
	i := strings.Index(page, anchor)
	if i < 0 {
		t.Fatalf("no run row for candidate scan %d", id)
	}
	row, _, _ := strings.Cut(page[i:], "</tr>")
	return row
}

// A candidate refused at enqueue shows as a failed run naming the reason and counts in Failed candidate runs, while one that starts does not.
func TestScanExperiment_refusedCandidateShowsAsAFailedRun(t *testing.T) {
	for name, tc := range map[string]struct {
		model, status, failed string
		refused               bool
	}{
		"unconfigured model": {"no-such-model", "failed", "1", true},
		"configured model":   {"", "queued", "0", false},
	} {
		t.Run(name, func(t *testing.T) {
			s, done := newTestServer(t)
			defer done()
			fx := seedExperimentFixture(t, s)
			baseline := finishedBaseline(t, s, fx)
			if tc.model != "" {
				baseline.ExperimentConfig = experimentSnapshot(t, config.ScanExperiment{Model: tc.model})
				s.DB.Model(&baseline).Update("experiment_config", baseline.ExperimentConfig)
			}
			s.enqueueCandidate(&baseline)
			runs := candidatesOf(t, s, baseline.ID)
			if len(runs) != 1 {
				t.Fatalf("candidates = %d, want 1", len(runs))
			}

			page := getRepoPagePath(t, s, fmt.Sprintf("/scans/%d/experiment", baseline.ID))
			if cells := experimentRunCells(t, page, runs[0].ID); cells[1] != "candidate" || cells[2] != tc.status {
				t.Errorf("run row = %q, want a %s candidate", cells, tc.status)
			}
			if got := experimentMeasurement(t, page, "Failed candidate runs"); got != tc.failed {
				t.Errorf("Failed candidate runs = %q, want %s", got, tc.failed)
			}
			reason := `This run is failed: candidate not started: invalid scan experiment: model "no-such-model" is not configured.`
			if got := strings.Contains(html.UnescapeString(experimentText(page)), reason); got != tc.refused {
				t.Errorf("page names the refusal reason = %v, want %v", got, tc.refused)
			}
		})
	}
}

// Incomplete candidate runs counts cancelled runs and done runs stopped by their cost cap or turn limit, never a plain done run.
func TestScanExperiment_incompleteCandidateRuns(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	baseline, candidate, _ := seedComparison(t, s)
	path := fmt.Sprintf("/scans/%d/experiment", baseline.ID)
	if got := experimentMeasurement(t, getRepoPagePath(t, s, path), "Incomplete candidate runs"); got != "0" {
		t.Fatalf("Incomplete candidate runs = %q with only a plain done run, want 0", got)
	}

	for i, run := range []db.Scan{
		{Status: db.ScanCancelled},
		{Status: db.ScanDone, CostCapped: true},
		{Status: db.ScanDone, MaxTurnsHit: true},
	} {
		run.RepositoryID, run.Kind, run.SkillName = baseline.RepositoryID, worker.JobSkill, candidate.SkillName
		run.Experiment, run.ExperimentConfig, run.CandidateOfScanID = "trial", baseline.ExperimentConfig, &baseline.ID
		s.DB.Create(&run)
		page := getRepoPagePath(t, s, path)
		if got, want := experimentMeasurement(t, page, "Incomplete candidate runs"), fmt.Sprint(i+1); got != want {
			t.Errorf("after a %s run (cost capped %v, max turns %v): Incomplete candidate runs = %q, want %s", run.Status, run.CostCapped, run.MaxTurnsHit, got, want)
		}
		if got := experimentMeasurement(t, page, "Failed candidate runs"); got != "0" {
			t.Errorf("Failed candidate runs = %q, want 0", got)
		}
	}
}

// A shared row renders both sides' CWE, confidence, reachability, rating and evidence and both severities, and a one-sided row only its own side.
func TestScanExperiment_rowsRenderEachSidesEvidence(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	baseline, candidate, _ := seedComparison(t, s)
	s.DB.Model(&db.FindingObservation{}).Where("scan_id = ? AND fingerprint = ?", baseline.ID, "fp-shared").Updates(map[string]any{
		"cwe": "CWE-89", "confidence": "high", "reachability": "reachable from the login form",
		"rating": "Baseline rates it exploitable.", "evidence": `{"sink":"db.Query"}`,
	})
	s.DB.Model(&db.CandidateObservation{}).Where("scan_id = ? AND fingerprint = ?", candidate.ID, "fp-shared").Updates(map[string]any{
		"cwe": "CWE-564", "confidence": "medium", "reachability": "admin only",
		"rating": "Candidate rates it hard to reach.", "evidence": `{"sink":"orm.Raw"}`,
	})

	page := getRepoPagePath(t, s, fmt.Sprintf("/scans/%d/experiment", baseline.ID))
	shared := experimentFindingRow(t, page, "SQLi")
	for side, want := range map[string]string{
		"Baseline":  `CWE CWE-89 Confidence high Reachability reachable from the login form Baseline rates it exploitable. { "sink": "db.Query" }`,
		"Candidate": `CWE CWE-564 Confidence medium Reachability admin only Candidate rates it hard to reach. { "sink": "orm.Raw" }`,
	} {
		if got := experimentEvidence(shared, side); got != want {
			t.Errorf("shared row %s evidence = %q, want %q", side, got, want)
		}
	}
	if cells := experimentCells(shared); cells[1] != "both" || cells[2] != "High" || cells[3] != "Low" {
		t.Errorf("shared row = reported by %q, baseline severity %q, candidate severity %q, want both, High, Low", cells[1], cells[2], cells[3])
	}

	missed := experimentFindingRow(t, page, "XSS")
	if got := experimentEvidence(missed, "Baseline"); got != "CWE - Confidence - Reachability -" {
		t.Errorf("baseline-only row evidence = %q, want every field as -", got)
	}
	if got := experimentEvidence(missed, "Candidate"); got != "" {
		t.Errorf("baseline-only row renders candidate evidence %q", got)
	}
	if cells := experimentCells(missed); cells[2] != "Medium" || cells[3] != "-" {
		t.Errorf("baseline-only row severities = %q and %q, want Medium and -", cells[2], cells[3])
	}
	if got := experimentEvidence(experimentFindingRow(t, page, "Path traversal"), "Baseline"); got != "" {
		t.Errorf("candidate-only row renders baseline evidence %q", got)
	}
}

// A saved assessment renders back into its row's form, and an unassessed row's form stays empty.
func TestScanExperiment_assessmentFormShowsTheSavedAssessment(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	baseline, _, extra := seedComparison(t, s)
	assessObservation(t, s, extra.ID, url.Values{"assessment": {db.CandidateFalsePositive}, "effort_minutes": {"25"}, "note": {"needs \"admin\" access"}})

	page := getRepoPagePath(t, s, fmt.Sprintf("/scans/%d/experiment", baseline.ID))
	selected, inputs := experimentFormState(experimentFindingRow(t, page, "Path traversal"))
	if len(selected) != 1 || selected[0] != db.CandidateFalsePositive || inputs["effort_minutes"] != "25" || inputs["note"] != `needs "admin" access` {
		t.Errorf("assessed form = selected %q, inputs %q, want false_positive, 25 minutes and the note", selected, inputs)
	}
	selected, inputs = experimentFormState(experimentFindingRow(t, page, "SQLi"))
	if len(selected) != 0 || inputs["effort_minutes"] != "" || inputs["note"] != "" {
		t.Errorf("unassessed form = selected %q, inputs %q, want nothing selected and empty minutes and note", selected, inputs)
	}
}

// The Runs table shows a run's measured duration, tokens and cost, and unavailable for each one a run did not record.
func TestScanExperiment_runsTableMeasurements(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	baseline, candidate, _ := seedComparison(t, s)
	started := time.Date(2026, time.November, 20, 10, 0, 0, 0, time.UTC)
	finished := started.Add(90 * time.Second)
	s.DB.Model(&candidate).Updates(map[string]any{"started_at": started, "finished_at": finished,
		"input_tokens": 12000, "cache_read_tokens": 3000, "output_tokens": 4500, "cost_usd": 1.25})
	unpriced := db.Scan{RepositoryID: baseline.RepositoryID, Kind: worker.JobSkill, Status: db.ScanDone, SkillName: candidate.SkillName,
		InputTokens: 800, OutputTokens: 200, Experiment: "trial", ExperimentConfig: baseline.ExperimentConfig, CandidateOfScanID: &baseline.ID}
	bare := db.Scan{RepositoryID: baseline.RepositoryID, Kind: worker.JobSkill, Status: db.ScanCancelled, SkillName: candidate.SkillName,
		Experiment: "trial", ExperimentConfig: baseline.ExperimentConfig, CandidateOfScanID: &baseline.ID}
	s.DB.Create(&unpriced)
	s.DB.Create(&bare)

	page := getRepoPagePath(t, s, fmt.Sprintf("/scans/%d/experiment", baseline.ID))
	for name, tc := range map[string]struct {
		id                     uint
		duration, tokens, cost string
		unpricedNote           bool
	}{
		"measured": {candidate.ID, "1m", "15.0K in / 4500 out", "$1.25", false},
		"unpriced": {unpriced.ID, "unavailable", "800 in / 200 out", "unavailable", true},
		"bare":     {bare.ID, "unavailable", "unavailable", "unavailable", false},
	} {
		cells := experimentRunCells(t, page, tc.id)
		if cells[8] != tc.duration || cells[9] != tc.tokens || cells[10] != tc.cost {
			t.Errorf("%s run = duration %q tokens %q cost %q, want %q %q %q", name, cells[8], cells[9], cells[10], tc.duration, tc.tokens, tc.cost)
		}
		if got := strings.Contains(experimentRunRow(t, page, tc.id), "no price is known for this model"); got != tc.unpricedNote {
			t.Errorf("%s run cost explains a missing price = %v, want %v", name, got, tc.unpricedNote)
		}
	}
}

// The repository list's Status badge and sort=status order come from ordinary scans, never a running candidate.
func TestRepoList_statusIgnoresRunningCandidates(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	settled := db.Repository{URL: "https://example.com/settled-repo", Name: "settled-repo"}
	waiting := db.Repository{URL: "https://example.com/waiting-repo", Name: "waiting-repo"}
	s.DB.Create(&settled)
	s.DB.Create(&waiting)
	baseline := db.Scan{RepositoryID: settled.ID, Kind: worker.JobSkill, SkillName: deepDiveSkillName, Status: db.ScanDone,
		StatusPriority: db.StatusPriorityFor(db.ScanDone)}
	s.DB.Create(&baseline)
	s.DB.Create(&db.Scan{RepositoryID: settled.ID, Kind: worker.JobSkill, SkillName: deepDiveSkillName, Status: db.ScanRunning,
		StatusPriority: db.StatusPriorityFor(db.ScanRunning), Experiment: "trial", CandidateOfScanID: &baseline.ID})
	s.DB.Create(&db.Scan{RepositoryID: waiting.ID, Kind: worker.JobSkill, SkillName: deepDiveSkillName, Status: db.ScanQueued,
		StatusPriority: db.StatusPriorityFor(db.ScanQueued)})

	page := getRepoPagePath(t, s, "/")
	for repo, want := range map[*db.Repository]string{&settled: "complete", &waiting: "queued"} {
		if got := experimentCells(requireRepoListRow(t, page, repo.ID))[3]; got != want {
			t.Errorf("%s Status = %q, want %q", repo.Name, got, want)
		}
	}
	assertOrder(t, getRepoPagePath(t, s, "/?sort=status"), "waiting-repo", "settled-repo")
	assertOrder(t, getRepoPagePath(t, s, "/?sort=status.desc"), "settled-repo", "waiting-repo")
}
