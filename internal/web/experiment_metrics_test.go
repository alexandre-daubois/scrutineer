package web

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"scrutineer/internal/db"
	"scrutineer/internal/worker"
)

var experimentTagRE = regexp.MustCompile(`<[^>]*>`)

func experimentText(html string) string {
	return strings.Join(strings.Fields(experimentTagRE.ReplaceAllString(html, " ")), " ")
}

// experimentMeasurement returns the visible text of the comparison cell under label.
func experimentMeasurement(t *testing.T, page, label string) string {
	t.Helper()
	anchor := ">" + label + "</dt><dd>"
	if n := strings.Count(page, anchor); n != 1 {
		t.Fatalf("comparison has %d %q cells, want 1", n, label)
	}
	_, rest, _ := strings.Cut(page, anchor)
	cell, _, _ := strings.Cut(rest, "</dd>")
	return experimentText(cell)
}

// experimentRunCells returns the visible text of each cell in the Runs row of candidate scan id.
func experimentRunCells(t *testing.T, page string, id uint) []string {
	t.Helper()
	anchor := fmt.Sprintf(`href="/scans/%d/experiment?candidate=%d">#%d</a>`, id, id, id)
	i := strings.Index(page, anchor)
	if i < 0 {
		t.Fatalf("no run row for candidate scan %d", id)
	}
	row, _, _ := strings.Cut(page[strings.LastIndex(page[:i], "<tr>"):], "</tr>")
	var cells []string
	for _, cell := range strings.Split(row, "<td")[1:] {
		cells = append(cells, experimentText("<td"+cell))
	}
	return cells
}

func assessObservation(t *testing.T, s *Server, id uint, form url.Values) {
	t.Helper()
	if w := postForm(t, s, fmt.Sprintf("/candidate-observations/%d/assessment", id), form); w.Code != http.StatusSeeOther {
		t.Fatalf("assessment status %d: %s", w.Code, w.Body)
	}
}

// Before any assessment the assessment-derived counts render unavailable, not 0.
func TestScanExperiment_unassessedCountsRenderUnavailable(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	baseline, _, _ := seedComparison(t, s)

	page := getRepoPagePath(t, s, fmt.Sprintf("/scans/%d/experiment", baseline.ID))
	for label, want := range map[string]string{
		"Additional confirmed":      "unavailable",
		"Candidate false positives": "unavailable",
		"Assessed":                  "0 of 2",
	} {
		if got := experimentMeasurement(t, page, label); got != want {
			t.Errorf("%s = %q, want %q", label, got, want)
		}
	}
}

// Every assessment counts towards Assessed and a false_positive one towards Candidate false positives.
func TestScanExperiment_talliesFalsePositivesAndAssessed(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	baseline, candidate, extra := seedComparison(t, s)
	var shared db.CandidateObservation
	s.DB.Where("scan_id = ? AND fingerprint = ?", candidate.ID, "fp-shared").First(&shared)

	assessObservation(t, s, extra.ID, url.Values{"assessment": {db.CandidateFalsePositive}})
	page := getRepoPagePath(t, s, fmt.Sprintf("/scans/%d/experiment", baseline.ID))
	for label, want := range map[string]string{
		"Candidate false positives": "1 of 1 assessed",
		"Additional confirmed":      "0",
		"Assessed":                  "1 of 2",
	} {
		if got := experimentMeasurement(t, page, label); got != want {
			t.Errorf("after one false_positive: %s = %q, want %q", label, got, want)
		}
	}

	assessObservation(t, s, shared.ID, url.Values{"assessment": {db.CandidateUnsure}})
	page = getRepoPagePath(t, s, fmt.Sprintf("/scans/%d/experiment", baseline.ID))
	for label, want := range map[string]string{
		"Candidate false positives": "1",
		"Assessed":                  "2 of 2",
	} {
		if got := experimentMeasurement(t, page, label); got != want {
			t.Errorf("after an unsure: %s = %q, want %q", label, got, want)
		}
	}
}

// A confirmed candidate-only observation counts as additional only when no finding of the same repository carries its fingerprint.
func TestScanExperiment_additionalConfirmedSkipsFindingsTheRepositoryAlreadyHas(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	baseline, candidate, extra := seedComparison(t, s)
	earlier := db.Scan{RepositoryID: baseline.RepositoryID, Kind: worker.JobSkill, Status: db.ScanDone, SkillName: baseline.SkillName}
	s.DB.Create(&earlier)
	s.DB.Create(&db.Finding{RepositoryID: baseline.RepositoryID, ScanID: earlier.ID, Title: "Open redirect", Severity: "Low", Fingerprint: "fp-known", Status: db.FindingNew,
		CreatedAt: candidate.CreatedAt.Add(-time.Hour)})
	other := db.Repository{URL: "https://example.com/other", Name: "other"}
	s.DB.Create(&other)
	otherScan := db.Scan{RepositoryID: other.ID, Kind: worker.JobSkill, Status: db.ScanDone, SkillName: baseline.SkillName}
	s.DB.Create(&otherScan)
	s.DB.Create(&db.Finding{RepositoryID: other.ID, ScanID: otherScan.ID, Title: extra.Title, Severity: extra.Severity, Fingerprint: extra.Fingerprint, Status: db.FindingNew})
	known := db.CandidateObservation{ScanID: candidate.ID, RepositoryID: baseline.RepositoryID, Fingerprint: "fp-known", Title: "Open redirect", Severity: "Low"}
	s.DB.Create(&known)

	assessObservation(t, s, known.ID, url.Values{"assessment": {db.CandidateConfirmed}})
	page := getRepoPagePath(t, s, fmt.Sprintf("/scans/%d/experiment", baseline.ID))
	if got := experimentMeasurement(t, page, "Candidate only"); got != "2" {
		t.Fatalf("Candidate only = %q, want 2", got)
	}
	if got := experimentMeasurement(t, page, "Additional confirmed"); got != "0 of 1 assessed" {
		t.Errorf("Additional confirmed = %q with only an already known finding confirmed, want 0 of 1 assessed", got)
	}
	if got := experimentMeasurement(t, page, "Confirmed, already known"); got != "1 of 1 assessed" {
		t.Errorf("Confirmed, already known = %q, want 1 of 1 assessed", got)
	}

	assessObservation(t, s, extra.ID, url.Values{"assessment": {db.CandidateConfirmed}})
	page = getRepoPagePath(t, s, fmt.Sprintf("/scans/%d/experiment", baseline.ID))
	if got := experimentMeasurement(t, page, "Additional confirmed"); got != "1" {
		t.Errorf("Additional confirmed = %q after confirming a finding only another repository has, want 1", got)
	}
}

// Baseline false positives counts the baseline observations whose repository finding is rejected, and no other rejected finding.
func TestScanExperiment_baselineFalsePositivesCountRejectedBaselineFindings(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	baseline, candidate, _ := seedComparison(t, s)
	page := getRepoPagePath(t, s, fmt.Sprintf("/scans/%d/experiment", baseline.ID))
	if got := experimentMeasurement(t, page, "Baseline false positives"); got != "unavailable" {
		t.Fatalf("Baseline false positives = %q before any triage, want unavailable", got)
	}

	s.DB.Model(&db.Finding{}).Where("fingerprint = ?", "fp-missed").Update("status", db.FindingRejected)
	earlier := db.Scan{RepositoryID: baseline.RepositoryID, Kind: worker.JobSkill, Status: db.ScanDone, SkillName: baseline.SkillName}
	s.DB.Create(&earlier)
	s.DB.Create(&db.Finding{RepositoryID: baseline.RepositoryID, ScanID: earlier.ID, Title: "Open redirect", Severity: "Low", Fingerprint: "fp-known", Status: db.FindingRejected})
	s.DB.Create(&db.CandidateObservation{ScanID: candidate.ID, RepositoryID: baseline.RepositoryID, Fingerprint: "fp-known", Title: "Open redirect", Severity: "Low"})

	page = getRepoPagePath(t, s, fmt.Sprintf("/scans/%d/experiment", baseline.ID))
	if got := experimentMeasurement(t, page, "Baseline false positives"); got != "1 of 1 triaged" {
		t.Errorf("Baseline false positives = %q, want 1 of 1 triaged for the rejected baseline finding only", got)
	}
}

// Candidate analyst effort sums recorded minutes over the observations that have any, and baseline analyst effort is always unavailable.
func TestScanExperiment_analystEffort(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	baseline, candidate, extra := seedComparison(t, s)
	var shared db.CandidateObservation
	s.DB.Where("scan_id = ? AND fingerprint = ?", candidate.ID, "fp-shared").First(&shared)

	assessObservation(t, s, extra.ID, url.Values{"assessment": {db.CandidateConfirmed}})
	page := getRepoPagePath(t, s, fmt.Sprintf("/scans/%d/experiment", baseline.ID))
	if got := experimentMeasurement(t, page, "Candidate analyst effort"); got != "unavailable" {
		t.Errorf("Candidate analyst effort = %q with no minutes recorded, want unavailable", got)
	}

	assessObservation(t, s, extra.ID, url.Values{"assessment": {db.CandidateConfirmed}, "effort_minutes": {"25"}})
	page = getRepoPagePath(t, s, fmt.Sprintf("/scans/%d/experiment", baseline.ID))
	if got := experimentMeasurement(t, page, "Candidate analyst effort"); got != "25 min on 1 of 2" {
		t.Errorf("Candidate analyst effort = %q, want 25 min on 1 of 2", got)
	}
	if got := experimentMeasurement(t, page, "Baseline analyst effort"); got != "unavailable" {
		t.Errorf("Baseline analyst effort = %q, want unavailable", got)
	}

	assessObservation(t, s, extra.ID, url.Values{"assessment": {db.CandidateConfirmed}})
	assessObservation(t, s, shared.ID, url.Values{"effort_minutes": {"0"}})
	page = getRepoPagePath(t, s, fmt.Sprintf("/scans/%d/experiment", baseline.ID))
	if got := experimentMeasurement(t, page, "Candidate analyst effort"); got != "0 min on 1 of 2" {
		t.Errorf("Candidate analyst effort = %q with only 0 minutes recorded, want 0 min on 1 of 2", got)
	}
}

// A failed candidate run counts in Failed candidate runs whichever run is selected, warns that its comparison may be incomplete and shows no findings count it never reported.
func TestScanExperiment_failedCandidateRun(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	baseline, candidate, _ := seedComparison(t, s)
	failed := db.Scan{RepositoryID: baseline.RepositoryID, Kind: worker.JobSkill, Status: db.ScanFailed, SkillName: candidate.SkillName,
		Error: "container exited with status 137", Experiment: "trial", ExperimentConfig: baseline.ExperimentConfig, CandidateOfScanID: &baseline.ID}
	s.DB.Create(&failed)

	page := getRepoPagePath(t, s, fmt.Sprintf("/scans/%d/experiment", baseline.ID))
	if !strings.Contains(page, "This run is failed: container exited with status 137. Its observations may be incomplete.") {
		t.Error("the failed run's comparison does not warn that it may be incomplete")
	}
	if got := experimentMeasurement(t, page, "Failed candidate runs"); got != "1" {
		t.Errorf("Failed candidate runs = %q, want 1", got)
	}
	if got := experimentRunCells(t, page, failed.ID)[7]; got != "unavailable" {
		t.Errorf("failed run Findings = %q, want unavailable", got)
	}
	if got := experimentRunCells(t, page, candidate.ID)[7]; got != "0" {
		t.Errorf("done run Findings = %q, want 0", got)
	}

	page = getRepoPagePath(t, s, fmt.Sprintf("/scans/%d/experiment?candidate=%d", baseline.ID, candidate.ID))
	if strings.Contains(page, "may be incomplete") {
		t.Error("the done run's comparison warns that it may be incomplete")
	}
	if got := experimentMeasurement(t, page, "Failed candidate runs"); got != "1" {
		t.Errorf("Failed candidate runs = %q with the done run selected, want 1", got)
	}
}

// A retried candidate run names the run it retries, and the first run names none.
func TestScanExperiment_retriedCandidateNamesItsParent(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	fx := seedExperimentFixture(t, s)
	baseline := finishedBaseline(t, s, fx)
	s.enqueueCandidate(&baseline)
	first := candidatesOf(t, s, baseline.ID)[0]
	s.DB.Model(&first).Updates(map[string]any{"status": db.ScanFailed, "error": "boom"})
	if w := postForm(t, s, fmt.Sprintf("/scans/%d/retry", first.ID), url.Values{}); w.Code != http.StatusSeeOther {
		t.Fatalf("retry status %d: %s", w.Code, w.Body)
	}
	retry := candidatesOf(t, s, baseline.ID)[1]

	page := getRepoPagePath(t, s, fmt.Sprintf("/scans/%d/experiment", baseline.ID))
	if got, want := experimentRunCells(t, page, retry.ID)[0], fmt.Sprintf("#%d retry of #%d", retry.ID, first.ID); got != want {
		t.Errorf("retry Scan cell = %q, want %q", got, want)
	}
	if got, want := experimentRunCells(t, page, first.ID)[0], fmt.Sprintf("#%d", first.ID); got != want {
		t.Errorf("first run Scan cell = %q, want %q", got, want)
	}
}

// An empty assessment clears the verdict and its timestamp, and an unknown observation id is a 404.
func TestCandidateObservationAssess_clearsAndRefusesMissingObservations(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	baseline, candidate, extra := seedComparison(t, s)

	assessObservation(t, s, extra.ID, url.Values{"assessment": {db.CandidateConfirmed}, "effort_minutes": {"25"}, "note": {"reproduced"}})
	var reloaded db.CandidateObservation
	s.DB.First(&reloaded, extra.ID)
	if reloaded.Assessment != db.CandidateConfirmed || reloaded.AssessedAt == nil {
		t.Fatalf("observation = assessment %q assessed_at %v, want confirmed with a timestamp", reloaded.Assessment, reloaded.AssessedAt)
	}

	assessObservation(t, s, extra.ID, url.Values{"assessment": {""}})
	reloaded = db.CandidateObservation{}
	s.DB.First(&reloaded, extra.ID)
	if reloaded.Assessment != "" || reloaded.AssessedAt != nil || reloaded.EffortMinutes != nil || reloaded.AssessmentNote != "" {
		t.Errorf("observation = %+v after clearing, want no assessment, timestamp, effort or note", reloaded)
	}
	page := getRepoPagePath(t, s, fmt.Sprintf("/scans/%d/experiment", baseline.ID))
	if got := experimentMeasurement(t, page, "Additional confirmed"); got != "unavailable" {
		t.Errorf("Additional confirmed = %q after clearing the only assessment, want unavailable", got)
	}

	gone := db.CandidateObservation{ScanID: candidate.ID, RepositoryID: baseline.RepositoryID, Fingerprint: "fp-gone", Title: "Gone"}
	s.DB.Create(&gone)
	s.DB.Delete(&gone)
	if w := postForm(t, s, fmt.Sprintf("/candidate-observations/%d/assessment", gone.ID), url.Values{"assessment": {db.CandidateConfirmed}}); w.Code != http.StatusNotFound {
		t.Errorf("assessing a missing observation: status %d, want 404", w.Code)
	}
}
