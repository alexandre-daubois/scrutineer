package worker

import (
	"slices"
	"testing"

	"scrutineer/internal/db"
)

const (
	candidateDiffSHA = "abc"
	streamedXSS      = `{"id":"F3","title":"XSS","severity":"Medium","cwe":"CWE-79","location":"c.rb:3","trace":"The name parameter is echoed unescaped."}`
)

// candidateDiffFixture seeds a done ordinary scan on ref main, its earlier
// diff base, and a done scan under the candidate's own skill and pinned SHA.
func candidateDiffFixture(t *testing.T) (w *Worker, repo db.Repository, base, decoy, ordinary, candidate *db.Scan) {
	t.Helper()
	w, repo = observationWorker(t)
	base = &db.Scan{RepositoryID: repo.ID, Kind: JobSkill, SkillName: "security-deep-dive", Ref: "main", Status: db.ScanDone, Commit: "base"}
	decoy = &db.Scan{RepositoryID: repo.ID, Kind: JobSkill, SkillName: "deep-dive-v2", Ref: candidateDiffSHA, Status: db.ScanDone, Commit: "decoy"}
	for _, s := range []*db.Scan{base, decoy} {
		if err := w.DB.Create(s).Error; err != nil {
			t.Fatal(err)
		}
	}
	ordinary, candidate = candidatePair(t, w, repo)
	if err := w.DB.Model(ordinary).Updates(map[string]any{"ref": "main", "diff_base_scan_id": base.ID}).Error; err != nil {
		t.Fatal(err)
	}
	candidate.Ref = candidateDiffSHA
	return w, repo, base, decoy, ordinary, candidate
}

// A candidate pinned to its ordinary scan's diff base resolves it, and a pin to
// a scan under the candidate's own skill and SHA is refused.
func TestCandidateDiff_pinnedBaseIsTheOrdinaryScans(t *testing.T) {
	w, _, base, decoy, ordinary, candidate := candidateDiffFixture(t)

	var stored db.Scan
	if err := w.DB.First(&stored, ordinary.ID).Error; err != nil {
		t.Fatal(err)
	}
	candidate.DiffBaseScanID = stored.DiffBaseScanID
	if got, ok := w.diffBaseline(candidate); !ok || got.ID != base.ID {
		t.Errorf("pinned to the ordinary base: baseline = %d (%v), want scan %d", got.ID, ok, base.ID)
	}

	candidate.DiffBaseScanID = &decoy.ID
	if got, ok := w.diffBaseline(candidate); ok {
		t.Errorf("pinned to a scan under the candidate's skill and SHA: baseline = %d, want none", got.ID)
	}
}

// Without a pinned base, a candidate looks up the latest scan under its ordinary
// scan's skill and ref, while an ordinary scan keys on its own.
func TestCandidateDiff_lookupKeysOnTheOrdinaryScansSkillAndRef(t *testing.T) {
	w, repo, base, decoy, ordinary, candidate := candidateDiffFixture(t)
	if err := w.DB.Model(ordinary).Updates(map[string]any{"status": db.ScanRunning, "diff_base_scan_id": nil}).Error; err != nil {
		t.Fatal(err)
	}
	var stored db.Scan
	if err := w.DB.First(&stored, ordinary.ID).Error; err != nil {
		t.Fatal(err)
	}
	ordinaryBase, ok := w.diffBaseline(&stored)
	if !ok || ordinaryBase.ID != base.ID {
		t.Fatalf("ordinary scan baseline = %d (%v), want scan %d", ordinaryBase.ID, ok, base.ID)
	}

	if got, ok := w.diffBaseline(candidate); !ok || got.ID != ordinaryBase.ID {
		t.Errorf("candidate baseline = %d (%v), want the ordinary scan's base %d", got.ID, ok, ordinaryBase.ID)
	}

	plain := &db.Scan{RepositoryID: repo.ID, SkillName: candidate.SkillName, Ref: candidateDiffSHA}
	if got, ok := w.diffBaseline(plain); !ok || got.ID != decoy.ID {
		t.Errorf("ordinary scan under the candidate's skill and SHA: baseline = %d (%v), want its own scan %d", got.ID, ok, decoy.ID)
	}
}

func candidateDiffTitles(t *testing.T, w *Worker, scanID uint) []string {
	t.Helper()
	var titles []string
	for _, o := range candidateObservations(t, w, scanID) {
		titles = append(titles, o.Title)
	}
	return titles
}

// streamCandidateRuns streams SQLi and XSS on the candidate, and XSS on a
// retry of the same ordinary scan.
func streamCandidateRuns(t *testing.T) (w *Worker, candidate, sibling *db.Scan) {
	t.Helper()
	w, repo := observationWorker(t)
	ordinary, candidate := candidatePair(t, w, repo)
	sibling = &db.Scan{RepositoryID: repo.ID, Kind: JobSkill, SkillName: "deep-dive-v2", Status: db.ScanRunning,
		Commit: "abc", Experiment: "trial", CandidateOfScanID: &ordinary.ID, ParentScanID: &candidate.ID}
	if err := w.DB.Create(sibling).Error; err != nil {
		t.Fatal(err)
	}
	for _, s := range []struct {
		scan *db.Scan
		raw  string
	}{
		{candidate, `{"id":"F1","title":"SQLi","severity":"High","cwe":"CWE-89","location":"a.rb:1","trace":"User input reaches the query unescaped."}`},
		{candidate, streamedXSS},
		{sibling, streamedXSS},
	} {
		if _, err := w.PersistStreamedFinding(s.scan, []byte(s.raw)); err != nil {
			t.Fatal(err)
		}
	}
	return w, candidate, sibling
}

// The final report drops a streamed observation it left out and keeps the
// ones it reports, without touching another run's rows.
func TestCandidateDiff_reportDropsStreamedObservationsItLeftOut(t *testing.T) {
	w, candidate, sibling := streamCandidateRuns(t)

	if err := w.parseCandidateOutput(&db.Skill{OutputKind: "findings"}, candidate, candidateReport, func(Event) {}); err != nil {
		t.Fatal(err)
	}

	if got := candidateDiffTitles(t, w, candidate.ID); !slices.Equal(got, []string{"SQLi", "Path traversal"}) {
		t.Errorf("candidate observations = %v, want SQLi and Path traversal", got)
	}
	if got := candidateDiffTitles(t, w, sibling.ID); !slices.Equal(got, []string{"XSS"}) {
		t.Errorf("other run's observations = %v, want its streamed XSS", got)
	}
}

// An empty final report drops every observation the run streamed and leaves
// another run's rows in place.
func TestCandidateDiff_emptyReportDropsEveryStreamedObservation(t *testing.T) {
	w, candidate, sibling := streamCandidateRuns(t)

	if err := w.parseCandidateOutput(&db.Skill{OutputKind: "findings"}, candidate, `{"findings":[]}`, func(Event) {}); err != nil {
		t.Fatal(err)
	}

	if got := candidateDiffTitles(t, w, candidate.ID); len(got) != 0 {
		t.Errorf("candidate observations = %v, want none", got)
	}
	if got := candidateDiffTitles(t, w, sibling.ID); !slices.Equal(got, []string{"XSS"}) {
		t.Errorf("other run's observations = %v, want its streamed XSS", got)
	}
}
