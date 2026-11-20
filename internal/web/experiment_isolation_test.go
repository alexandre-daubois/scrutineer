package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"scrutineer/internal/db"
	"scrutineer/internal/worker"
)

const candidateGateRefusal = "candidate scans may only read"

// The scheduled rescan fires past a queued or paused candidate and still skips behind an open ordinary scan.
func TestRunScheduledScan_openCandidateDoesNotHoldTheRescan(t *testing.T) {
	for name, tc := range map[string]struct {
		status    db.ScanStatus
		candidate bool
		wantFired bool
	}{
		"queued candidate":     {db.ScanQueued, true, true},
		"paused candidate":     {db.ScanPaused, true, true},
		"queued ordinary scan": {db.ScanQueued, false, false},
	} {
		t.Run(name, func(t *testing.T) {
			s, _, done := scheduleTestServer(t, "def456", nil)
			defer done()
			for _, name := range []string{deepDiveSkillName, threatModelSkillName} {
				s.DB.Create(&db.Skill{Name: name, Description: "d", Body: "b", OutputFile: "report.json", Version: 1, Active: true, Source: "ui"})
			}
			repo := scheduledRepo(t, s, "daily", time.Now().Add(-time.Minute))
			baseline := db.Scan{RepositoryID: repo.ID, Kind: worker.JobSkill, Status: db.ScanDone, SkillName: deepDiveSkillName, Commit: "abc123"}
			s.DB.Create(&baseline)
			open := db.Scan{RepositoryID: repo.ID, Kind: worker.JobSkill, Status: tc.status, SkillName: deepDiveSkillName}
			if tc.candidate {
				open.Experiment, open.CandidateOfScanID = "trial", &baseline.ID
			}
			s.DB.Create(&open)

			s.runScheduledScan(context.Background(), repo, time.Second)

			var rescans int64
			s.DB.Model(&db.Scan{}).Where("repository_id = ? AND skill_name = ? AND rescan_mode = ? AND status = ?",
				repo.ID, threatModelSkillName, db.ScanRescanModeDiff, db.ScanQueued).Count(&rescans)
			skips := countSkips(t, s, repo.ID)
			if tc.wantFired && (rescans != 1 || skips != 0) {
				t.Fatalf("rescans %d skips %d, want the rescan enqueued past the candidate", rescans, skips)
			}
			if !tc.wantFired && (rescans != 0 || !strings.Contains(lastSkip(t, s, repo.ID).Error, "queued or running")) {
				t.Fatalf("rescans %d, want a skip behind the open ordinary scan", rescans)
			}
		})
	}
}

// The repository list sorted by last scan orders on each repository's latest ordinary scan, never a newer candidate.
func TestRepoList_sortScannedIgnoresCandidates(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	older := db.Repository{URL: "https://github.com/example/older", Name: "older"}
	newer := db.Repository{URL: "https://github.com/example/newer", Name: "newer"}
	s.DB.Create(&older)
	s.DB.Create(&newer)
	olderScan := db.Scan{RepositoryID: older.ID, Kind: worker.JobSkill, SkillName: deepDiveSkillName, Status: db.ScanDone, Commit: "abc"}
	s.DB.Create(&olderScan)
	s.DB.Create(&db.Scan{RepositoryID: newer.ID, Kind: worker.JobSkill, SkillName: deepDiveSkillName, Status: db.ScanDone, Commit: "def"})
	s.DB.Create(&db.Scan{RepositoryID: older.ID, Kind: worker.JobSkill, SkillName: deepDiveSkillName, Status: db.ScanDone, Commit: "abc",
		Experiment: "trial", CandidateOfScanID: &olderScan.ID})

	for sort, wantNewerFirst := range map[string]bool{"scanned": true, "scanned.asc": false} {
		body := getRepoPagePath(t, s, "/?sort="+sort)
		o := strings.Index(body, fmt.Sprintf(`<tr id="repo-%d">`, older.ID))
		n := strings.Index(body, fmt.Sprintf(`<tr id="repo-%d">`, newer.ID))
		if o < 0 || n < 0 {
			t.Fatalf("sort=%s: missing repo rows (older at %d, newer at %d)", sort, o, n)
		}
		if (n < o) != wantNewerFirst {
			t.Errorf("sort=%s: newer listed first = %v, want %v", sort, n < o, wantNewerFirst)
		}
	}
}

// Usage sink counts come from the latest ordinary deep-dive report, not a newer candidate's.
func TestLoadUsageDeepDiveSinks_skipsCandidateReports(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://github.com/example/sinks", Name: "sinks"}
	s.DB.Create(&repo)
	baseline := db.Scan{RepositoryID: repo.ID, Kind: worker.JobSkill, SkillName: deepDiveSkillName, Status: db.ScanDone, CostUSD: 1,
		Report: `{"inventory":[{},{}]}`}
	s.DB.Create(&baseline)
	candidate := db.Scan{RepositoryID: repo.ID, Kind: worker.JobSkill, SkillName: deepDiveSkillName, Status: db.ScanDone, CostUSD: 1,
		Report: `{"inventory":[{},{},{},{},{}]}`, Experiment: "trial", CandidateOfScanID: &baseline.ID}
	s.DB.Create(&candidate)

	got := s.loadUsageDeepDiveSinks()
	if len(got) != 1 || got[baseline.ID] != 2 {
		t.Errorf("sinks = %v, want only baseline %d with 2 sinks", got, baseline.ID)
	}
}

// A candidate token is refused communications, references, submissions and streaming into another repository, and none of them writes a row.
func TestCandidateAPI_refusesDisclosureWritesAndForeignStreams(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo, baseline := seedRunningScan(t, s)
	other := db.Repository{URL: "https://example.com/other", Name: "other"}
	s.DB.Create(&other)
	finding := db.Finding{RepositoryID: repo.ID, ScanID: baseline.ID, Title: "SQLi", Severity: "High", Status: db.FindingNew}
	s.DB.Create(&finding)
	candidate := db.Scan{RepositoryID: repo.ID, Kind: worker.JobSkill, Status: db.ScanRunning, SkillName: deepDiveSkillName,
		Experiment: "trial", CandidateOfScanID: &baseline.ID, APIToken: "tok-candidate", FindingID: &finding.ID}
	s.DB.Create(&candidate)
	stream := `{"id":"F1","title":"Path traversal","severity":"Critical","location":"b.go:9","trace":"User input reaches os.Open unchecked."}`
	submission := `{"channel":"pvr","external_id":"GHSA-abcd-efgh-ijkl","url":"https://github.com/acme/widget/security/advisories/GHSA-abcd-efgh-ijkl",` +
		`"actor":"report-upstream","body":"Filed PVR report.","request":{"summary":"Path traversal"}}`

	for _, tc := range []struct{ path, body string }{
		{fmt.Sprintf("/findings/%d/communications", finding.ID), `{"channel":"github","direction":"outbound","actor":"bot","body":"hello maintainers"}`},
		{fmt.Sprintf("/findings/%d/references", finding.ID), `{"url":"https://example.com/advisory","tags":"ghsa"}`},
		{fmt.Sprintf("/findings/%d/submissions", finding.ID), submission},
		{fmt.Sprintf("/repositories/%d/findings", other.ID), stream},
	} {
		w := candidateAPIRequest(t, s, candidate.APIToken, "POST", tc.path, tc.body)
		if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), candidateGateRefusal) {
			t.Errorf("POST %s: status %d %s, want 403 from the candidate gate", tc.path, w.Code, w.Body)
		}
	}
	var comms, refs, subs, findings, obs int64
	s.DB.Model(&db.FindingCommunication{}).Count(&comms)
	s.DB.Model(&db.FindingReference{}).Count(&refs)
	s.DB.Model(&db.DisclosureSubmission{}).Count(&subs)
	s.DB.Model(&db.Finding{}).Count(&findings)
	s.DB.Model(&db.CandidateObservation{}).Count(&obs)
	if comms != 0 || refs != 0 || subs != 0 || findings != 1 || obs != 0 {
		t.Errorf("after refused writes: communications %d references %d submissions %d findings %d observations %d, want 0 0 0 1 0",
			comms, refs, subs, findings, obs)
	}

	if w := candidateAPIRequest(t, s, candidate.APIToken, "POST", fmt.Sprintf("/repositories/%d/findings", repo.ID), stream); w.Code != http.StatusCreated {
		t.Fatalf("stream into its own repository: status %d %s, want 201", w.Code, w.Body)
	}
}

// A scan_group sibling listing the group's findings sees an ordinary member's stream and nothing a candidate in that group streamed.
func TestAPIListFindings_scanGroupHidesCandidateStreams(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo, member := seedRunningScan(t, s)
	s.DB.Model(&member).Updates(map[string]any{"scan_group": "grp-1", "skill_name": deepDiveSkillName})
	sibling := db.Scan{RepositoryID: repo.ID, Kind: worker.JobSkill, Status: db.ScanRunning, SkillName: "semgrep", ScanGroup: "grp-1", APIToken: "tok-sibling"}
	s.DB.Create(&sibling)
	candidate := db.Scan{RepositoryID: repo.ID, Kind: worker.JobSkill, Status: db.ScanRunning, SkillName: deepDiveSkillName, ScanGroup: "grp-1",
		Experiment: "trial", CandidateOfScanID: &member.ID, APIToken: "tok-candidate"}
	s.DB.Create(&candidate)

	path := fmt.Sprintf("/repositories/%d/findings", repo.ID)
	for token, body := range map[string]string{
		candidate.APIToken: `{"id":"F1","title":"Path traversal","severity":"Critical","location":"b.go:9","trace":"User input reaches os.Open unchecked."}`,
		member.APIToken:    `{"id":"F2","title":"SQLi","severity":"High","location":"a.go:3","trace":"User input reaches the query unescaped."}`,
	} {
		if w := candidateAPIRequest(t, s, token, "POST", path, body); w.Code != http.StatusCreated {
			t.Fatalf("stream with %s: status %d %s", token, w.Code, w.Body)
		}
	}

	w := candidateAPIRequest(t, s, sibling.APIToken, "GET", path+"?scan_group=grp-1", "")
	if w.Code != http.StatusOK {
		t.Fatalf("sibling read status %d: %s", w.Code, w.Body)
	}
	var rows []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0]["title"] != "SQLi" {
		t.Errorf("group findings = %v, want only the ordinary member's SQLi", rows)
	}
}

// enqueueSkillWith refuses a candidate joining a scan group, a triage cohort or a focus area, or naming an unconfigured model, and writes no row.
func TestEnqueueSkillWith_refusesCandidateOptsOutsideItsSandbox(t *testing.T) {
	for name, tc := range map[string]struct {
		set     func(*ScanOpts, db.Scan)
		refused bool
	}{
		"plain candidate": {func(*ScanOpts, db.Scan) {}, false},
		"scan group":      {func(o *ScanOpts, _ db.Scan) { o.ScanGroup = "grp-1" }, true},
		"triage cohort":   {func(o *ScanOpts, b db.Scan) { o.TriageScanID = &b.ID }, true},
		"focus area": {func(o *ScanOpts, _ db.Scan) {
			o.FocusArea = `{"name":"parser","paths":["src/**"],"surface":"request bytes"}`
		}, true},
		"unconfigured model": {func(o *ScanOpts, _ db.Scan) { o.Model = "no-such-model" }, true},
	} {
		t.Run(name, func(t *testing.T) {
			s, done := newTestServer(t)
			defer done()
			fx := seedExperimentFixture(t, s)
			baseline := finishedBaseline(t, s, fx)
			opts := ScanOpts{Model: fx.candidate, Ref: baseline.Commit, Experiment: "trial", ExperimentConfig: baseline.ExperimentConfig, CandidateOfScanID: &baseline.ID}
			tc.set(&opts, baseline)

			_, err := s.enqueueSkillWith(context.Background(), fx.repo.ID, fx.variant.ID, opts)
			rows := len(candidatesOf(t, s, baseline.ID))
			if tc.refused && (!errors.Is(err, ErrInvalidExperiment) || rows != 0) {
				t.Errorf("err = %v with %d candidate rows, want ErrInvalidExperiment and none", err, rows)
			}
			if !tc.refused && (err != nil || rows != 1) {
				t.Errorf("err = %v with %d candidate rows, want one enqueued candidate", err, rows)
			}
		})
	}
}
