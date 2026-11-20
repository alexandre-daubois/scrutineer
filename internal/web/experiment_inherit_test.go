package web

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"scrutineer/internal/config"
	"scrutineer/internal/db"
	"scrutineer/internal/worker"
)

func retriesOf(t *testing.T, s *Server, parentID uint) []db.Scan {
	t.Helper()
	var scans []db.Scan
	if err := s.DB.Where("parent_scan_id = ?", parentID).Order("id").Find(&scans).Error; err != nil {
		t.Fatal(err)
	}
	return scans
}

// A candidate copies its baseline's runner profile, egress policy, cost cap and diff rescan settings,
// and starts nowhere once the baseline's egress policy is no longer configured.
func TestEnqueueCandidate_inheritsTheBaselineExecutionSettings(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	fx := seedExperimentFixture(t, s)
	s.ScanEgressPolicies = []string{"registries"}
	diffBase := db.Scan{RepositoryID: fx.repo.ID, Kind: worker.JobSkill, Status: db.ScanDone, SkillID: &fx.findings.ID, SkillName: fx.findings.Name, Commit: "feedbeef"}
	s.DB.Create(&diffBase)
	settings := map[string]any{"profile": "gpu-runner", "egress_policy": "registries", "max_cost_usd": 2.5,
		"rescan_mode": db.ScanRescanModeDiff, "diff_base_scan_id": diffBase.ID}

	baseline := finishedBaseline(t, s, fx)
	s.DB.Model(&baseline).Updates(settings)
	baseline = reloadScan(t, s, baseline.ID)
	s.enqueueCandidate(&baseline)
	got := candidatesOf(t, s, baseline.ID)
	if len(got) != 1 {
		t.Fatalf("candidates = %d, want 1", len(got))
	}
	c := got[0]
	if c.Profile != "gpu-runner" || c.EgressPolicy != "registries" || c.MaxCostUSD != 2.5 || c.RescanMode != db.ScanRescanModeDiff ||
		c.DiffBaseScanID == nil || *c.DiffBaseScanID != diffBase.ID {
		t.Errorf("candidate = profile %q egress %q max cost %v rescan %q diff base %v, want the baseline's", c.Profile, c.EgressPolicy, c.MaxCostUSD, c.RescanMode, c.DiffBaseScanID)
	}

	s.ScanEgressPolicies = nil
	stale := finishedBaseline(t, s, fx)
	s.DB.Model(&stale).Updates(settings)
	stale = reloadScan(t, s, stale.ID)
	s.enqueueCandidate(&stale)
	requireRefusedCandidate(t, s, stale.ID, "registries")
}

// An experiment skill that requires another runner profile than the baseline ran with starts no candidate.
func TestEnqueueCandidate_refusesAnExperimentSkillNeedingAnotherProfile(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	fx := seedExperimentFixture(t, s)
	s.DB.Model(&fx.variant).Update("requires_profile", "gpu-runner")

	for profile, want := range map[string]int{"cpu-runner": 0, "gpu-runner": 1} {
		baseline := finishedBaseline(t, s, fx)
		s.DB.Model(&baseline).Update("profile", profile)
		baseline.Profile = profile
		s.enqueueCandidate(&baseline)
		if want == 0 {
			requireRefusedCandidate(t, s, baseline.ID, "gpu-runner")
			continue
		}
		got := candidatesOf(t, s, baseline.ID)
		if len(got) != 1 || got[0].Status != db.ScanQueued {
			t.Errorf("baseline profile %q: candidates %+v, want one queued", profile, got)
			continue
		}
		if got[0].Profile != "gpu-runner" || got[0].SkillID == nil || *got[0].SkillID != fx.variant.ID {
			t.Errorf("candidate = profile %q skill %v, want the variant skill on gpu-runner", got[0].Profile, got[0].SkillID)
		}
	}
}

// Launching an experiment on a local-directory repository is a 422 that creates no scan.
func TestSkillRun_refusesAnExperimentOnALocalRepository(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	fx := seedExperimentFixture(t, s)
	local := db.Repository{URL: "file:///srv/checkouts/exp", Name: "local-exp"}
	s.DB.Create(&local)

	w := postExperimentScan(s, local, fx.findings, "trial")
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "local directory") {
		t.Fatalf("status %d: %s, want 422 naming the local directory", w.Code, w.Body)
	}
	if n := len(skillScans(s)); n != 0 {
		t.Fatalf("%d scans created, want 0", n)
	}

	if w := postExperimentScan(s, local, fx.findings, ""); w.Code != http.StatusSeeOther {
		t.Fatalf("plain scan of the local repository: status %d: %s", w.Code, w.Body)
	}
	if scans := skillScans(s); len(scans) != 1 || scans[0].RepositoryID != local.ID {
		t.Fatalf("%d scans, want one plain scan of the local repository", len(scans))
	}
}

// Retrying a candidate whose model is no longer configured is a 422, never a run on the skill default.
func TestScanRetry_refusesACandidateWhoseModelIsGone(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	fx := seedExperimentFixture(t, s)
	baseline := finishedBaseline(t, s, fx)
	s.enqueueCandidate(&baseline)
	first := candidatesOf(t, s, baseline.ID)[0]
	s.DB.Model(&first).Updates(map[string]any{"status": db.ScanFailed, "model": "retired-model"})

	w := postForm(t, s, fmt.Sprintf("/scans/%d/retry", first.ID), url.Values{})
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "retired-model") {
		t.Fatalf("retry status %d: %s, want 422 naming the model", w.Code, w.Body)
	}
	if got := retriesOf(t, s, first.ID); len(got) != 0 {
		t.Fatalf("%d retries, want none", len(got))
	}

	s.DB.Model(&first).Update("model", fx.candidate)
	if w := postForm(t, s, fmt.Sprintf("/scans/%d/retry", first.ID), url.Values{}); w.Code != http.StatusSeeOther {
		t.Fatalf("retry with a configured model: status %d: %s", w.Code, w.Body)
	}
	if got := retriesOf(t, s, first.ID); len(got) != 1 || got[0].Model != fx.candidate || !got[0].IsCandidate() {
		t.Fatalf("%d retries, want one candidate on %s", len(got), fx.candidate)
	}
}

// A candidate retried after its scan_experiments entry was removed and its experiment skill renamed runs the model, effort, skill and snapshot it ran with.
func TestScanRetry_candidateKeepsItsSnapshotOnceTheEntryIsRemoved(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	fx := seedExperimentFixture(t, s)
	baseline := finishedBaseline(t, s, fx)
	s.enqueueCandidate(&baseline)
	first := candidatesOf(t, s, baseline.ID)[0]
	s.DB.Model(&first).Update("status", db.ScanFailed)
	delete(s.ScanExperiments, "trial")
	s.DB.Model(&fx.variant).Update("name", "deep-dive-v3")

	if w := postForm(t, s, fmt.Sprintf("/scans/%d/retry", first.ID), url.Values{}); w.Code != http.StatusSeeOther {
		t.Fatalf("retry status %d: %s", w.Code, w.Body)
	}
	got := retriesOf(t, s, first.ID)
	if len(got) != 1 {
		t.Fatalf("retries = %d, want 1", len(got))
	}
	r := got[0]
	if r.Model != fx.candidate || r.Effort != "low" || r.SkillID == nil || *r.SkillID != fx.variant.ID {
		t.Errorf("retry = model %q effort %q skill %v, want %q low %d", r.Model, r.Effort, r.SkillID, fx.candidate, fx.variant.ID)
	}
	if r.ExperimentConfig != first.ExperimentConfig || r.CandidateOfScanID == nil || *r.CandidateOfScanID != baseline.ID {
		t.Errorf("retry = config %q candidate of %v, want the first run's snapshot against baseline %d", r.ExperimentConfig, r.CandidateOfScanID, baseline.ID)
	}
}

// A retried baseline that finalizes starts its own candidate, pinned to the retry's commit, and leaves the first pair alone.
func TestScanRetry_retriedBaselineStartsAFreshCandidate(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	fx := seedExperimentFixture(t, s)
	baseline := finishedBaseline(t, s, fx)
	s.onScanFinalized(&baseline)
	first := candidatesOf(t, s, baseline.ID)
	if len(first) != 1 {
		t.Fatalf("first candidates = %d, want 1", len(first))
	}

	if w := postForm(t, s, fmt.Sprintf("/scans/%d/retry", baseline.ID), url.Values{}); w.Code != http.StatusSeeOther {
		t.Fatalf("retry status %d: %s", w.Code, w.Body)
	}
	retries := retriesOf(t, s, baseline.ID)
	if len(retries) != 1 {
		t.Fatalf("retries = %d, want 1", len(retries))
	}
	s.DB.Model(&retries[0]).Updates(map[string]any{"status": db.ScanDone, "commit": "4567cdef"})
	retry := reloadScan(t, s, retries[0].ID)
	s.onScanFinalized(&retry)

	got := candidatesOf(t, s, retry.ID)
	if len(got) != 1 {
		t.Fatalf("candidates of the retry = %d, want 1", len(got))
	}
	if got[0].Ref != "4567cdef" {
		t.Errorf("retry candidate ref = %q, want the retry's commit 4567cdef", got[0].Ref)
	}
	if again := candidatesOf(t, s, baseline.ID); len(again) != 1 || again[0].ID != first[0].ID || again[0].Ref != baseline.Commit {
		t.Errorf("first pair = %d candidates, want only #%d on %s", len(again), first[0].ID, baseline.Commit)
	}
}

// Bulk retry lets neither an ordinary scan nor a candidate supersede the other's failure, while a later ordinary run still supersedes an ordinary failure.
func TestScansRetryFailed_ordinaryAndCandidateRunsDoNotSupersedeEachOther(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	fx := seedExperimentFixture(t, s)
	baseline := finishedBaseline(t, s, fx)
	snapshot := experimentSnapshot(t, config.ScanExperiment{Model: fx.candidate})
	scan := func(subPath string, status db.ScanStatus, candidate bool) db.Scan {
		sc := db.Scan{RepositoryID: fx.repo.ID, Kind: worker.JobSkill, Status: status, SkillID: &fx.findings.ID, SkillName: fx.findings.Name,
			Model: fx.candidate, Ref: baseline.Commit, Commit: baseline.Commit, SubPath: subPath}
		if candidate {
			sc.Experiment, sc.ExperimentConfig, sc.CandidateOfScanID = "trial", snapshot, &baseline.ID
		}
		if err := s.DB.Create(&sc).Error; err != nil {
			t.Fatal(err)
		}
		return sc
	}
	ordinary := scan("a", db.ScanFailed, false)
	scan("a", db.ScanDone, true)
	candidate := scan("b", db.ScanFailed, true)
	scan("b", db.ScanDone, false)
	superseded := scan("c", db.ScanFailed, false)
	scan("c", db.ScanDone, false)

	if w := postForm(t, s, "/scans/retry-failed", url.Values{}); w.Code >= 400 {
		t.Fatalf("bulk retry status %d: %s", w.Code, w.Body)
	}
	if got := retriesOf(t, s, ordinary.ID); len(got) != 1 || got[0].IsCandidate() {
		t.Errorf("ordinary scan: %d retries, want one ordinary scan despite the later candidate", len(got))
	}
	if got := retriesOf(t, s, candidate.ID); len(got) != 1 || got[0].CandidateOfScanID == nil || *got[0].CandidateOfScanID != baseline.ID {
		t.Errorf("candidate: %d retries, want one candidate of baseline %d despite the later ordinary scan", len(got), baseline.ID)
	}
	if got := retriesOf(t, s, superseded.ID); len(got) != 0 {
		t.Errorf("superseded ordinary scan: %d retries, want none behind the later ordinary scan", len(got))
	}
}
