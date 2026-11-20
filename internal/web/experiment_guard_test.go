package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"scrutineer/internal/config"
	"scrutineer/internal/db"
	"scrutineer/internal/worker"
)

var (
	experimentDecisionSelectRE  = regexp.MustCompile(`(?s)<select[^>]*name="decision"[^>]*>(.*?)</select>`)
	experimentSelectedOptionRE  = regexp.MustCompile(`<option value="([^"]*)"[^>]*\sselected[\s>]`)
	experimentFailOnReport      = `{"findings":[{"title":"SQLi","severity":"Critical","cwe":"CWE-89","location":"a.go:3"}]}`
	experimentGuardStagedDigest = "5e1f0c8d2b7a4e93"
	errExperimentGuardBaseline  = errors.New("runner exploded")
)

// A candidate's skill running on the host refuses the launch with 422, and the ordinary skill running there does not.
func TestSkillRun_refusesAnExperimentWhoseCandidateRunsOnTheHost(t *testing.T) {
	for name, tc := range map[string]struct {
		runner  func(fx experimentFixture) worker.SkillRunner
		refused bool
	}{
		"local claude": {func(experimentFixture) worker.SkillRunner { return worker.LocalClaude{} }, true},
		"host split naming the experiment skill": {func(fx experimentFixture) worker.SkillRunner {
			return worker.HostSplitRunner{Container: worker.ContainerRunner{}, Host: worker.LocalClaude{}, HostSkills: []string{fx.variant.Name}}
		}, true},
		"host split naming the ordinary skill": {func(fx experimentFixture) worker.SkillRunner {
			return worker.HostSplitRunner{Container: worker.ContainerRunner{}, Host: worker.LocalClaude{}, HostSkills: []string{fx.findings.Name}}
		}, false},
	} {
		t.Run(name, func(t *testing.T) {
			s, done := newTestServer(t)
			defer done()
			fx := seedExperimentFixture(t, s)
			s.Worker.Runner = tc.runner(fx)

			w := postExperimentScan(s, fx.repo, fx.findings, "trial")
			scans := skillScans(s)
			if tc.refused && (w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "requires a container runner") || len(scans) != 0) {
				t.Fatalf("status %d: %s with %d scans, want 422 naming the container runner and no scan", w.Code, w.Body, len(scans))
			}
			if !tc.refused && (w.Code != http.StatusSeeOther || len(scans) != 1 || scans[0].Experiment != "trial") {
				t.Fatalf("status %d: %s with %d scans, want one ordinary scan asking for trial", w.Code, w.Body, len(scans))
			}
		})
	}
}

// An experiment skill staging other files than the ordinary skill is refused at launch and recorded as a refused candidate of a finalized baseline, and one staging the same files runs.
func TestExperimentSkill_mustStageTheSameFilesAsTheOrdinarySkill(t *testing.T) {
	scope := map[string]any{"paths": "src/**", "ignore_paths": "vendor/**", "recurse_submodules": true, "full_history": true}
	for name, variant := range map[string]map[string]any{
		"same scope":         {},
		"paths":              {"paths": "lib/**"},
		"ignore_paths":       {"ignore_paths": ""},
		"recurse_submodules": {"recurse_submodules": false},
		"full_history":       {"full_history": false},
	} {
		t.Run(name, func(t *testing.T) {
			s, done := newTestServer(t)
			defer done()
			fx := seedExperimentFixture(t, s)
			s.DB.Model(&db.Skill{}).Where("id IN ?", []uint{fx.findings.ID, fx.variant.ID}).Updates(scope)
			refused := len(variant) > 0
			if refused {
				s.DB.Model(&db.Skill{}).Where("id = ?", fx.variant.ID).Updates(variant)
			}

			w := postExperimentScan(s, fx.repo, fx.findings, "trial")
			if refused && (w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "stages different files")) {
				t.Fatalf("launch status %d: %s, want 422 naming the staged files", w.Code, w.Body)
			}
			if !refused && w.Code != http.StatusSeeOther {
				t.Fatalf("launch status %d: %s, want 303", w.Code, w.Body)
			}

			baseline := finishedBaseline(t, s, fx)
			s.onScanFinalized(&baseline)
			if refused {
				requireRefusedCandidate(t, s, baseline.ID, "stages different files")
				return
			}
			got := candidatesOf(t, s, baseline.ID)
			if len(got) != 1 || got[0].Status != db.ScanQueued || got[0].SkillID == nil || *got[0].SkillID != fx.variant.ID {
				t.Fatalf("candidates = %+v, want one queued run of the variant skill", got)
			}
		})
	}
}

// A running candidate takes no slot of the per-repository open scan cap on scan-token enqueues, while a running ordinary scan does.
func TestAPIRunSkill_runningCandidateTakesNoOpenScanSlot(t *testing.T) {
	for name, tc := range map[string]struct {
		candidate bool
		want      int
		enqueued  int64
	}{
		"running candidate":     {true, http.StatusCreated, 1},
		"running ordinary scan": {false, http.StatusTooManyRequests, 0},
	} {
		t.Run(name, func(t *testing.T) {
			s, done := newTestServer(t)
			defer done()
			repo, caller := seedRunningScan(t, s)
			skill := db.Skill{Name: deepDiveSkillName, Body: "b", OutputFile: "report.json", OutputKind: "findings", Version: 1, Active: true, Source: "ui"}
			s.DB.Create(&skill)
			open := db.Scan{RepositoryID: repo.ID, Kind: worker.JobSkill, Status: db.ScanRunning, SkillName: "semgrep"}
			if tc.candidate {
				open.Experiment, open.CandidateOfScanID = "trial", &caller.ID
			}
			s.DB.Create(&open)
			// The authenticated caller is itself a running ordinary scan and holds one slot.
			s.MaxAgentAPIOpenScansPerRepository = 2

			w := runSkillAPIJSON(t, s, repo, caller, skill.Name, `{}`)
			var enqueued int64
			s.DB.Model(&db.Scan{}).Where("skill_id = ?", skill.ID).Count(&enqueued)
			if w.Code != tc.want || enqueued != tc.enqueued {
				t.Fatalf("status %d: %s with %d scans enqueued, want %d and %d", w.Code, w.Body, enqueued, tc.want, tc.enqueued)
			}
		})
	}
}

// A candidate row between two identical scheduled skips leaves them collapsed into one row, while an ordinary scan between them keeps both.
func TestRecordScheduledSkip_collapsesAcrossACandidate(t *testing.T) {
	for name, tc := range map[string]struct {
		candidate bool
		want      int64
	}{
		"candidate between":     {true, 1},
		"ordinary scan between": {false, 2},
	} {
		t.Run(name, func(t *testing.T) {
			s, done := newTestServer(t)
			defer done()
			repo := db.Repository{URL: "https://example.com/skips", Name: "skips"}
			s.DB.Create(&repo)
			baseline := db.Scan{RepositoryID: repo.ID, Kind: worker.JobSkill, Status: db.ScanDone, SkillName: deepDiveSkillName}
			s.DB.Create(&baseline)

			s.recordScheduledSkip(repo, "no new commits since abc")
			between := db.Scan{RepositoryID: repo.ID, Kind: worker.JobSkill, Status: db.ScanQueued, SkillName: deepDiveSkillName}
			if tc.candidate {
				between.Experiment, between.CandidateOfScanID = "trial", &baseline.ID
			}
			s.DB.Create(&between)
			s.recordScheduledSkip(repo, "no new commits since abc")

			if got := countSkips(t, s, repo.ID); got != tc.want {
				t.Fatalf("skip rows = %d, want %d", got, tc.want)
			}
		})
	}
}

// The decision form preselects no decision, and a POST without one is refused with 422 and records nothing.
func TestScanExperimentDecision_requiresAnExplicitDecision(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	baseline, candidate, _ := seedComparison(t, s)
	s.DB.Model(&candidate).Update("experiment_config", experimentSnapshot(t, config.ScanExperiment{Model: Models[len(Models)-1].ID}))
	s.DB.Model(&db.Skill{}).Where("id = ?", *baseline.SkillID).Update("model", "")

	page := getRepoPagePath(t, s, fmt.Sprintf("/scans/%d/experiment", baseline.ID))
	m := experimentDecisionSelectRE.FindStringSubmatch(page)
	if m == nil {
		t.Fatal("comparison page has no decision select")
	}
	var selected []string
	for _, option := range experimentSelectedOptionRE.FindAllStringSubmatch(m[1], -1) {
		selected = append(selected, option[1])
	}
	if !slices.Equal(selected, []string{""}) || !strings.Contains(m[0], " required>") {
		t.Errorf("decision select = selected %q in %s, want only the empty placeholder selected on a required select", selected, m[0])
	}

	path := fmt.Sprintf("/scans/%d/experiment-decision", candidate.ID)
	for name, form := range map[string]url.Values{
		"empty decision":    {"decision": {""}},
		"no decision field": {"note": {"looks good"}},
	} {
		if w := postForm(t, s, path, form); w.Code != http.StatusUnprocessableEntity {
			t.Errorf("%s: status %d, want 422", name, w.Code)
		}
	}
	var decisions int64
	s.DB.Model(&db.ExperimentDecision{}).Count(&decisions)
	var skill db.Skill
	s.DB.First(&skill, *baseline.SkillID)
	if decisions != 0 || skill.Model != "" {
		t.Fatalf("after refused decisions: %d decisions, skill model %q, want none and unchanged", decisions, skill.Model)
	}

	if w := postForm(t, s, path, url.Values{"decision": {db.ExperimentReject}}); w.Code != http.StatusSeeOther {
		t.Fatalf("reject status %d: %s", w.Code, w.Body)
	}
	s.DB.Model(&db.ExperimentDecision{}).Count(&decisions)
	if decisions != 1 {
		t.Errorf("decisions after an explicit reject = %d, want 1", decisions)
	}
}

// An ordinary scan launched with an experiment runs its own model and effort, and finalizing it leaves the skill's model alone until an adopt is recorded.
func TestExperimentLaunch_ordinaryScanKeepsItsConfigurationUntilAdopt(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	fx := seedExperimentFixture(t, s)
	ordinaryModel, trialModel := Models[0].ID, Models[len(Models)-1].ID
	if ordinaryModel == trialModel {
		t.Fatal("the test needs two configured models")
	}
	s.ScanExperiments["trial"] = config.ScanExperiment{Model: trialModel, Effort: "low"}
	skillModel := func() string {
		t.Helper()
		var skill db.Skill
		s.DB.Select("model").First(&skill, fx.findings.ID)
		return skill.Model
	}

	w := postForm(t, s, fmt.Sprintf("/repositories/%d/skill-scan", fx.repo.ID), url.Values{
		"skill_id": {strconv.FormatUint(uint64(fx.findings.ID), 10)}, "model": {ordinaryModel}, "experiment": {"trial"},
	})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("launch status %d: %s", w.Code, w.Body)
	}
	scans := skillScans(s)
	if len(scans) != 1 || scans[0].Model != ordinaryModel || scans[0].Effort != s.DefaultEffort() {
		t.Fatalf("scans = %+v, want one ordinary scan on %s with the default effort %s", scans, ordinaryModel, s.DefaultEffort())
	}

	s.DB.Model(&scans[0]).Updates(map[string]any{"status": db.ScanDone, "commit": "0123abcd"})
	baseline := reloadScan(t, s, scans[0].ID)
	s.onScanFinalized(&baseline)
	candidates := candidatesOf(t, s, baseline.ID)
	if len(candidates) != 1 || candidates[0].Model != trialModel || candidates[0].Effort != "low" {
		t.Fatalf("candidates = %+v, want one on %s with low effort", candidates, trialModel)
	}
	if got := skillModel(); got != "" {
		t.Fatalf("skill model after the candidate started = %q, want it unchanged", got)
	}

	if w := postForm(t, s, fmt.Sprintf("/scans/%d/experiment-decision", candidates[0].ID), url.Values{"decision": {db.ExperimentAdopt}}); w.Code != http.StatusSeeOther {
		t.Fatalf("adopt status %d: %s", w.Code, w.Body)
	}
	if got := skillModel(); got != trialModel {
		t.Errorf("skill model after adopt = %q, want %q", got, trialModel)
	}
}

// Missed by candidate, confirmed counts baseline-only observations whose repository finding is triaged as real, and reads unavailable before any triage.
func TestScanExperiment_missedByCandidateCountsRealBaselineOnlyFindings(t *testing.T) {
	for name, tc := range map[string]struct {
		shared, missed db.FindingLifecycle
		want           string
	}{
		"untriaged":        {db.FindingNew, db.FindingNew, "unavailable"},
		"enriched":         {db.FindingNew, db.FindingEnriched, "unavailable"},
		"missed ready":     {db.FindingNew, db.FindingReady, "1 of 1 triaged"},
		"missed rejected":  {db.FindingNew, db.FindingRejected, "0 of 1 triaged"},
		"missed duplicate": {db.FindingNew, db.FindingDuplicate, "0 of 1 triaged"},
		"shared ready":     {db.FindingReady, db.FindingNew, "0 of 1 triaged"},
	} {
		t.Run(name, func(t *testing.T) {
			s, done := newTestServer(t)
			defer done()
			baseline, _, _ := seedComparison(t, s)
			s.DB.Model(&db.Finding{}).Where("fingerprint = ?", "fp-shared").Update("status", tc.shared)
			s.DB.Model(&db.Finding{}).Where("fingerprint = ?", "fp-missed").Update("status", tc.missed)

			page := getRepoPagePath(t, s, fmt.Sprintf("/scans/%d/experiment", baseline.ID))
			if got := experimentMeasurement(t, page, "Missed by candidate, confirmed"); got != tc.want {
				t.Errorf("Missed by candidate, confirmed = %q, want %q", got, tc.want)
			}
		})
	}
}

// Cost, all candidate runs sums every candidate run including a retry and reads unavailable once one run is unpriced, and Cost, ordinary scan shows the baseline's cost or unavailable.
func TestScanExperiment_costMeasurements(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	baseline, candidate, _ := seedComparison(t, s)
	path := fmt.Sprintf("/scans/%d/experiment?candidate=%d", baseline.ID, candidate.ID)
	requireCosts := func(step, candidates, ordinary string) {
		t.Helper()
		page := getRepoPagePath(t, s, path)
		if got := experimentMeasurement(t, page, "Cost, all candidate runs"); got != candidates {
			t.Errorf("%s: Cost, all candidate runs = %q, want %q", step, got, candidates)
		}
		if got := experimentMeasurement(t, page, "Cost, ordinary scan"); got != ordinary {
			t.Errorf("%s: Cost, ordinary scan = %q, want %q", step, got, ordinary)
		}
	}
	requireCosts("no cost recorded", "unavailable", "unavailable")

	s.DB.Model(&candidate).Update("cost_usd", 1.25)
	s.DB.Model(&baseline).Update("cost_usd", 2.5)
	s.DB.Create(&db.Scan{RepositoryID: baseline.RepositoryID, Kind: worker.JobSkill, Status: db.ScanDone, SkillName: candidate.SkillName, CostUSD: 0.5,
		ParentScanID: &candidate.ID, Experiment: "trial", ExperimentConfig: baseline.ExperimentConfig, CandidateOfScanID: &baseline.ID})
	requireCosts("priced runs and a retry", "$1.75", "$2.50")

	s.DB.Create(&db.Scan{RepositoryID: baseline.RepositoryID, Kind: worker.JobSkill, Status: db.ScanFailed, SkillName: candidate.SkillName,
		InputTokens: 800, OutputTokens: 200, Experiment: "trial", ExperimentConfig: baseline.ExperimentConfig, CandidateOfScanID: &baseline.ID})
	requireCosts("an unpriced candidate run", "unavailable", "$2.50")

	s.DB.Model(&baseline).Updates(map[string]any{"cost_usd": 0, "input_tokens": 500})
	requireCosts("an unpriced baseline", "unavailable", "unavailable")
}

// The scans JSONL export carries each scan's experiment, configuration snapshot, staged inputs digest and baseline, and leaves them empty on an ordinary scan.
func TestExportScans_carriesExperimentColumns(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	baseline, candidate, _ := seedComparison(t, s)
	s.DB.Model(&db.Scan{}).Where("id IN ?", []uint{baseline.ID, candidate.ID}).Update("staged_inputs_sha256", experimentGuardStagedDigest)
	plain := db.Scan{RepositoryID: baseline.RepositoryID, Kind: worker.JobSkill, Status: db.ScanDone, SkillName: baseline.SkillName}
	s.DB.Create(&plain)

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq(http.MethodGet, "/api/v1/scans?repository_id="+strconv.FormatUint(uint64(baseline.RepositoryID), 10)))
	if w.Code != http.StatusOK {
		t.Fatalf("export status %d: %s", w.Code, w.Body)
	}
	rows := map[float64]map[string]any{}
	for _, row := range readJSONL(t, w.Body.String()) {
		rows[row["id"].(float64)] = row
	}
	for name, tc := range map[string]struct {
		id                 uint
		experiment, digest string
		snapshot           string
		candidateOf        any
	}{
		"baseline":  {baseline.ID, "trial", experimentGuardStagedDigest, baseline.ExperimentConfig, nil},
		"candidate": {candidate.ID, "trial", experimentGuardStagedDigest, baseline.ExperimentConfig, float64(baseline.ID)},
		"ordinary":  {plain.ID, "", "", "", nil},
	} {
		row := rows[float64(tc.id)]
		if row == nil {
			t.Errorf("%s scan missing from the export", name)
			continue
		}
		for key, want := range map[string]any{
			"experiment": tc.experiment, "experiment_config": tc.snapshot, "staged_inputs_sha256": tc.digest, "candidate_of_scan_id": tc.candidateOf,
		} {
			if got, ok := row[key]; !ok || got != want {
				t.Errorf("%s %s = %#v (present %v), want %#v", name, key, got, ok, want)
			}
		}
	}
}

// Retrying a refused candidate is a 422 while its model is unconfigured and enqueues one queued candidate once it is configured, never an ordinary scan.
func TestScanRetry_refusedCandidateRetriesAsACandidate(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	fx := seedExperimentFixture(t, s)
	baseline := finishedBaseline(t, s, fx)
	baseline.ExperimentConfig = experimentSnapshot(t, config.ScanExperiment{Model: "trial-model"})
	s.DB.Model(&baseline).Update("experiment_config", baseline.ExperimentConfig)
	s.onScanFinalized(&baseline)
	requireRefusedCandidate(t, s, baseline.ID, "trial-model")
	refused := candidatesOf(t, s, baseline.ID)[0]
	ordinaryScans := func() int64 {
		t.Helper()
		var n int64
		s.DB.Model(&db.Scan{}).Where("candidate_of_scan_id IS NULL").Count(&n)
		return n
	}
	ordinary := ordinaryScans()
	retryPath := fmt.Sprintf("/scans/%d/retry", refused.ID)

	w := postForm(t, s, retryPath, url.Values{})
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "trial-model") {
		t.Fatalf("retry status %d: %s, want 422 naming the model", w.Code, w.Body)
	}
	if got, n := candidatesOf(t, s, baseline.ID), ordinaryScans(); len(got) != 1 || n != ordinary {
		t.Fatalf("after a refused retry: %d candidates and %d ordinary scans, want 1 and %d", len(got), n, ordinary)
	}

	withTestModels(t, append(slices.Clone(Models), Model{Name: "Trial", ID: "trial-model"}))
	if w := postForm(t, s, retryPath, url.Values{}); w.Code != http.StatusSeeOther {
		t.Fatalf("retry with the model configured: status %d: %s", w.Code, w.Body)
	}
	got := candidatesOf(t, s, baseline.ID)
	if len(got) != 2 || got[1].Status != db.ScanQueued || got[1].Model != "trial-model" || got[1].Ref != baseline.Commit ||
		got[1].ParentScanID == nil || *got[1].ParentScanID != refused.ID {
		t.Fatalf("candidates = %+v, want a queued retry of #%d on trial-model pinned to %s", got, refused.ID, baseline.Commit)
	}
	if n := ordinaryScans(); n != ordinary {
		t.Errorf("ordinary scans = %d after the retry, want %d", n, ordinary)
	}
}

type experimentBaselineRunner struct {
	report string
	err    error
}

func (experimentBaselineRunner) SkillDir(root, name string) string {
	return filepath.Join(root, "skills", name)
}

func (r experimentBaselineRunner) RunSkill(context.Context, worker.SkillJob, func(worker.Event)) (worker.SkillResult, error) {
	return worker.SkillResult{Commit: "0123abcd", Report: r.report}, r.err
}

// runQueuedBaseline runs the queued scan through the worker with runner and returns its row once the worker has finished it.
func runQueuedBaseline(t *testing.T, s *Server, scanID uint, runner worker.SkillRunner) db.Scan {
	t.Helper()
	w := s.Worker
	w.Log, w.DataDir, w.Runner = s.Log, t.TempDir(), runner
	w.PrepareRepoSrc = func(_ context.Context, _, _, root string, _ func(worker.Event)) (string, error) {
		return "0123abcd", os.MkdirAll(filepath.Join(root, "src"), 0o755)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	onFinalized, onFailed := w.OnScanFinalized, w.OnScanFailed
	w.OnScanFinalized = func(scan *db.Scan) {
		onFinalized(scan)
		if scan.ID == scanID {
			cancel()
		}
	}
	w.OnScanFailed = func(scan *db.Scan) {
		onFailed(scan)
		if scan.ID == scanID {
			cancel()
		}
	}
	w.Register(s.Queue)
	s.Queue.Reconfigure(1)
	stopped := make(chan struct{})
	go func() { s.Queue.Start(ctx); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(10 * time.Second):
		t.Fatal("the baseline did not finish")
	}
	return reloadScan(t, s, scanID)
}

// A baseline whose run fails without tripping fail_on starts no candidate, while one failed by its fail_on threshold still finalizes and starts one.
func TestWorker_failedBaselineStartsACandidateOnlyOnFailOn(t *testing.T) {
	for name, tc := range map[string]struct {
		runner    experimentBaselineRunner
		candidate bool
	}{
		"runner error":      {experimentBaselineRunner{err: errExperimentGuardBaseline}, false},
		"fail_on threshold": {experimentBaselineRunner{report: experimentFailOnReport}, true},
	} {
		t.Run(name, func(t *testing.T) {
			s, done := newTestServer(t)
			defer done()
			fx := seedExperimentFixture(t, s)
			s.DB.Model(&fx.findings).Update("fail_on", "high")
			if w := postExperimentScan(s, fx.repo, fx.findings, "trial"); w.Code != http.StatusSeeOther {
				t.Fatalf("launch status %d: %s", w.Code, w.Body)
			}

			baseline := runQueuedBaseline(t, s, skillScans(s)[0].ID, tc.runner)
			if baseline.Status != db.ScanFailed {
				t.Fatalf("baseline status = %s (%s), want failed", baseline.Status, baseline.Error)
			}
			got := candidatesOf(t, s, baseline.ID)
			if !tc.candidate && len(got) != 0 {
				t.Fatalf("candidates = %+v, want none for a run that failed before recording findings", got)
			}
			if tc.candidate && (len(got) != 1 || got[0].Ref != "0123abcd" || got[0].SkillID == nil || *got[0].SkillID != fx.variant.ID) {
				t.Fatalf("candidates = %+v, want one run of the variant skill pinned to 0123abcd", got)
			}
		})
	}
}
