package worker

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"scrutineer/internal/db"
)

type streamThenFailRunner struct {
	w *Worker
}

func (r streamThenFailRunner) RunSkill(_ context.Context, sj SkillJob, _ func(Event)) (SkillResult, error) {
	var scan db.Scan
	if err := r.w.DB.First(&scan, sj.ScanID).Error; err != nil {
		return SkillResult{}, err
	}
	if _, err := r.w.PersistStreamedFinding(&scan, []byte(`{"id":"F1","title":"SQLi","severity":"High","cwe":"CWE-89","location":"a.rb:1","trace":"User input reaches the query unescaped."}`)); err != nil {
		return SkillResult{}, err
	}
	return SkillResult{Commit: "abc"}, errors.New("agent exited mid-run")
}

func (streamThenFailRunner) SkillDir(workRoot, name string) string {
	return ClaudeHarness{}.SkillDir(workRoot, name)
}

// A candidate whose skill runs on the host fails before any agent starts, while
// a split runner sending only another skill to the host runs it in its container.
func TestCandidateRunner_hostExecutionFailsBeforeTheAgentStarts(t *testing.T) {
	for _, tc := range []struct {
		name          string
		runner        func(container SkillRunner) SkillRunner
		wantStatus    db.ScanStatus
		wantError     string
		wantContainer bool
	}{
		{"local runner", func(SkillRunner) SkillRunner { return LocalClaude{} }, db.ScanFailed, "requires a container runner", false},
		{"split runner naming the candidate skill", func(c SkillRunner) SkillRunner {
			return HostSplitRunner{Container: c, Host: LocalClaude{}, HostSkills: []string{"deep-dive-v2"}}
		}, db.ScanFailed, "requires a container runner", false},
		{"split runner naming another skill", func(c SkillRunner) SkillRunner {
			return HostSplitRunner{Container: c, Host: LocalClaude{}, HostSkills: []string{"verify"}}
		}, db.ScanDone, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bin := t.TempDir()
			marker := filepath.Join(bin, "claude-ran")
			writeFakeBin(t, bin, "claude", "#!/bin/sh\ntouch \"$CANDIDATE_HOST_MARKER\"\n")
			t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
			t.Setenv("CANDIDATE_HOST_MARKER", marker)
			t.Setenv("HOME", t.TempDir())
			t.Setenv("CLAUDE_CONFIG_DIR", t.TempDir())
			j := newCandidateJob(t, fakeRunner{})
			container := &recordingRunner{res: SkillResult{Commit: "abc", Report: candidateReport}}
			j.w.Runner = tc.runner(container)

			got := j.run(t, j.candidate.ID)

			if got.Status != tc.wantStatus || !strings.Contains(got.Error, tc.wantError) {
				t.Errorf("candidate = %s %q, want %s with %q", got.Status, got.Error, tc.wantStatus, tc.wantError)
			}
			if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("host claude ran for a candidate (marker stat err = %v)", err)
			}
			if ran := container.got.ScanID == j.candidate.ID; ran != tc.wantContainer {
				t.Errorf("container runner ran = %v, want %v", ran, tc.wantContainer)
			}
			if obs := candidateObservations(t, j.w, j.candidate.ID); (len(obs) == 2) != tc.wantContainer {
				t.Errorf("candidate observations = %d, want 2 only when the container ran", len(obs))
			}
		})
	}
}

// An ordinary scan tied to an experiment records the digest of the scan config
// and threat model it staged, and one outside any experiment records none.
func TestCandidateRunner_baselineRunPinsItsStagedInputs(t *testing.T) {
	for _, tc := range []struct {
		name       string
		experiment string
		wantDigest func(t *testing.T) string
	}{
		{"baseline in an experiment", "trial", func(t *testing.T) string { return stagedDigest(t, candidateJobThreatModel) }},
		{"scan outside any experiment", "", func(*testing.T) string { return "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			j := newCandidateJob(t, fakeRunner{skillRes: SkillResult{Commit: "abc", Report: `{"findings":[]}`}})
			if err := j.w.DB.Model(&db.Skill{}).Where("id = ?", *j.candidate.SkillID).Update("fail_on", "").Error; err != nil {
				t.Fatal(err)
			}
			scan := &db.Scan{RepositoryID: j.repo.ID, Kind: JobSkill, Status: db.ScanQueued, SkillID: j.candidate.SkillID,
				Model: "model-a", Experiment: tc.experiment}
			if err := j.w.DB.Create(scan).Error; err != nil {
				t.Fatal(err)
			}

			got := j.run(t, scan.ID)

			if got.Status != db.ScanDone {
				t.Fatalf("scan status = %s (%q), want done", got.Status, got.Error)
			}
			if want := tc.wantDigest(t); got.StagedInputsSHA256 != want {
				t.Errorf("staged_inputs_sha256 = %q, want %q", got.StagedInputsSHA256, want)
			}
		})
	}
}

// A candidate whose agent fails after streaming a finding ends failed with the
// streamed candidate observation kept, no finding written and no hook fired.
func TestCandidateRunner_streamedFindingSurvivesAFailedRun(t *testing.T) {
	j := newCandidateJob(t, fakeRunner{})
	j.w.Runner = streamThenFailRunner{w: j.w}

	got := j.run(t, j.candidate.ID)

	if got.Status != db.ScanFailed || !strings.Contains(got.Error, "agent exited mid-run") {
		t.Fatalf("candidate = %s %q, want failed with the runner error", got.Status, got.Error)
	}
	if obs := candidateObservations(t, j.w, j.candidate.ID); len(obs) != 1 || obs[0].Title != "SQLi" || obs[0].ReportFindingID != "F1" {
		t.Errorf("candidate observations = %+v, want the streamed SQLi", obs)
	}
	var findings int64
	if err := j.w.DB.Model(&db.Finding{}).Count(&findings).Error; err != nil {
		t.Fatal(err)
	}
	if findings != 0 {
		t.Errorf("findings = %d, want 0", findings)
	}
	if len(j.hooks) != 0 {
		t.Errorf("hooks fired for a failed candidate: %v", j.hooks)
	}
}
