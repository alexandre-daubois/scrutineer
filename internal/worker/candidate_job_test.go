package worker

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"scrutineer/internal/db"
	"scrutineer/internal/queue"
)

const (
	candidateJobThreatModel = "Attackers reach the public API."
	candidateJobScanConfig  = "attack_surface: public API"
)

type candidateJob struct {
	w                   *Worker
	repo                db.Repository
	baseline, candidate *db.Scan
	hooks               map[string]int
}

// newCandidateJob queues a candidate whose commit, scan config and staged
// threat model all match its baseline, with every follow-up hook counted.
func newCandidateJob(t *testing.T, runner fakeRunner) *candidateJob {
	t.Helper()
	w, repo := observationWorker(t)
	repo.ThreatModel, repo.ScanConfig = candidateJobThreatModel, candidateJobScanConfig
	if err := w.DB.Save(&repo).Error; err != nil {
		t.Fatal(err)
	}
	skill := db.Skill{Name: "deep-dive-v2", Description: "d", Body: "b", OutputFile: "report.json",
		OutputKind: "findings", FailOn: "low", Version: 1, Active: true, Source: "ui"}
	if err := w.DB.Create(&skill).Error; err != nil {
		t.Fatal(err)
	}
	baseline, candidate := candidatePair(t, w, repo)
	recipe, err := buildScanRecipe(baseline, "", repo.ThreatModel, repo.ScanConfig)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.DB.Model(baseline).Updates(map[string]any{
		"recipe": recipe, "staged_inputs_sha256": stagedDigest(t, repo.ThreatModel),
	}).Error; err != nil {
		t.Fatal(err)
	}
	if err := w.DB.Model(candidate).Updates(map[string]any{
		"status": db.ScanQueued, "skill_id": skill.ID, "scan_group": "grp",
	}).Error; err != nil {
		t.Fatal(err)
	}

	j := &candidateJob{w: w, repo: repo, baseline: baseline, candidate: candidate, hooks: map[string]int{}}
	w.DataDir = t.TempDir()
	w.Runner = runner
	w.PrepareRepoSrc = stubPrepareRepoSrc
	w.OnFindingCreated = func(*db.Scan, *db.Finding) { j.hooks["created"]++ }
	w.OnScanFinalized = func(*db.Scan) { j.hooks["finalized"]++ }
	w.OnScanFailed = func(*db.Scan) { j.hooks["failed"]++ }
	w.OnScanGroupSettled = func(*db.Scan) { j.hooks["settled"]++ }
	return j
}

func (j *candidateJob) run(t *testing.T, scanID uint) db.Scan {
	t.Helper()
	body, _ := json.Marshal(queue.Payload{ScanID: scanID})
	if err := j.w.wrap(j.w.doSkill)(t.Context(), body); err != nil {
		t.Fatal(err)
	}
	var got db.Scan
	if err := j.w.DB.First(&got, scanID).Error; err != nil {
		t.Fatal(err)
	}
	return got
}

// A candidate run through the job path records both reported vulnerabilities
// as candidate observations, ignores fail_on and leaves findings and hooks alone.
func TestCandidateJob_recordsObservationsWithoutTouchingFindings(t *testing.T) {
	j := newCandidateJob(t, fakeRunner{skillRes: SkillResult{Commit: "abc", Report: candidateReport}})
	if err := j.w.parseFindingsOutput(&db.Skill{}, j.baseline,
		`{"findings":[{"id":"F1","title":"SQLi","severity":"High","cwe":"CWE-89","location":"a.rb:1"}]}`, func(Event) {}); err != nil {
		t.Fatal(err)
	}
	var before db.Finding
	if err := j.w.DB.First(&before).Error; err != nil {
		t.Fatal(err)
	}
	clear(j.hooks)

	got := j.run(t, j.candidate.ID)

	if got.Status != db.ScanDone {
		t.Fatalf("candidate status = %s (%q), want done", got.Status, got.Error)
	}
	obs := candidateObservations(t, j.w, j.candidate.ID)
	if len(obs) != 2 {
		t.Fatalf("candidate observations = %d, want 2", len(obs))
	}
	if obs[0].Fingerprint != before.Fingerprint || obs[1].Title != "Path traversal" {
		t.Errorf("observations = %+v, want the existing finding's fingerprint then the new vulnerability", obs)
	}
	var findings []db.Finding
	if err := j.w.DB.Find(&findings).Error; err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].SeenCount != before.SeenCount || findings[0].LastSeenScanID != before.LastSeenScanID ||
		findings[0].MissedCount != before.MissedCount || findings[0].Status != before.Status {
		t.Errorf("findings after candidate = %+v, want the baseline row unchanged", findings)
	}
	var candidateRows int64
	if err := j.w.DB.Model(&db.FindingObservation{}).Where("scan_id = ?", j.candidate.ID).Count(&candidateRows).Error; err != nil {
		t.Fatal(err)
	}
	if candidateRows != 0 {
		t.Errorf("finding observations for the candidate = %d, want 0", candidateRows)
	}
	if len(j.hooks) != 0 {
		t.Errorf("hooks fired for a candidate: %v", j.hooks)
	}
}

// A candidate whose inputs differ from its baseline's fails before the run and
// records nothing.
func TestCandidateJob_mismatchedInputsFail(t *testing.T) {
	for _, tc := range []struct {
		name    string
		diverge func(t *testing.T, j *candidateJob)
		want    string
	}{
		{"other commit", func(t *testing.T, j *candidateJob) {
			if err := j.w.DB.Model(j.baseline).Update("commit", "def").Error; err != nil {
				t.Fatal(err)
			}
		}, `candidate source commit "abc" differs`},
		{"edited scan config", func(t *testing.T, j *candidateJob) {
			if err := j.w.DB.Model(&db.Repository{}).Where("id = ?", j.repo.ID).Update("scan_config", "attack_surface: admin panel").Error; err != nil {
				t.Fatal(err)
			}
		}, "scan config, threat model or analyst feedback staged for this candidate differs"},
		{"other scope", func(t *testing.T, j *candidateJob) {
			if err := j.w.DB.Model(j.baseline).Update("sub_path", "pkg").Error; err != nil {
				t.Fatal(err)
			}
		}, "candidate scope"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			j := newCandidateJob(t, fakeRunner{skillRes: SkillResult{Commit: "abc", Report: candidateReport}})
			tc.diverge(t, j)

			got := j.run(t, j.candidate.ID)

			if got.Status != db.ScanFailed || !strings.Contains(got.Error, tc.want) {
				t.Fatalf("candidate = %s %q, want failed with %q", got.Status, got.Error, tc.want)
			}
			if obs := candidateObservations(t, j.w, j.candidate.ID); len(obs) != 0 {
				t.Errorf("candidate observations = %+v, want none", obs)
			}
			if len(j.hooks) != 0 {
				t.Errorf("hooks fired for a failed candidate: %v", j.hooks)
			}
		})
	}
}

// A hard-scoped candidate that hits a dependency resolution failure keeps its
// hard scope, while an ordinary scan in the same situation widens to soft.
func TestCandidateJob_hardScopeIsNotWidened(t *testing.T) {
	runner := fakeRunner{skillRes: SkillResult{Commit: "abc"}, skillErr: errors.New("npm ERR! ERESOLVE unable to resolve dependency tree")}
	for _, tc := range []struct {
		name      string
		candidate bool
		wantScope string
	}{
		{"candidate", true, "hard"},
		{"ordinary scan", false, "soft"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			j := newCandidateJob(t, runner)
			j.w.PrepareRepoSrc = func(ctx context.Context, url, ref, workRoot string, emit func(Event)) (string, error) {
				commit, err := stubPrepareRepoSrc(ctx, url, ref, workRoot, emit)
				if err != nil {
					return "", err
				}
				return commit, os.MkdirAll(filepath.Join(workRoot, "src", "pkg"), 0o755)
			}
			scan := j.candidate
			if !tc.candidate {
				scan = &db.Scan{RepositoryID: j.repo.ID, Kind: JobSkill, Status: db.ScanQueued, SkillID: j.candidate.SkillID}
				if err := j.w.DB.Create(scan).Error; err != nil {
					t.Fatal(err)
				}
			}
			if tc.candidate {
				if err := j.w.DB.Model(j.baseline).Updates(map[string]any{"sub_path": "pkg", "scope_mode": "hard"}).Error; err != nil {
					t.Fatal(err)
				}
			}
			if err := j.w.DB.Model(scan).Updates(map[string]any{"sub_path": "pkg", "scope_mode": "hard"}).Error; err != nil {
				t.Fatal(err)
			}

			got := j.run(t, scan.ID)

			if got.Status != db.ScanFailed || !strings.Contains(got.Error, "ERESOLVE") {
				t.Fatalf("status = %s %q, want failed with the resolution error", got.Status, got.Error)
			}
			if got.ScopeMode != tc.wantScope {
				t.Errorf("scope_mode = %q, want %q", got.ScopeMode, tc.wantScope)
			}
		})
	}
}

func stagedDigest(t *testing.T, model string) string {
	t.Helper()
	digest, err := stagedInputsDigest(candidateJobScanConfig, model, nil)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}
