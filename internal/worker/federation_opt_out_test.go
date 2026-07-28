package worker

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"scrutineer/internal/db"
	"scrutineer/internal/queue"
)

// mustNotRunRunner fails the test if the skill is dispatched at all, which is
// the whole point of the opt-out gate: the report is not the concern, reading
// the maintainer's code is.
type mustNotRunRunner struct{ t *testing.T }

func (m mustNotRunRunner) RunSkill(context.Context, SkillJob, func(Event)) (SkillResult, error) {
	m.t.Error("the runner must not be reached for an opted-out repository")
	return SkillResult{}, nil
}

func (mustNotRunRunner) SkillDir(workRoot, name string) string {
	return ClaudeHarness{}.SkillDir(workRoot, name)
}

func newOptOutWorker(t *testing.T, optedOut bool) (*Worker, db.Scan) {
	t.Helper()
	gdb, err := db.Open(filepath.Join(t.TempDir(), "optout.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://example.com/x", Name: "x"}
	if optedOut {
		at := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
		repo.FederationOptOutAt = &at
	}
	gdb.Create(&repo)
	skill := db.Skill{Name: "metadata", Description: "x", Body: "b", Active: true, Source: "ui", Version: 1}
	gdb.Create(&skill)
	scan := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanQueued, SkillID: &skill.ID}
	gdb.Create(&scan)
	return &Worker{
		DB:             gdb,
		Log:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		DataDir:        t.TempDir(),
		Runner:         mustNotRunRunner{t: t},
		PrepareRepoSrc: stubPrepareRepoSrc,
	}, scan
}

// A scan enqueued before the maintainer opted out is already on the queue when
// the opt-out lands, so the enqueue gate cannot catch it; dispatch must.
func TestWrap_cancelsJobForOptedOutRepository(t *testing.T) {
	w, scan := newOptOutWorker(t, true)
	body, _ := json.Marshal(queue.Payload{ScanID: scan.ID})
	if err := w.wrap(w.doSkill)(context.Background(), body); err != nil {
		t.Fatalf("wrap: %v", err)
	}

	var got db.Scan
	w.DB.First(&got, scan.ID)
	if got.Status != db.ScanCancelled {
		t.Errorf("status = %s, want cancelled", got.Status)
	}
	if got.Error != OptOutCancelReason {
		t.Errorf("error = %q, want %q", got.Error, OptOutCancelReason)
	}
	if got.FinishedAt == nil {
		t.Error("a cancelled scan must be terminal, got no finished_at")
	}
	if got.StartedAt != nil {
		t.Error("the gate must refuse before the scan is marked running")
	}
}

func TestWrap_dispatchesWhenNotOptedOut(t *testing.T) {
	w, scan := newOptOutWorker(t, false)
	w.Runner = fakeRunner{skillRes: SkillResult{Report: `{"ok":true}`}}
	body, _ := json.Marshal(queue.Payload{ScanID: scan.ID})
	if err := w.wrap(w.doSkill)(context.Background(), body); err != nil {
		t.Fatalf("wrap: %v", err)
	}

	var got db.Scan
	w.DB.First(&got, scan.ID)
	if got.Status != db.ScanDone {
		t.Fatalf("status = %s (%s), want done", got.Status, got.Error)
	}
}
