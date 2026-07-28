package web

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"scrutineer/internal/db"
)

func seedOptOutRepo(t *testing.T, s *Server, optedOut bool) db.Repository {
	t.Helper()
	repo := db.Repository{URL: "https://github.com/acme/lib", Name: "lib"}
	if optedOut {
		at := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
		repo.FederationOptOutAt = &at
	}
	if err := s.DB.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	return repo
}

func TestEnqueueSkill_refusedForOptedOutRepository(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := seedOptOutRepo(t, s, true)
	skill := db.Skill{Name: "security-deep-dive", Active: true}
	s.DB.Create(&skill)

	if _, err := s.enqueueSkill(context.Background(), repo.ID, skill.ID, ""); !errors.Is(err, ErrRepoFederationOptOut) {
		t.Fatalf("expected ErrRepoFederationOptOut, got %v", err)
	}
	var scans int64
	s.DB.Model(&db.Scan{}).Count(&scans)
	if scans != 0 {
		t.Fatalf("a refused enqueue must create no scan row, got %d", scans)
	}
}

func TestEnqueueSkill_allowedWhenNotOptedOut(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := seedOptOutRepo(t, s, false)
	skill := db.Skill{Name: "security-deep-dive", Active: true}
	s.DB.Create(&skill)

	if _, err := s.enqueueSkill(context.Background(), repo.ID, skill.ID, ""); err != nil {
		t.Fatalf("a repository that did not opt out must still be scannable: %v", err)
	}
}

// The scheduler has to refuse before it makes any network call: the upstream
// sync is a force-push to the maintainer's host, which is the other half of
// what the opt-out asks us not to do.
func TestRunScheduledScan_skipsOptedOutRepositoryBeforeAnyNetworkCall(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := seedOptOutRepo(t, s, true)
	// A bogus upstream: reaching syncUpstream at all would try to talk to it,
	// so the skip reason proves the check fired first.
	s.DB.Model(&db.Repository{}).Where("id = ?", repo.ID).
		Update("upstream_url", "https://127.0.0.1:1/never/reached.git")

	s.runScheduledScan(context.Background(), db.Repository{
		ID: repo.ID, Name: repo.Name, URL: repo.URL,
		UpstreamURL:        "https://127.0.0.1:1/never/reached.git",
		FederationOptOutAt: repo.FederationOptOutAt,
	})

	var skip db.Scan
	if err := s.DB.Where("repository_id = ?", repo.ID).Order("id desc").First(&skip).Error; err != nil {
		t.Fatal(err)
	}
	if skip.Status != db.ScanSkipped || skip.Kind != scheduleKind {
		t.Fatalf("expected a scheduled skip row, got kind %q status %q", skip.Kind, skip.Status)
	}
	if skip.Error != "maintainer opted out of federated scanning" {
		t.Errorf("skip reason = %q; the opt-out must be why, not a network failure", skip.Error)
	}
}

func TestRepoFederationOptOut_setEditAndClear(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := seedOptOutRepo(t, s, false)
	path := "/repositories/" + strconv.FormatUint(uint64(repo.ID), 10) + "/federation-opt-out"
	reload := func() db.Repository {
		t.Helper()
		var got db.Repository
		if err := s.DB.First(&got, repo.ID).Error; err != nil {
			t.Fatal(err)
		}
		return got
	}

	if w := postForm(t, s, path, url.Values{"opt_out": {"1"}, "reason": {"maintainer asked"}}); w.Code >= 400 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	set := reload()
	if set.FederationOptOutAt == nil || set.FederationOptOutReason != "maintainer asked" {
		t.Fatalf("opt-out not recorded: %v / %q", set.FederationOptOutAt, set.FederationOptOutReason)
	}
	requested := *set.FederationOptOutAt

	if w := postForm(t, s, path, url.Values{"opt_out": {"1"}, "reason": {"they repeated it"}}); w.Code >= 400 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	edited := reload()
	if !edited.FederationOptOutAt.Equal(requested) {
		t.Errorf("editing the reason must keep the original request date, got %v want %v", edited.FederationOptOutAt, requested)
	}
	if edited.FederationOptOutReason != "they repeated it" {
		t.Errorf("reason = %q", edited.FederationOptOutReason)
	}

	if w := postForm(t, s, path, url.Values{"reason": {"ignored"}}); w.Code >= 400 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	cleared := reload()
	if cleared.FederationOptOutAt != nil || cleared.FederationOptOutReason != "" {
		t.Fatalf("clearing must drop both columns: %v / %q", cleared.FederationOptOutAt, cleared.FederationOptOutReason)
	}
}

// A policy refusal must be distinguishable from a server fault on the API,
// or a skill's retry logic hammers the endpoint instead of stopping.
func TestAPIRunSkill_optedOutRepositoryAnswers409(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo, scan := seedRunningScan(t, s)
	at := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	if err := s.DB.Model(&db.Repository{}).Where("id = ?", repo.ID).
		Update("federation_opt_out_at", &at).Error; err != nil {
		t.Fatal(err)
	}
	s.DB.Create(&db.Skill{Name: "metadata", Description: "m", Body: "b", OutputFile: "report.json", Version: 1, Active: true, Source: "ui"})

	r := httptest.NewRequest("POST", "/api/repositories/"+strconv.FormatUint(uint64(repo.ID), 10)+"/skills/metadata/run", nil)
	r.Host = testHost
	r.Header.Set("Authorization", "Bearer "+scan.APIToken)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusConflict {
		t.Fatalf("status %d, want 409. body=%s", w.Code, w.Body)
	}
}
