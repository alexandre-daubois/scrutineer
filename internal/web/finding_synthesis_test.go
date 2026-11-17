package web

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"scrutineer/internal/db"
)

func seedSynthesis(t *testing.T, s *Server, f db.Finding) {
	t.Helper()
	var obs []db.FindingObservation
	if err := s.DB.Where("finding_id = ?", f.ID).Order("id").Find(&obs).Error; err != nil || len(obs) != 2 {
		t.Fatalf("observations = %d err=%v", len(obs), err)
	}
	synth := db.Scan{RepositoryID: f.RepositoryID, Kind: "skill", Status: db.ScanDone, SkillName: synthesizeSkillName, FindingID: &f.ID}
	if err := s.DB.Create(&synth).Error; err != nil {
		t.Fatal(err)
	}
	report := `{"summary":"Both describe one injection.","claims":[{"statement":"Input reaches the query <img src=x onerror=alert(1)>","sources":["R1","R2"]}],` +
		`"disagreements":[{"field":"severity","positions":[{"source":"R1","value":"High"},{"source":"R2","value":"Low"}]}],"unused":[]}`
	if err := db.RecordFindingSynthesis(s.DB, &db.FindingSynthesis{FindingID: f.ID, ScanID: synth.ID, RepositoryID: f.RepositoryID,
		Report: report, Sources: fmt.Sprintf(`{"R1":%d,"R2":%d}`, obs[0].ID, obs[1].ID)}); err != nil {
		t.Fatal(err)
	}
}

func TestFindingShowRendersSynthesisWithReviewersAttached(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	f := seedObservedFinding(t, s)
	seedSynthesis(t, s, f)

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq(http.MethodGet, fmt.Sprintf("/findings/%d", f.ID)))
	if w.Code != http.StatusOK {
		t.Fatalf("GET status = %d: %s", w.Code, w.Body)
	}
	body := w.Body.String()
	_, section, ok := strings.Cut(body, "A synthesis is not verification")
	if !ok {
		t.Fatal("synthesis section missing")
	}
	for _, want := range []string{"Both describe one injection.", "R1", "R2", "claude-code · model-a", "codex · model-b", "Disagreement"} {
		if !strings.Contains(section, want) {
			t.Errorf("synthesis section missing %q", want)
		}
	}
	if strings.Contains(body, "<img src=x onerror=alert(1)>") || !strings.Contains(section, "&lt;img src=x onerror=alert(1)&gt;") {
		t.Error("synthesis claim was not escaped")
	}
}

func TestFindingShowOffersSynthesisOnlyWithTwoObservations(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	f := seedObservedFinding(t, s)
	action := fmt.Sprintf(`action="/findings/%d/synthesize"`, f.ID)
	get := func() string {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, localReq(http.MethodGet, fmt.Sprintf("/findings/%d", f.ID)))
		return w.Body.String()
	}
	if body := get(); !strings.Contains(body, action) || strings.Contains(body, "A synthesis is not verification") {
		t.Fatal("two observations: want the synthesize button and no synthesis section")
	}
	if err := s.DB.Where("finding_id = ? AND severity = ?", f.ID, "Low").Delete(&db.FindingObservation{}).Error; err != nil {
		t.Fatal(err)
	}
	if strings.Contains(get(), action) {
		t.Fatal("one observation still offers synthesis")
	}
}

func TestFindingSynthesizeEnqueuesFindingScopedScan(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	f := seedObservedFinding(t, s)
	path := fmt.Sprintf("/findings/%d/synthesize", f.ID)
	if w := postForm(t, s, path, url.Values{}); w.Code != http.StatusPreconditionFailed {
		t.Fatalf("without the skill: status %d, want 412", w.Code)
	}
	if err := s.DB.Create(&db.Skill{Name: synthesizeSkillName, Body: "x", OutputKind: "synthesis", Active: true}).Error; err != nil {
		t.Fatal(err)
	}
	if w := postForm(t, s, path, url.Values{}); w.Code != http.StatusSeeOther {
		t.Fatalf("enqueue: %d %s", w.Code, w.Body)
	}
	var scan db.Scan
	if err := s.DB.Where("finding_id = ? AND skill_name = ? AND status = ?", f.ID, synthesizeSkillName, db.ScanQueued).First(&scan).Error; err != nil {
		t.Fatal(err)
	}
	postForm(t, s, path, url.Values{})
	assertQueuedJobCount(t, s, 1)
}
