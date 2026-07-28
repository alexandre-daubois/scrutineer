package web

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"scrutineer/internal/db"
	"scrutineer/internal/worker"
)

// peerServer stands in for a federation peer's POST /claim-check.
func peerServer(t *testing.T, status int, body string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/claim-check" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func seedReadyFinding(t *testing.T, s *Server) db.Finding {
	t.Helper()
	repo := db.Repository{URL: "https://github.com/acme/lib", Name: "lib"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Kind: worker.JobSkill, Status: db.ScanDone, SkillName: "security-deep-dive"}
	s.DB.Create(&scan)
	f := db.Finding{
		ScanID: scan.ID, RepositoryID: repo.ID, Title: "sqli", Severity: "High",
		Status: db.FindingReady, CWE: "CWE-89", Location: "src/db.go:42",
	}
	s.DB.Create(&f)
	return f
}

func postFindingStatus(t *testing.T, s *Server, id uint, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	return postForm(t, s, "/findings/"+strconv.FormatUint(uint64(id), 10)+"/status", form)
}

func reloadFinding(t *testing.T, s *Server, id uint) db.Finding {
	t.Helper()
	var f db.Finding
	if err := s.DB.First(&f, id).Error; err != nil {
		t.Fatal(err)
	}
	return f
}

func TestValidatePeerURL(t *testing.T) {
	for _, ok := range []string{"https://peer.example.com", "http://127.0.0.1:8080", "https://peer.example.com/scrutineer"} {
		if err := ValidatePeerURL(ok); err != nil {
			t.Errorf("%q must be accepted: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"", "peer.example.com", "file:///etc/passwd", "ftp://peer.example.com", "https://",
		// Credentials would be sent on every click and logged when the peer
		// is down; a query or fragment would swallow the /claim-check path.
		"https://user:token@peer.example.com",
		"https://peer.example.com?tenant=1",
		"https://peer.example.com#frag",
	} {
		if err := ValidatePeerURL(bad); err == nil {
			t.Errorf("%q must be refused", bad)
		}
	}
}

func TestAskPeerClaim_appendsToThePeerPath(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"match":false}`))
	}))
	defer srv.Close()

	if _, _, err := askPeerClaim(t.Context(), srv.URL+"/scrutineer", strings.Repeat("ab", 32)); err != nil {
		t.Fatal(err)
	}
	if got != "/scrutineer/claim-check" {
		t.Errorf("posted to %q, want the endpoint appended to the peer's path", got)
	}
}

func TestPeerClaims(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		want   bool
	}{
		{"match", http.StatusOK, `{"match":true,"contact":"peer@example.com"}`, true},
		{"miss", http.StatusOK, `{"match":false}`, false},
		{"peer not federated", http.StatusNotFound, "not found", false},
		{"peer erroring", http.StatusInternalServerError, "boom", false},
		{"peer answering garbage", http.StatusOK, "{not json", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, done := newTestServer(t)
			defer done()
			s.FederationSalt = testFederationSalt
			s.FederationPeers = []string{peerServer(t, tc.status, tc.body)}
			f := seedReadyFinding(t, s)

			claims, err := s.peerClaims(t.Context(), f)
			if err != nil {
				t.Fatalf("a peer answering badly must not be a local error: %v", err)
			}
			if got := claims != ""; got != tc.want {
				t.Fatalf("peerClaims = %q, want a claim: %v", claims, tc.want)
			}
			if tc.want && claims != s.FederationPeers[0]+" (peer@example.com)" {
				t.Errorf("claim must name the peer and its contact, got %q", claims)
			}
		})
	}
}

func TestPeerClaims_dormantWithoutPeersOrSalt(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	f := seedReadyFinding(t, s)
	peer := peerServer(t, http.StatusOK, `{"match":true,"contact":"peer@example.com"}`)

	claims, err := s.peerClaims(t.Context(), f)
	if err != nil || claims != "" {
		t.Errorf("no peers configured must mean no claim, got %q / %v", claims, err)
	}
	s.FederationPeers = []string{peer}
	claims, err = s.peerClaims(t.Context(), f)
	if err != nil || claims != "" {
		t.Errorf("without the shared salt the hash cannot match, so no claim must be reported, got %q / %v", claims, err)
	}
}

// A local failure must not read as "nobody claims it": that would open the
// gate on exactly the runs where it could not be evaluated.
func TestPeerClaims_localFailureIsAnError(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.FederationSalt = testFederationSalt
	s.FederationPeers = []string{peerServer(t, http.StatusOK, `{"match":true,"contact":"peer@example.com"}`)}
	f := seedReadyFinding(t, s)
	f.RepositoryID = 999999

	if _, err := s.peerClaims(t.Context(), f); err == nil {
		t.Fatal("a repository that cannot be loaded must be reported as an error")
	}
}

func TestFindingStatus_claimGateFailureDoesNotReport(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.FederationSalt = testFederationSalt
	s.FederationPeers = []string{peerServer(t, http.StatusOK, `{"match":false}`)}
	f := seedReadyFinding(t, s)
	// A finding pointing at a repository row that cannot be read cannot be
	// hashed, so the gate must refuse rather than let the transition through
	// unchecked. Repointing rather than deleting: the repository cascade
	// would take the finding with it.
	if err := s.DB.Model(&db.Finding{}).Where("id = ?", f.ID).
		Update("repository_id", 999999).Error; err != nil {
		t.Fatal(err)
	}

	if w := postFindingStatus(t, s, f.ID, url.Values{statusKey: {"reported"}}); w.Code != http.StatusInternalServerError {
		t.Fatalf("status %d, want 500. body=%s", w.Code, w.Body)
	}
	if got := reloadFinding(t, s, f.ID); got.Status != db.FindingReady {
		t.Fatalf("status = %q, want ready", got.Status)
	}
}

func TestFindingStatus_peerClaimBlocksReported(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.FederationSalt = testFederationSalt
	peer := peerServer(t, http.StatusOK, `{"match":true,"contact":"peer@example.com"}`)
	s.FederationPeers = []string{peer}
	f := seedReadyFinding(t, s)

	if w := postFindingStatus(t, s, f.ID, url.Values{statusKey: {"reported"}}); w.Code >= 400 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	blocked := reloadFinding(t, s, f.ID)
	if blocked.Status != db.FindingReady {
		t.Fatalf("a claimed finding must stay ready, got %q", blocked.Status)
	}
	if blocked.FederationClaimContacts == "" || blocked.FederationClaimAt == nil {
		t.Fatalf("the claim must be recorded for the banner: %q / %v", blocked.FederationClaimContacts, blocked.FederationClaimAt)
	}

	// The finding page names the contact to coordinate through.
	page := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/findings/"+strconv.FormatUint(uint64(f.ID), 10), nil)
	req.Host = testHost
	s.Handler().ServeHTTP(page, req)
	if !strings.Contains(page.Body.String(), "peer@example.com") {
		t.Error("the finding page must surface the peer contact")
	}

	// The recorded claim is the acknowledgement: a second submit goes
	// through, no extra form field needed.
	if w := postFindingStatus(t, s, f.ID, url.Values{statusKey: {"reported"}}); w.Code >= 400 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	acked := reloadFinding(t, s, f.ID)
	if acked.Status != db.FindingReported {
		t.Fatalf("acknowledging the claim must let the transition through, got %q", acked.Status)
	}
	if acked.FederationClaimContacts != "" || acked.FederationClaimAt != nil {
		t.Errorf("a completed transition must clear the claim: %q / %v", acked.FederationClaimContacts, acked.FederationClaimAt)
	}
}

// A peer must not be able to aim this instance's own POST at its loopback
// admin API by answering the claim-check with a redirect.
func TestAskPeerClaim_doesNotFollowRedirects(t *testing.T) {
	var reached string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = r.URL.Path
	}))
	defer target.Close()
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/repositories/1/delete", http.StatusTemporaryRedirect)
	}))
	defer peer.Close()

	_, matched, err := askPeerClaim(t.Context(), peer.URL, strings.Repeat("ab", 32))
	if err == nil {
		t.Fatal("a redirected claim-check must be reported as an error, not followed")
	}
	if matched {
		t.Error("a redirect must never read as a match")
	}
	if reached != "" {
		t.Fatalf("the redirect was followed to %q", reached)
	}
}

// report-upstream files with the maintainer and only then PATCHes the
// status, so the gate has to sit at enqueue: refusing the later write would
// leave the outreach done and the finding stuck.
func TestEnqueueOutreachSkill_refusedWhileAPeerHoldsTheFinding(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.FederationSalt = testFederationSalt
	s.FederationPeers = []string{peerServer(t, http.StatusOK, `{"match":true,"contact":"peer@example.com"}`)}
	f := seedReadyFinding(t, s)
	skill := db.Skill{Name: "report-upstream", Active: true}
	s.DB.Create(&skill)

	_, err := s.enqueueSkillScoped(t.Context(), f.RepositoryID, skill.ID, &f.ID, "")
	if !errors.Is(err, ErrFederationClaimPending) {
		t.Fatalf("expected ErrFederationClaimPending, got %v", err)
	}
	var scans int64
	s.DB.Model(&db.Scan{}).Where("skill_id = ?", skill.ID).Count(&scans)
	if scans != 0 {
		t.Fatalf("a refused enqueue must create no scan row, got %d", scans)
	}
	held := reloadFinding(t, s, f.ID)
	if held.FederationClaimContacts == "" {
		t.Fatal("the claim must be recorded so the page names the contact")
	}

	// Recorded claim = acknowledged, so running it again goes through.
	if _, err := s.enqueueSkillScoped(t.Context(), f.RepositoryID, skill.ID, &f.ID, ""); err != nil {
		t.Fatalf("second attempt must proceed: %v", err)
	}
}

func TestEnqueueNonOutreachSkill_neverConsultsPeers(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.FederationSalt = testFederationSalt
	s.FederationPeers = []string{peerServer(t, http.StatusOK, `{"match":true,"contact":"peer@example.com"}`)}
	f := seedReadyFinding(t, s)
	skill := db.Skill{Name: "verify", Active: true}
	s.DB.Create(&skill)

	if _, err := s.enqueueSkillScoped(t.Context(), f.RepositoryID, skill.ID, &f.ID, ""); err != nil {
		t.Fatalf("a skill that contacts nobody must not be gated: %v", err)
	}
	if got := reloadFinding(t, s, f.ID); got.FederationClaimContacts != "" {
		t.Errorf("no claim should have been recorded, got %q", got.FederationClaimContacts)
	}
}

func TestFindingStatus_unclaimedFindingReportsNormally(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.FederationSalt = testFederationSalt
	s.FederationPeers = []string{peerServer(t, http.StatusOK, `{"match":false}`)}
	f := seedReadyFinding(t, s)

	if w := postFindingStatus(t, s, f.ID, url.Values{statusKey: {"reported"}}); w.Code >= 400 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if got := reloadFinding(t, s, f.ID); got.Status != db.FindingReported {
		t.Fatalf("status = %q, want reported", got.Status)
	}
}

func TestFindingStatus_gateOnlyAppliesToReported(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.FederationSalt = testFederationSalt
	// A peer that would claim anything: other transitions must not consult
	// it at all, so they go through regardless.
	s.FederationPeers = []string{peerServer(t, http.StatusOK, `{"match":true,"contact":"peer@example.com"}`)}
	f := seedReadyFinding(t, s)

	if w := postFindingStatus(t, s, f.ID, url.Values{statusKey: {"rejected"}}); w.Code >= 400 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if got := reloadFinding(t, s, f.ID); got.Status != db.FindingRejected {
		t.Fatalf("status = %q, want rejected", got.Status)
	}
}
