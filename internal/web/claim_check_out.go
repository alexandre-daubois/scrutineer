package web

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"scrutineer/internal/db"
	"scrutineer/internal/interchange"
)

// peerClaimTimeout bounds the whole outbound claim-check round, peers
// queried in sequence. It stays short because it sits inside an analyst's
// click: an unreachable peer must not hold up marking a finding reported.
const peerClaimTimeout = 5 * time.Second

// peerClaimMaxBody bounds a peer's response. The payload is a boolean and
// a contact string, so anything larger is a misconfigured endpoint.
const peerClaimMaxBody = 4096

// peerClaimClient refuses to follow redirects. A claim-check answer is a
// boolean and a contact, so it never legitimately redirects, and following
// one would let a peer aim this instance's own POST anywhere: a 307 to
// http://127.0.0.1:8080/repositories/1/delete replays the request against
// the admin UI, whose only authorization is the loopback Host check and a
// Sec-Fetch-Site check that a redirected Go request satisfies (the Host
// comes from the redirect target and no Sec-Fetch-Site is sent).
var peerClaimClient = &http.Client{
	Timeout:       peerClaimTimeout,
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

// ValidatePeerURL rejects a federation peer base URL this instance should
// not POST /claim-check to: anything but plain http(s) with a host, and
// anything carrying more than scheme, host and path. Credentials are
// refused because they would be sent on every analyst click and written to
// the log whenever the peer is unreachable, and a query or fragment is
// refused because /claim-check is appended to the path, so the endpoint
// would end up inside the query string instead.
func ValidatePeerURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("federation peer %q: %w", raw, err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("federation peer %q must be an http(s) URL with a host", raw)
	}
	if u.User != nil {
		return fmt.Errorf("federation peer %q must not contain credentials; configure them on the peer's reverse proxy instead", raw)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("federation peer %q must be a base URL with no query or fragment", raw)
	}
	return nil
}

// peerClaims asks every configured federation peer whether it already
// holds this finding, and returns the matching peers with their contacts
// as one display string (empty when nobody claims it). Peers are asked
// with the salted finding hash only, so the question reveals no more than
// the answer does.
//
// A peer that errors, times out, or answers 404 (not federated, or no such
// endpoint) is not a claim: the gate this feeds must not block an analyst
// because a peer is down. A local failure is different and returns an
// error: computing the hash needs this instance's own repository row, and
// reporting "nobody claims it" because the database was busy would silently
// open the exact gate the caller asked for.
func (s *Server) peerClaims(ctx context.Context, f db.Finding) (string, error) {
	if len(s.FederationPeers) == 0 || s.FederationSalt == "" {
		return "", nil
	}
	var repo db.Repository
	if err := s.DB.Select("url").First(&repo, f.RepositoryID).Error; err != nil {
		return "", fmt.Errorf("load repository %d: %w", f.RepositoryID, err)
	}
	hash := interchange.FindingHash(s.FederationSalt, repo.URL, f.SubPath, f.Location, f.CWE)
	ctx, cancel := context.WithTimeout(ctx, peerClaimTimeout)
	defer cancel()
	var claims []string
	for _, peer := range s.FederationPeers {
		contact, matched, err := askPeerClaim(ctx, peer, hash)
		if err != nil {
			s.Log.Warn("claim-check out: peer unreachable", "peer", peer, "finding", f.ID, "err", err)
			continue
		}
		if matched {
			claims = append(claims, peer+" ("+contact+")")
		}
	}
	return strings.Join(claims, ", "), nil
}

func askPeerClaim(ctx context.Context, peer, hash string) (string, bool, error) {
	body, err := json.Marshal(map[string]string{"hash": hash})
	if err != nil {
		return "", false, err
	}
	endpoint, err := url.JoinPath(peer, "claim-check")
	if err != nil {
		return "", false, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", false, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := peerClaimClient.Do(req)
	if err != nil {
		return "", false, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		return "", false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return "", false, fmt.Errorf("claim-check answered %s", resp.Status)
	}
	var out struct {
		Match   bool   `json:"match"`
		Contact string `json:"contact"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, peerClaimMaxBody)).Decode(&out); err != nil {
		return "", false, err
	}
	return out.Contact, out.Match, nil
}

// claimPeerHold runs the outbound claim-check for f, records any peer claim
// on the finding, and reports whether a peer holds it. A claim already
// recorded is the acknowledgement: the analyst has seen the banner naming
// the contacts, so the second attempt goes through. That makes one rule
// serve both entry points, the analyst's status transition and the enqueue
// of a skill that reports on their behalf, and it survives a page reload in
// a way a flash message would not.
func (s *Server) claimPeerHold(ctx context.Context, f db.Finding) (bool, error) {
	if f.FederationClaimContacts != "" {
		return false, nil
	}
	claims, err := s.peerClaims(ctx, f)
	if err != nil || claims == "" {
		return false, err
	}
	now := time.Now().UTC()
	return true, s.DB.Model(&db.Finding{}).Where("id = ?", f.ID).Updates(map[string]any{
		"federation_claim_contacts": claims,
		"federation_claim_at":       &now,
	}).Error
}

// federationClaimGate runs the outbound claim-check before a finding moves
// to reported and reports whether the transition may proceed; when it may
// not, the response has already been written. A peer holding the same
// finding means two instances are about to report it separately, so the
// analyst is sent back to the page where the banner names the contacts to
// coordinate with, and the next submit goes through.
func (s *Server) federationClaimGate(w http.ResponseWriter, r *http.Request, f db.Finding) bool {
	held, err := s.claimPeerHold(r.Context(), f)
	if err != nil {
		s.Log.Error("claim-check out", "finding", f.ID, "err", err)
		http.Error(w, "failed to check federation peers", http.StatusInternalServerError)
		return false
	}
	if !held {
		return true
	}
	s.redirect(w, r, fmt.Sprintf("/findings/%d", f.ID))
	return false
}

// clearFederationClaim drops a recorded peer claim once the transition it
// was blocking has actually gone through. It runs after the status write,
// not before: clearing first would erase the contacts the banner names on
// exactly the runs where the write then fails.
func (s *Server) clearFederationClaim(f db.Finding) {
	if f.FederationClaimContacts == "" && f.FederationClaimAt == nil {
		return
	}
	if err := s.DB.Model(&db.Finding{}).Where("id = ?", f.ID).Updates(map[string]any{
		"federation_claim_contacts": "",
		"federation_claim_at":       nil,
	}).Error; err != nil {
		s.Log.Error("claim-check out: clear claim", "finding", f.ID, "err", err)
	}
}
