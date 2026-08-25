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
	"sync"
	"time"

	"scrutineer/internal/db"
	"scrutineer/internal/interchange"
)

// peerClaimTimeout bounds the whole outbound claim-check round. It stays
// short because it sits inside an analyst's click: an unreachable peer must
// not hold up marking a finding reported.
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
//
// The two repositories the feeds never publish are silent here too: an
// opted-out repository, whose maintainer asked federated instances not to
// contact them about it, and a local (file://) one, whose hash is derived
// from a path on the operator's own filesystem.
func (s *Server) peerClaims(ctx context.Context, f db.Finding) (string, error) {
	if len(s.FederationPeers) == 0 || s.FederationSalt == "" {
		return "", nil
	}
	var repo db.Repository
	if err := s.DB.Select("url, federation_opt_out_at").First(&repo, f.RepositoryID).Error; err != nil {
		return "", fmt.Errorf("load repository %d: %w", f.RepositoryID, err)
	}
	if repo.IsLocal() || repo.FederationOptedOut() {
		return "", nil
	}
	hash := interchange.FindingHash(s.FederationSalt, repo.URL, f.SubPath, f.Location, f.CWE)
	ctx, cancel := context.WithTimeout(ctx, peerClaimTimeout)
	defer cancel()
	// Peers are asked concurrently: queried in sequence they share one
	// deadline, so a single hanging peer eats the budget and a claim the next
	// one would have answered is missed, which opens the gate this exists to
	// close.
	contacts := make([]string, len(s.FederationPeers))
	var wg sync.WaitGroup
	for i, peer := range s.FederationPeers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			contact, matched, err := askPeerClaim(ctx, peer, hash)
			if err != nil {
				s.Log.Warn("claim-check out: peer unreachable", "peer", peer, "finding", f.ID, "err", err)
				return
			}
			if matched {
				contacts[i] = peer + " (" + contact + ")"
			}
		}()
	}
	wg.Wait()
	var claims []string
	for _, claim := range contacts {
		if claim != "" {
			claims = append(claims, claim)
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
// on the finding, and returns the claim it recorded (empty when nobody holds
// it). A claim already recorded is the acknowledgement: the analyst has seen
// the banner naming the contacts, so the second attempt goes through. That
// makes one rule serve every entry point, the analyst's status transition,
// the VINCE submission, and the enqueue of a skill that reports on their
// behalf, and it survives a page reload in a way a flash message would not.
func (s *Server) claimPeerHold(ctx context.Context, f db.Finding) (string, error) {
	if f.FederationClaimContacts != "" {
		return "", nil
	}
	claims, err := s.peerClaims(ctx, f)
	if err != nil || claims == "" {
		return "", err
	}
	now := time.Now().UTC()
	return claims, s.DB.Model(&db.Finding{}).Where("id = ?", f.ID).Updates(map[string]any{
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
	claims, err := s.claimPeerHold(r.Context(), f)
	if err != nil {
		s.Log.Error("claim-check out", "finding", f.ID, "err", err)
		http.Error(w, "failed to check federation peers", http.StatusInternalServerError)
		return false
	}
	if claims == "" {
		return true
	}
	s.redirect(w, r, fmt.Sprintf("/findings/%d", f.ID))
	return false
}

// refuseClaimedOutreach runs the outbound claim-check when an outreach skill is
// about to be enqueued on a finding, and returns ErrFederationClaimPending when
// a peer holds it. The check sits at enqueue rather than on the skill's own
// status write: report-upstream files with the maintainer and only then PATCHes
// the status, so refusing the write would leave the outreach done and the
// finding stuck.
func (s *Server) refuseClaimedOutreach(ctx context.Context, opts ScanOpts, sk db.Skill, hasSkill bool) error {
	if opts.FindingID == nil || !hasSkill || !outreachSkills[sk.Name] {
		return nil
	}
	var f db.Finding
	if err := s.DB.Select("id, repository_id, sub_path, location, cwe, federation_claim_contacts").
		First(&f, *opts.FindingID).Error; err != nil {
		return err
	}
	claims, err := s.claimPeerHold(ctx, f)
	if err != nil {
		return err
	}
	if claims == "" {
		return nil
	}
	return fmt.Errorf("%w: %q", ErrFederationClaimPending, sk.Name)
}
