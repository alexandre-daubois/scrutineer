package web

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/git-pkgs/clone"
	"gorm.io/gorm"

	"scrutineer/internal/db"
	"scrutineer/internal/interchange"
)

// federationTick is how often the export and import feed jobs run. Feeds
// carry slow-moving records (a disclosure route, an opt-out, a fix-audit
// verdict), so an hour keeps peers usefully fresh without a git push per
// scan; the export skips the push entirely when nothing changed.
const federationTick = time.Hour

// feedCommitter identifies the export job's commits. Feed clones are
// scrutineer-owned working copies and the host may have no git identity
// configured at all, so the identity is passed per invocation rather than
// read from global config.
var feedCommitter = []string{"-c", "user.name=scrutineer", "-c", "user.email=scrutineer@localhost"}

// feedDirPerm is the mode of the feed working-clone directories under the
// data directory.
const feedDirPerm = 0o755

// StartFederation runs the interchange feed jobs until ctx is cancelled,
// starting with one immediate pass so an operator who has just configured
// a feed sees it populated without waiting out a tick. It returns straight
// away when no feed is configured.
func (s *Server) StartFederation(ctx context.Context) {
	if s.FederationPublicFeed == "" && s.FederationMembersFeed == "" && len(s.FederationImportFeeds) == 0 {
		return
	}
	s.runFederation(ctx)
	t := time.NewTicker(federationTick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.runFederation(ctx)
		}
	}
}

func (s *Server) runFederation(ctx context.Context) {
	for _, feed := range []struct {
		tier   interchange.Tier
		remote string
	}{
		{interchange.TierPublic, s.FederationPublicFeed},
		{interchange.TierMembers, s.FederationMembersFeed},
	} {
		if feed.remote == "" {
			continue
		}
		if err := s.exportFeed(ctx, feed.tier, feed.remote); err != nil {
			s.Log.Error("federation: export feed", "tier", feed.tier, "err", err)
		}
	}
	if len(s.FederationImportFeeds) == 0 {
		return
	}
	// The URL index is immutable, so it is built once for the whole pass
	// rather than re-reading the repositories table per feed.
	repoIDs, err := s.repoIDsByCanonicalURL()
	if err != nil {
		s.Log.Error("federation: index repositories", "err", err)
		return
	}
	for _, remote := range s.FederationImportFeeds {
		if err := s.importFeed(ctx, remote, repoIDs); err != nil {
			s.Log.Error("federation: import feed", "remote", remote, "err", err)
		}
	}
}

// exportFeed republishes one tier: sync the working clone, rewrite it to
// exactly the records this instance currently stands behind, then commit
// and push if that changed anything. Rewriting rather than appending is
// what makes a withdrawn opt-out or a re-audited certificate disappear
// from the feed instead of sitting next to its replacement.
func (s *Server) exportFeed(ctx context.Context, tier interchange.Tier, remote string) error {
	dir, err := s.feedClone(ctx, string(tier), remote)
	if err != nil {
		return err
	}
	recs, err := s.feedRecords(tier)
	if err != nil {
		return err
	}
	var keys interchange.FeedKeys
	if tier == interchange.TierMembers {
		keys = interchange.FeedKeys{Recipients: s.EncRecipients, Identities: s.EncIdentities}
	}
	if err := interchange.WriteFeed(dir, tier, recs, keys); err != nil {
		return err
	}
	pushed, err := commitAndPushFeed(ctx, dir, fmt.Sprintf("scrutineer: %s feed, %d records", tier, len(recs)))
	if err != nil {
		return err
	}
	if pushed {
		s.Log.Info("federation: published feed", "tier", tier, "records", len(recs))
	}
	return nil
}

// publishableRepo narrows a query to the repositories whose URL may appear
// in a record. A local (file://) URL is a path on the operator's own
// filesystem, and an empty one canonicalises to a value the schema refuses,
// which would abort the whole export over a single unusable row.
// Qualified so it reads the same in the certificate query, which joins.
const publishableRepo = "repositories.url != '' AND repositories.url NOT LIKE 'file://%'"

// feedRecords builds every record this instance publishes on a tier.
// Opted-out repositories are excluded from route and certificate records as
// well as scanning: an opt-out asks federated instances not to contact the
// maintainer, and republishing their disclosure route works against that.
func (s *Server) feedRecords(tier interchange.Tier) ([]interchange.Statement, error) {
	var out []interchange.Statement
	if tier == interchange.TierPublic {
		optOuts, err := s.optOutRecords()
		if err != nil {
			return nil, err
		}
		routes, err := s.routeRecords()
		if err != nil {
			return nil, err
		}
		out = append(out, optOuts...)
		out = append(out, routes...)
	}
	certs, err := s.certificateRecords(tier)
	if err != nil {
		return nil, err
	}
	return append(out, certs...), nil
}

func (s *Server) optOutRecords() ([]interchange.Statement, error) {
	var rows []db.Repository
	if err := s.DB.Select("url, federation_opt_out_at, federation_opt_out_reason").
		Where("repositories.federation_opt_out_at IS NOT NULL").Where(publishableRepo).
		Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]interchange.Statement, 0, len(rows))
	for _, r := range rows {
		out = append(out, interchange.NewOptOut(interchange.OptOutPredicate{
			Repository:  r.URL,
			RequestedAt: r.FederationOptOutAt.UTC(),
			Reason:      r.FederationOptOutReason,
		}))
	}
	return out, nil
}

// routeRecords publishes the validated disclosure route of every
// repository that has one. A repository whose channel predates
// disclosure_channel_at is skipped rather than stamped with a made-up
// verified_at: the record's timestamp has to be the one that only moves
// when the channel does, or every export would rewrite the whole feed.
func (s *Server) routeRecords() ([]interchange.Statement, error) {
	var rows []db.Repository
	if err := s.DB.Select("url, disclosure_channel, disclosure_channel_at").
		Where("disclosure_channel != '' AND disclosure_channel_at IS NOT NULL").
		Where(db.FederationNotOptedOut).Where(publishableRepo).
		Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]interchange.Statement, 0, len(rows))
	for _, r := range rows {
		out = append(out, interchange.NewRoute(interchange.RoutePredicate{
			Repository: r.URL,
			Channel:    r.DisclosureChannel,
			VerifiedAt: r.DisclosureChannelAt.UTC(),
		}))
	}
	return out, nil
}

// certificateRecords publishes the newest fix-audit verdict per
// (repository, advisory), split by tier: the clean "fixed" verdicts are
// certificate/v1 records for the public feed, the bypass/variant/regressed
// ones certificate/v2 records for the encrypted members feed, since each
// of those names a repository whose advertised fix does not hold.
func (s *Server) certificateRecords(tier interchange.Tier) ([]interchange.Statement, error) {
	type row struct {
		URL         string
		AdvisoryURL string
		Advisory    string
		Status      string
		Commit      string
		CreatedAt   time.Time
	}
	// The advisories join goes through a grouped subselect: nothing enforces
	// uniqueness on (repository_id, uuid) and parseAdvisoriesOutput inserts
	// whatever the report listed, so a plain join would fan out and publish
	// the same subject twice with an advisory_url picked by row order.
	q := s.DB.Model(&db.AdvisoryAudit{}).
		Select("repositories.url, advisories.url AS advisory_url, advisory_audits.advisory_uuid AS advisory, advisory_audits.status, advisory_audits.`commit`, advisory_audits.created_at").
		Joins("JOIN repositories ON repositories.id = advisory_audits.repository_id").
		Joins("LEFT JOIN (SELECT repository_id, uuid, MIN(url) AS url FROM advisories GROUP BY repository_id, uuid) advisories"+
			" ON advisories.repository_id = advisory_audits.repository_id AND advisories.uuid = advisory_audits.advisory_uuid").
		Where("advisory_audits.id IN (?)", s.DB.Model(&db.AdvisoryAudit{}).
			Select("MAX(id)").Group("repository_id, advisory_uuid")).
		Where(db.FederationNotOptedOut).
		Where(publishableRepo).
		Where("advisory_audits.advisory_uuid != ''")
	// Filtered to the verdicts each revision's schema accepts, rather than
	// "everything that is not fixed": an unexpected status would otherwise
	// reach certificate/v2, fail validation, and abort the whole export.
	if tier == interchange.TierPublic {
		q = q.Where("advisory_audits.status = ?", interchange.CertificateStatusFixed)
	} else {
		q = q.Where("advisory_audits.status IN ?", interchange.CertificateStatusesV2())
	}
	var rows []row
	if err := q.Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]interchange.Statement, 0, len(rows))
	for _, r := range rows {
		out = append(out, interchange.NewCertificate(interchange.CertificatePredicate{
			Repository:  r.URL,
			Advisory:    r.Advisory,
			AdvisoryURL: r.AdvisoryURL,
			Status:      r.Status,
			Commit:      r.Commit,
			AuditedAt:   r.CreatedAt.UTC(),
		}))
	}
	return out, nil
}

// importFeed pulls one peer feed and ingests it. Every record is stored
// verbatim; opt-outs and routes additionally apply to the matching local
// repository, which is the whole point of importing them, and stay open
// until they have been. A record that fails to decrypt, validate or decode
// is logged and skipped so one bad file from a peer does not cost the rest
// of the feed.
func (s *Server) importFeed(ctx context.Context, remote string, repoIDs map[string]uint) error {
	dir, err := s.feedClone(ctx, filepath.Join("import", feedDirName(remote)), remote)
	if err != nil {
		return err
	}
	records, err := interchange.ReadFeed(dir, s.EncIdentities)
	if err != nil {
		return err
	}
	var stored, applied, failed int
	for _, rec := range records {
		if rec.Err != nil {
			s.Log.Warn("federation: skipping record", "remote", remote, "path", rec.Path, "err", rec.Err)
			failed++
			continue
		}
		row, err := s.storeImportedRecord(remote, rec)
		if err != nil {
			s.Log.Error("federation: store record", "remote", remote, "path", rec.Path, "err", err)
			failed++
			continue
		}
		stored++
		if row.AppliedAt != nil {
			continue
		}
		// The stamp is what closes a record, so it is written only once the
		// record has actually been acted on: an apply that fails, or one whose
		// repository this instance does not track yet, leaves the row open and
		// the next pass tries again. Advancing on the archive write alone would
		// drop a maintainer's opt-out on a single transient failure, and would
		// never honour one published before its repository was imported here.
		done, err := s.applyImportedRecord(rec.Statement, repoIDs, remote)
		if err != nil {
			s.Log.Error("federation: apply record", "remote", remote, "path", rec.Path, "err", err)
			continue
		}
		if !done {
			continue
		}
		applied++
		if err := s.DB.Model(&db.InterchangeRecord{}).Where("id = ?", row.ID).
			UpdateColumn("applied_at", time.Now().UTC()).Error; err != nil {
			s.Log.Error("federation: stamp record", "remote", remote, "path", rec.Path, "err", err)
		}
	}
	s.Log.Info("federation: imported feed", "remote", remote, "stored", stored, "applied", applied, "skipped", failed)
	return nil
}

// storeImportedRecord archives the peer's own bytes and returns the stored
// row. Bytes that differ from the archived ones clear applied_at so the
// caller re-applies the correction; identical bytes keep the stamp, since an
// unchanged record has already had its effect and re-applying it every hour
// would silently undo an operator who cleared what a peer once asked for.
func (s *Server) storeImportedRecord(remote string, rec interchange.FeedRecord) (db.InterchangeRecord, error) {
	row := db.InterchangeRecord{
		Feed:          remote,
		PredicateType: rec.Statement.PredicateType,
		SubjectDigest: rec.Statement.Subject[0].Digest["sha256"],
	}
	var existing db.InterchangeRecord
	res := s.DB.Where(&row).Limit(1).Find(&existing)
	if res.Error != nil {
		return db.InterchangeRecord{}, res.Error
	}
	now, raw := time.Now().UTC(), string(rec.Raw)
	if res.RowsAffected == 0 {
		row.Record, row.ReceivedAt = raw, now
		return row, s.DB.Create(&row).Error
	}
	if existing.Record == raw {
		return existing, s.DB.Model(&existing).UpdateColumn("received_at", now).Error
	}
	existing.Record, existing.ReceivedAt, existing.AppliedAt = raw, now, nil
	return existing, s.DB.Model(&existing).
		Updates(map[string]any{"record": raw, "received_at": now, "applied_at": nil}).Error
}

// applyImportedRecord mirrors a peer's opt-out or disclosure route onto the
// matching local repository. An opt-out is honoured whichever peer sent it,
// since refusing to scan is the conservative direction; a route is only
// taken when this instance has none of its own and the repository has not
// opted out, so an imported hint neither overwrites what the maintainers
// skill or the analyst established here nor routes outreach to a maintainer
// who asked not to be contacted.
//
// The repository row is re-read per record rather than taken from the URL
// index: an opt-out applied earlier in the same pass (opt-outs sort before
// routes) has already changed the columns this decision turns on.
//
// It reports whether the record is closed. False means the subject names no
// repository this instance tracks, so the caller leaves the row open for a
// later pass: a peer publishing an opt-out before this operator imports the
// repository must not have it silently forgotten. The kinds that apply to
// nothing local (certificates, claims) are closed on sight.
func (s *Server) applyImportedRecord(rec interchange.Statement, repoIDs map[string]uint, feed string) (bool, error) {
	switch rec.PredicateType {
	case interchange.PredicateTypeOptOut:
		var p interchange.OptOutPredicate
		if err := interchange.DecodePredicate(rec, &p); err != nil {
			return false, err
		}
		repo, unlock, ok, err := s.repoForRecord(repoIDs, p.Repository)
		defer unlock()
		if err != nil || !ok {
			return false, err
		}
		// An opt-out already recorded here keeps its own request date, which is
		// what a peer is told the request was made on; only the sweep below is
		// worth redoing, since reaching this line means no earlier pass closed
		// the record and its sweep may be the step that failed.
		if !repo.FederationOptedOut() {
			at := p.RequestedAt.UTC()
			if err := s.DB.Model(&db.Repository{}).Where("id = ?", repo.ID).Updates(map[string]any{
				"federation_opt_out_at":     &at,
				"federation_opt_out_reason": p.Reason,
			}).Error; err != nil {
				return false, err
			}
		}
		// Same order as the repo page's own handler: the flag commits first, so
		// no scan is enqueued behind the sweep, then the work already under way
		// is stopped. An imported opt-out is the same maintainer's request, so
		// it has to stop this instance's scans too and not merely refuse the
		// next one.
		return true, s.stopScansForOptOut(repo.ID)
	case interchange.PredicateTypeRoute:
		var p interchange.RoutePredicate
		if err := interchange.DecodePredicate(rec, &p); err != nil {
			return false, err
		}
		repo, unlock, ok, err := s.repoForRecord(repoIDs, p.Repository)
		defer unlock()
		if err != nil || !ok {
			return false, err
		}
		if repo.DisclosureChannel != "" || repo.FederationOptedOut() {
			return true, nil
		}
		// The channel is where an unpublished GHSA draft and patch get
		// mailed, so an imported one says where it came from: an analyst must
		// be able to tell a peer's hint from an address the maintainers skill
		// read out of a verified SECURITY.md. Same convention as cna-match,
		// which appends the CNA's organization name.
		//
		// disclosure_channel_at is cleared rather than set to the peer's
		// verified_at: that timestamp is what routeRecords publishes, so
		// keeping it would re-export a hint this instance never validated as
		// its own confirmed route, peer feed remote and all, and make one
		// peer's claim look like two independent ones. The channel goes back
		// on the feed once an analyst changes it, which stamps it here.
		return true, s.DB.Model(&db.Repository{}).Where("id = ?", repo.ID).Updates(map[string]any{
			"disclosure_channel":    p.Channel + " (via " + feed + ")",
			"disclosure_channel_at": nil,
		}).Error
	}
	return true, nil
}

// repoForRecord resolves a record's repository URL to the current local row
// and holds that repository's federation section until the caller releases
// it: the opt-out flag both decisions turn on is written under the same lock
// by the repo page and read under it by the scheduler, so reading it outside
// would leave the import applying a route to a repository that opted out in
// between. The release is never nil, so a caller defers it unconditionally.
//
// A URL this instance does not track is not an error; a row that vanished
// between the index and the read is not either, but any other failure is,
// since silently treating a locked database as "no such repository" would
// drop a maintainer's opt-out.
func (s *Server) repoForRecord(repoIDs map[string]uint, url string) (db.Repository, func(), bool, error) {
	id, ok := repoIDs[interchange.CanonicalRepo(url)]
	if !ok {
		return db.Repository{}, func() {}, false, nil
	}
	unlock := s.lockRepoFederation(id)
	var repo db.Repository
	err := s.DB.Select("id, disclosure_channel, federation_opt_out_at").First(&repo, id).Error
	if err != nil {
		unlock()
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return db.Repository{}, func() {}, false, nil
		}
		return db.Repository{}, func() {}, false, err
	}
	return repo, unlock, true, nil
}

// ValidateFeedRemote rejects a git remote that embeds a token. Feed remotes
// are pushed to and fetched from on every tick and are written verbatim into
// the job's error messages and log fields, so a credentialed remote would
// leak its token into the logs. Both spellings are covered: the URL form
// parses its userinfo, and the scp-style form does not parse as a URL at all,
// so its userinfo is read off the text before the path.
func ValidateFeedRemote(raw string) error {
	remote := strings.TrimSpace(raw)
	credentialed := fmt.Errorf("federation feed remote %q must not contain credentials; configure a git credential helper on the host instead", raw)
	if u, err := url.Parse(remote); err == nil && u.Scheme != "" && u.Host != "" {
		// Over http(s) any userinfo is refused: as parse_repo_url.go puts it,
		// tokens are commonly supplied as the username, so a bare-username
		// allowance would let the common PAT spelling straight through. A bare
		// username over ssh:// is the ordinary ssh://git@host/... form and
		// carries no secret; a password there still does.
		if u.User != nil {
			_, hasPassword := u.User.Password()
			if hasPassword || u.Scheme == "http" || u.Scheme == "https" {
				return credentialed
			}
		}
		return nil
	}
	// scp-style: [user[:password]@]host:path. Only the part before the first
	// "/" can hold userinfo, so the path never confuses the check.
	head, _, _ := strings.Cut(remote, "/")
	if userinfo, _, ok := strings.Cut(head, "@"); ok && strings.Contains(userinfo, ":") {
		return credentialed
	}
	return nil
}

// repoIDsByCanonicalURL keys the local repository ids by the same canonical
// URL the records carry, since the canonicalisation (lowercase, trailing
// slash and .git stripped) cannot be expressed as a SQL join. Only the id is
// indexed: it is the one thing that cannot change under an import pass.
func (s *Server) repoIDsByCanonicalURL() (map[string]uint, error) {
	var rows []db.Repository
	if err := s.DB.Select("id, url").Where(publishableRepo).Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make(map[string]uint, len(rows))
	for _, r := range rows {
		out[interchange.CanonicalRepo(r.URL)] = r.ID
	}
	return out, nil
}

// feedClone returns a synced working clone of remote under the data
// directory, cloning it on first use and hard-resetting it to the remote
// afterwards. The reset is what keeps the export idempotent: local commits
// from a previous run that never reached the remote are discarded rather
// than accumulating into a push that conflicts forever.
func (s *Server) feedClone(ctx context.Context, name, remote string) (string, error) {
	if s.Worker == nil || s.Worker.DataDir == "" {
		return "", errors.New("no data directory configured")
	}
	dir := filepath.Join(s.Worker.DataDir, "feeds", name)
	if _, err := os.Stat(filepath.Join(dir, ".git")); err != nil {
		// A clone that died partway leaves the destination populated but
		// without .git, and git refuses a non-empty target with a permanent
		// error, so the leftovers would wedge every later tick. The path is
		// entirely scrutineer-owned and derived from the tier or a digest of
		// the remote, never from user input, so clearing it is safe.
		if err := os.RemoveAll(dir); err != nil {
			return "", err
		}
		if err := os.MkdirAll(filepath.Dir(dir), feedDirPerm); err != nil {
			return "", err
		}
		if out, err := runFeedGit(ctx, "", "clone", "--quiet", "--", remote, dir); err != nil {
			return "", fmt.Errorf("clone %s: %s: %w", remote, out, err)
		}
		return dir, nil
	}
	branch, err := runFeedGit(ctx, dir, "symbolic-ref", "--short", "HEAD")
	if err != nil {
		return "", fmt.Errorf("resolve branch of %s: %s: %w", remote, branch, err)
	}
	if out, err := runFeedGit(ctx, dir, "fetch", "--quiet", "origin"); err != nil {
		return "", fmt.Errorf("fetch %s: %s: %w", remote, out, err)
	}
	// Reset onto this branch's remote-tracking ref, not FETCH_HEAD: the fetch
	// uses the clone's all-branches refspec, so FETCH_HEAD holds every branch
	// the remote advertises and which one it resolves to depends on git's
	// ordering. The tracking ref is also independent of branch.<name>.merge,
	// which a clone of an empty remote never sets. A remote that does not
	// carry this branch yet is the first-export case: nothing to reset onto,
	// and the local state is already the whole feed.
	tracking := "refs/remotes/origin/" + strings.TrimSpace(branch)
	if _, err := runFeedGit(ctx, dir, "rev-parse", "--verify", "--quiet", tracking); err != nil {
		return dir, nil
	}
	if out, err := runFeedGit(ctx, dir, "reset", "--quiet", "--hard", tracking); err != nil {
		return "", fmt.Errorf("reset %s: %s: %w", remote, out, err)
	}
	return dir, nil
}

// commitAndPushFeed commits the working tree and pushes it, reporting
// whether anything was published. A clean tree means the feed already
// matches what this instance stands behind, so the tick costs a fetch and
// nothing else.
func commitAndPushFeed(ctx context.Context, dir, message string) (bool, error) {
	// --force so a stray .gitignore in the feed repository cannot make the
	// job report a clean tree while silently publishing nothing.
	if out, err := runFeedGit(ctx, dir, "add", "--all", "--force", "."); err != nil {
		return false, fmt.Errorf("add: %s: %w", out, err)
	}
	status, err := runFeedGit(ctx, dir, "status", "--porcelain")
	if err != nil {
		return false, fmt.Errorf("status: %s: %w", status, err)
	}
	if strings.TrimSpace(status) == "" {
		return false, nil
	}
	if out, err := runFeedGit(ctx, dir, append(append([]string{}, feedCommitter...), "commit", "--quiet", "-m", message)...); err != nil {
		return false, fmt.Errorf("commit: %s: %w", out, err)
	}
	if out, err := runFeedGit(ctx, dir, "push", "--quiet", "origin", "HEAD"); err != nil {
		return false, fmt.Errorf("push: %s: %w", out, err)
	}
	return true, nil
}

// runFeedGit runs one git command against a feed clone under the standard
// network retry policy. GIT_TERMINAL_PROMPT=0 keeps a feed remote whose
// credentials are missing failing fast instead of blocking the job on a
// prompt no one can answer.
func runFeedGit(ctx context.Context, dir string, args ...string) (string, error) {
	return clone.Retry{}.Do(ctx, clone.Command{
		Label: "feed " + args[0],
		Dir:   dir,
		Env:   []string{"GIT_TERMINAL_PROMPT=0"},
		Args:  args,
	})
}

// feedDirName is a stable, filesystem-safe directory name for a peer
// remote, so two peers never share a working clone and a remote containing
// a path separator or credentials cannot escape the feeds directory.
func feedDirName(remote string) string {
	h := sha256.Sum256([]byte(remote))
	return hex.EncodeToString(h[:8])
}
