package web

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"scrutineer/internal/db"
	"scrutineer/internal/interchange"
)

func feedTime(t *testing.T) time.Time {
	t.Helper()
	return time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
}

// seedFeedRepo creates a repository with a disclosure route already
// stamped, which is what routeRecords requires to publish it.
func seedFeedRepo(t *testing.T, s *Server, url, channel string) db.Repository {
	t.Helper()
	at := feedTime(t)
	repo := db.Repository{URL: url, Name: filepath.Base(url), DisclosureChannel: channel}
	if channel != "" {
		repo.DisclosureChannelAt = &at
	}
	if err := s.DB.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	return repo
}

func seedAudit(t *testing.T, s *Server, repoID uint, uuid, status string) {
	t.Helper()
	if err := s.DB.Create(&db.AdvisoryAudit{
		RepositoryID: repoID, AdvisoryUUID: uuid, Status: status, CreatedAt: feedTime(t),
	}).Error; err != nil {
		t.Fatal(err)
	}
}

func mustRepoIDs(t *testing.T, s *Server) map[string]uint {
	t.Helper()
	ids, err := s.repoIDsByCanonicalURL()
	if err != nil {
		t.Fatal(err)
	}
	return ids
}

func recordKindCounts(recs []interchange.Statement) map[string]int {
	out := map[string]int{}
	for _, rec := range recs {
		out[rec.PredicateType]++
	}
	return out
}

// initBareRemote creates an empty bare repository usable as a feed remote.
func initBareRemote(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	cmd := exec.Command("git", "init", "--quiet", "--bare", dir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git init --bare: %v\n%s", err, out)
	}
	return dir
}

func remoteCommitCount(t *testing.T, remote string) int {
	t.Helper()
	out, err := exec.Command("git", "-C", remote, "rev-list", "--count", "--all").CombinedOutput()
	if err != nil {
		t.Fatalf("git rev-list: %v\n%s", err, out)
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil {
		t.Fatalf("unexpected rev-list output %q: %v", out, err)
	}
	return n
}

func TestValidateFeedRemote(t *testing.T) {
	for _, ok := range []string{
		"https://github.com/org/feed.git",
		"git@github.com:org/feed.git",
		"ssh://git@github.com/org/feed.git",
		"/srv/feeds/public.git",
	} {
		if err := ValidateFeedRemote(ok); err != nil {
			t.Errorf("%q must be accepted: %v", ok, err)
		}
	}
	for _, bad := range []string{
		// A token as the username is the common PAT spelling and the remote
		// reaches the log on every pass, so it is refused like a password.
		"https://ghp_secret@github.com/org/feed.git",
		"https://x-access-token:ghp_secret@github.com/org/feed.git",
		"user:pw@github.com:org/feed.git",
	} {
		if err := ValidateFeedRemote(bad); err == nil {
			t.Errorf("%q embeds credentials and must be refused", bad)
		}
	}
}

func TestFeedRecords_publicTier(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.Worker.DataDir = t.TempDir()

	routed := seedFeedRepo(t, s, "https://github.com/acme/routed", "security@acme.example")
	seedAudit(t, s, routed.ID, "uuid-clean", "fixed")
	seedAudit(t, s, routed.ID, "uuid-broken", "bypass")

	optedOut := seedFeedRepo(t, s, "https://github.com/acme/quiet", "security@quiet.example")
	at := feedTime(t)
	s.DB.Model(&db.Repository{}).Where("id = ?", optedOut.ID).Update("federation_opt_out_at", &at)
	seedAudit(t, s, optedOut.ID, "uuid-quiet", "fixed")

	recs, err := s.feedRecords(interchange.TierPublic)
	if err != nil {
		t.Fatal(err)
	}
	counts := recordKindCounts(recs)
	if counts[interchange.PredicateTypeOptOut] != 1 {
		t.Errorf("expected 1 optout record, got %d", counts[interchange.PredicateTypeOptOut])
	}
	if counts[interchange.PredicateTypeRoute] != 1 {
		t.Errorf("expected only the non-opted-out route, got %d", counts[interchange.PredicateTypeRoute])
	}
	if counts[interchange.PredicateTypeCertificate] != 1 {
		t.Errorf("expected only the clean certificate of the non-opted-out repo, got %d", counts[interchange.PredicateTypeCertificate])
	}
	if counts[interchange.PredicateTypeCertificateV2] != 0 {
		t.Errorf("a non-clean certificate must never appear on the public tier, got %d", counts[interchange.PredicateTypeCertificateV2])
	}
}

func TestFeedRecords_membersTierCarriesOnlyNonCleanCertificates(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := seedFeedRepo(t, s, "https://github.com/acme/lib", "security@acme.example")
	seedAudit(t, s, repo.ID, "uuid-clean", "fixed")
	seedAudit(t, s, repo.ID, "uuid-bypass", "bypass")
	seedAudit(t, s, repo.ID, "uuid-variant", "variant")

	// A repository whose maintainer opted out must stay off this tier too:
	// a certificate/v2 names a live unfixed weakness in it.
	optedOut := seedFeedRepo(t, s, "https://github.com/acme/quiet", "")
	at := feedTime(t)
	s.DB.Model(&db.Repository{}).Where("id = ?", optedOut.ID).Update("federation_opt_out_at", &at)
	seedAudit(t, s, optedOut.ID, "uuid-quiet", "regressed")

	recs, err := s.feedRecords(interchange.TierMembers)
	if err != nil {
		t.Fatal(err)
	}
	counts := recordKindCounts(recs)
	if counts[interchange.PredicateTypeCertificateV2] != 2 {
		t.Errorf("expected the 2 non-clean certificates of the non-opted-out repo, got %d", counts[interchange.PredicateTypeCertificateV2])
	}
	if len(recs) != 2 {
		t.Errorf("the members tier must carry certificates only, got %d records", len(recs))
	}
}

// The members query filters on the verdicts certificate/v2 accepts rather
// than on "not fixed", so this list has to stay in step with the db enum:
// a new verdict must be added to both or the export silently stops
// publishing it.
func TestCertificateStatusesV2_matchesTheAuditEnum(t *testing.T) {
	want := make([]string, 0, len(db.AdvisoryAuditStatuses))
	for status := range db.AdvisoryAuditStatuses {
		if status != interchange.CertificateStatusFixed {
			want = append(want, status)
		}
	}
	slices.Sort(want)
	if !slices.Equal(interchange.CertificateStatusesV2, want) {
		t.Fatalf("CertificateStatusesV2 = %v, want %v (from db.AdvisoryAuditStatuses)", interchange.CertificateStatusesV2, want)
	}
}

func TestFeedRecords_skipsLocalReposAndUnstampedRoutes(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	local := db.Repository{URL: LocalScheme + "/home/analyst/work/lib", Name: "lib", DisclosureChannel: "me@example.com"}
	at := feedTime(t)
	local.DisclosureChannelAt = &at
	s.DB.Create(&local)
	seedAudit(t, s, local.ID, "uuid-local", "fixed")

	// A channel written before disclosure_channel_at existed has no
	// verified_at to publish, so it stays off the feed instead of being
	// stamped with a timestamp that would move on every export.
	legacy := db.Repository{URL: "https://github.com/acme/legacy", Name: "legacy", DisclosureChannel: "security@legacy.example"}
	s.DB.Create(&legacy)

	recs, err := s.feedRecords(interchange.TierPublic)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 0 {
		t.Fatalf("expected no publishable records, got %+v", recs)
	}
}

func TestCertificateRecords_newestVerdictWins(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := seedFeedRepo(t, s, "https://github.com/acme/lib", "")
	seedAudit(t, s, repo.ID, "uuid-1", "fixed")
	seedAudit(t, s, repo.ID, "uuid-1", "regressed")

	public, err := s.certificateRecords(interchange.TierPublic)
	if err != nil {
		t.Fatal(err)
	}
	if len(public) != 0 {
		t.Errorf("a superseded clean verdict must not stay on the public feed, got %+v", public)
	}
	members, err := s.certificateRecords(interchange.TierMembers)
	if err != nil {
		t.Fatal(err)
	}
	if len(members) != 1 {
		t.Fatalf("expected the newest verdict only, got %d records", len(members))
	}
}

func TestExportFeed_publishesThenNoOps(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.Worker.DataDir = t.TempDir()
	remote := initBareRemote(t)

	repo := seedFeedRepo(t, s, "https://github.com/acme/lib", "security@acme.example")
	seedAudit(t, s, repo.ID, "uuid-clean", "fixed")

	if err := s.exportFeed(context.Background(), interchange.TierPublic, remote); err != nil {
		t.Fatal(err)
	}
	if got := remoteCommitCount(t, remote); got != 1 {
		t.Fatalf("expected 1 commit after the first export, got %d", got)
	}
	clone := filepath.Join(s.Worker.DataDir, "feeds", "public")
	records, err := interchange.ReadFeed(clone, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("expected the route and the certificate on the feed, got %d", len(records))
	}

	if err := s.exportFeed(context.Background(), interchange.TierPublic, remote); err != nil {
		t.Fatal(err)
	}
	if got := remoteCommitCount(t, remote); got != 1 {
		t.Fatalf("an unchanged feed must not produce a second commit, got %d", got)
	}
}

// The sync has to actually reset onto the remote, not just skip: a peer or a
// second instance pushing between ticks must not leave this one exporting
// from a diverged clone forever.
func TestExportFeed_picksUpAThirdPartyCommit(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.Worker.DataDir = t.TempDir()
	remote := initBareRemote(t)

	repo := seedFeedRepo(t, s, "https://github.com/acme/lib", "security@acme.example")
	seedAudit(t, s, repo.ID, "uuid-clean", "fixed")
	if err := s.exportFeed(context.Background(), interchange.TierPublic, remote); err != nil {
		t.Fatal(err)
	}

	// A third party adds a README to the feed repository.
	work := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("git", append([]string{"-C", work}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("clone", "--quiet", remote, ".")
	if err := os.WriteFile(filepath.Join(work, "README.md"), []byte("peer feed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", "README.md")
	run("-c", "user.name=peer", "-c", "user.email=peer@localhost", "commit", "--quiet", "-m", "readme")
	run("push", "--quiet", "origin", "HEAD")

	if err := s.exportFeed(context.Background(), interchange.TierPublic, remote); err != nil {
		t.Fatal(err)
	}
	clone := filepath.Join(s.Worker.DataDir, "feeds", "public")
	if _, err := os.Stat(filepath.Join(clone, "README.md")); err != nil {
		t.Fatalf("the export clone must have been reset onto the remote: %v", err)
	}
	if got := remoteCommitCount(t, remote); got != 2 {
		t.Fatalf("an unchanged record set must add no commit on top of the peer's, got %d", got)
	}
}

func TestExportFeed_membersTierIsEncrypted(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.Worker.DataDir = t.TempDir()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	s.EncRecipients = []age.Recipient{id.Recipient()}
	s.EncIdentities = []age.Identity{id}
	remote := initBareRemote(t)

	repo := seedFeedRepo(t, s, "https://github.com/acme/lib", "")
	seedAudit(t, s, repo.ID, "uuid-bypass", "bypass")

	if err := s.exportFeed(context.Background(), interchange.TierMembers, remote); err != nil {
		t.Fatal(err)
	}
	// age re-encrypts under a fresh key each call, so without the
	// plaintext comparison every tick would push a full rewrite forever.
	if err := s.exportFeed(context.Background(), interchange.TierMembers, remote); err != nil {
		t.Fatal(err)
	}
	if got := remoteCommitCount(t, remote); got != 1 {
		t.Fatalf("an unchanged members feed must not produce a second commit, got %d", got)
	}
	clone := filepath.Join(s.Worker.DataDir, "feeds", "members")
	if records, err := interchange.ReadFeed(clone, nil); err != nil {
		t.Fatal(err)
	} else if len(records) != 1 || records[0].Err == nil {
		t.Fatalf("the members feed must be unreadable without an identity: %+v", records)
	}
	records, err := interchange.ReadFeed(clone, []age.Identity{id})
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Err != nil {
		t.Fatalf("expected one decryptable record, got %+v", records)
	}
}

func TestExportFeed_membersTierWithoutRecipientsFails(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.Worker.DataDir = t.TempDir()
	remote := initBareRemote(t)

	repo := seedFeedRepo(t, s, "https://github.com/acme/lib", "")
	seedAudit(t, s, repo.ID, "uuid-bypass", "bypass")

	if err := s.exportFeed(context.Background(), interchange.TierMembers, remote); err == nil {
		t.Fatal("publishing non-clean certificates without recipients must fail")
	}
	if got := remoteCommitCount(t, remote); got != 0 {
		t.Fatalf("nothing must have been pushed, got %d commits", got)
	}
}

// publishPeerFeed writes recs to a bare remote by way of a throwaway
// export, giving the import tests a real peer feed to pull from.
func publishPeerFeed(t *testing.T, recs []interchange.Statement) string {
	t.Helper()
	remote := initBareRemote(t)
	work := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("git", append([]string{"-C", work}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init", "--quiet")
	run("remote", "add", "origin", remote)
	if err := interchange.WriteFeed(work, interchange.TierPublic, recs, interchange.FeedKeys{}); err != nil {
		t.Fatal(err)
	}
	run("add", "--all", ".")
	run("-c", "user.name=peer", "-c", "user.email=peer@localhost", "commit", "--quiet", "-m", "feed")
	run("push", "--quiet", "origin", "HEAD")
	return remote
}

func TestImportFeed_storesRecordsAndAppliesOptOut(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.Worker.DataDir = t.TempDir()

	repo := seedFeedRepo(t, s, "https://github.com/acme/lib", "")
	remote := publishPeerFeed(t, []interchange.Statement{
		interchange.NewOptOut(interchange.OptOutPredicate{
			Repository:  "https://github.com/ACME/lib.git",
			RequestedAt: feedTime(t),
			Reason:      "please stop",
		}),
	})

	if err := s.importFeed(context.Background(), remote, mustRepoIDs(t, s)); err != nil {
		t.Fatal(err)
	}
	var rows []db.InterchangeRecord
	if err := s.DB.Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].PredicateType != interchange.PredicateTypeOptOut {
		t.Fatalf("expected the opt-out stored verbatim, got %+v", rows)
	}
	// The column is documented as the record as published, so it must be
	// the peer's own bytes: same as what sits on the feed clone.
	onFeed, err := interchange.ReadFeed(filepath.Join(s.Worker.DataDir, "feeds", "import", feedDirName(remote)), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(onFeed) != 1 || strings.TrimSpace(string(onFeed[0].Raw)) != strings.TrimSpace(rows[0].Record) {
		t.Fatalf("stored record is not the published bytes:\n%s\n---\n%s", onFeed[0].Raw, rows[0].Record)
	}
	var got db.Repository
	s.DB.First(&got, repo.ID)
	if got.FederationOptOutAt == nil {
		t.Fatal("a peer opt-out must apply even when the URL differs in case and .git suffix")
	}
	if got.FederationOptOutReason != "please stop" {
		t.Errorf("reason = %q", got.FederationOptOutReason)
	}
}

func TestImportFeed_routeOnlyFillsAnEmptyChannel(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.Worker.DataDir = t.TempDir()

	empty := seedFeedRepo(t, s, "https://github.com/acme/empty", "")
	owned := seedFeedRepo(t, s, "https://github.com/acme/owned", "analyst@example.com")
	remote := publishPeerFeed(t, []interchange.Statement{
		interchange.NewRoute(interchange.RoutePredicate{
			Repository: "https://github.com/acme/empty", Channel: "peer@example.com", VerifiedAt: feedTime(t),
		}),
		interchange.NewRoute(interchange.RoutePredicate{
			Repository: "https://github.com/acme/owned", Channel: "peer@example.com", VerifiedAt: feedTime(t),
		}),
	})

	if err := s.importFeed(context.Background(), remote, mustRepoIDs(t, s)); err != nil {
		t.Fatal(err)
	}
	var filled db.Repository
	s.DB.First(&filled, empty.ID)
	if !strings.HasPrefix(filled.DisclosureChannel, "peer@example.com") || filled.DisclosureChannelAt == nil {
		t.Errorf("an imported route must fill an empty channel, got %q at %v", filled.DisclosureChannel, filled.DisclosureChannelAt)
	}
	// The channel is where a GHSA draft gets mailed, so an analyst has to be
	// able to see it came from a peer rather than a verified SECURITY.md.
	if !strings.Contains(filled.DisclosureChannel, "(via "+remote+")") {
		t.Errorf("an imported channel must name the feed it came from, got %q", filled.DisclosureChannel)
	}
	var kept db.Repository
	s.DB.First(&kept, owned.ID)
	if kept.DisclosureChannel != "analyst@example.com" {
		t.Errorf("an imported route must never overwrite a local channel, got %q", kept.DisclosureChannel)
	}
}

func TestImportFeed_keepsOneRowPerPeer(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.Worker.DataDir = t.TempDir()

	rec := interchange.NewOptOut(interchange.OptOutPredicate{
		Repository: "https://github.com/acme/lib", RequestedAt: feedTime(t),
	})
	for _, remote := range []string{publishPeerFeed(t, []interchange.Statement{rec}), publishPeerFeed(t, []interchange.Statement{rec})} {
		if err := s.importFeed(context.Background(), remote, mustRepoIDs(t, s)); err != nil {
			t.Fatal(err)
		}
		// Re-importing the same feed must refresh its row, not add one.
		if err := s.importFeed(context.Background(), remote, mustRepoIDs(t, s)); err != nil {
			t.Fatal(err)
		}
	}
	var count int64
	s.DB.Model(&db.InterchangeRecord{}).Count(&count)
	if count != 2 {
		t.Fatalf("expected one row per peer for the same subject, got %d", count)
	}
}

func TestImportFeed_unchangedRecordIsNotReapplied(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.Worker.DataDir = t.TempDir()

	repo := seedFeedRepo(t, s, "https://github.com/acme/lib", "")
	remote := publishPeerFeed(t, []interchange.Statement{
		interchange.NewOptOut(interchange.OptOutPredicate{
			Repository: "https://github.com/acme/lib", RequestedAt: feedTime(t),
		}),
	})
	if err := s.importFeed(context.Background(), remote, mustRepoIDs(t, s)); err != nil {
		t.Fatal(err)
	}
	// An operator who clears an imported opt-out must not have it silently
	// reinstated on the next tick from a record the peer has not touched.
	if err := s.DB.Model(&db.Repository{}).Where("id = ?", repo.ID).
		Update("federation_opt_out_at", nil).Error; err != nil {
		t.Fatal(err)
	}
	if err := s.importFeed(context.Background(), remote, mustRepoIDs(t, s)); err != nil {
		t.Fatal(err)
	}
	var got db.Repository
	s.DB.First(&got, repo.ID)
	if got.FederationOptOutAt != nil {
		t.Fatal("an unchanged record must not be re-applied")
	}
}

func TestSetDisclosureChannel_stampsOnlyOnChange(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := seedFeedRepo(t, s, "https://github.com/acme/lib", "")

	if err := db.SetDisclosureChannel(s.DB, repo.ID, "", "security@acme.example"); err != nil {
		t.Fatal(err)
	}
	var got db.Repository
	s.DB.First(&got, repo.ID)
	if got.DisclosureChannelAt == nil {
		t.Fatal("a new channel must be stamped")
	}
	stamped := *got.DisclosureChannelAt

	if err := db.SetDisclosureChannel(s.DB, repo.ID, "security@acme.example", "security@acme.example"); err != nil {
		t.Fatal(err)
	}
	s.DB.First(&got, repo.ID)
	if !got.DisclosureChannelAt.Equal(stamped) {
		t.Errorf("an unchanged re-write must not move the timestamp the route record publishes")
	}
}

func TestStartFederation_returnsWithoutConfiguration(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	// No feed configured: the job must not tick, and above all must not
	// block the goroutine main starts it on.
	stopped := make(chan struct{})
	go func() {
		s.StartFederation(context.Background())
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("StartFederation must return immediately when no feed is configured")
	}
}
