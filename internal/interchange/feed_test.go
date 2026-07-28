package interchange

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
)

func certificate(t *testing.T, status string) Statement {
	t.Helper()
	return NewCertificate(CertificatePredicate{
		Repository: "https://github.com/acme/lib",
		Advisory:   "GHSA-xxxx-yyyy-zzzz",
		Status:     status,
		AuditedAt:  time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC),
	})
}

func optOut(t *testing.T, repo string) Statement {
	t.Helper()
	return NewOptOut(OptOutPredicate{
		Repository:  repo,
		RequestedAt: time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC),
	})
}

func testIdentity(t *testing.T) *age.X25519Identity {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestNewCertificatePicksPredicateTypeFromVerdict(t *testing.T) {
	if got := certificate(t, CertificateStatusFixed).PredicateType; got != PredicateTypeCertificate {
		t.Errorf("clean verdict must stay on certificate/v1, got %s", got)
	}
	for _, status := range []string{"bypass", "variant", "regressed"} {
		if got := certificate(t, status).PredicateType; got != PredicateTypeCertificateV2 {
			t.Errorf("%s verdict must use certificate/v2, got %s", status, got)
		}
	}
}

func TestTierCarries(t *testing.T) {
	cases := []struct {
		tier          Tier
		predicateType string
		want          bool
	}{
		{TierPublic, PredicateTypeCertificate, true},
		{TierPublic, PredicateTypeOptOut, true},
		{TierPublic, PredicateTypeRoute, true},
		{TierPublic, PredicateTypeCertificateV2, false},
		{TierPublic, PredicateTypeClaim, false},
		{TierMembers, PredicateTypeCertificateV2, true},
		{TierMembers, PredicateTypeCertificate, false},
		{TierMembers, PredicateTypeOptOut, false},
		{TierMembers, PredicateTypeClaim, false},
		{Tier("other"), PredicateTypeOptOut, false},
	}
	for _, c := range cases {
		if got := c.tier.Carries(c.predicateType); got != c.want {
			t.Errorf("%s.Carries(%s) = %v, want %v", c.tier, c.predicateType, got, c.want)
		}
	}
}

func TestRecordFile(t *testing.T) {
	rec := optOut(t, "https://github.com/acme/lib")
	digest := rec.Subject[0].Digest["sha256"]
	got, err := RecordFile(rec, false)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join("optout", digest+".json"); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if got, _ = RecordFile(rec, true); !strings.HasSuffix(got, ".json.age") {
		t.Errorf("encrypted record must carry the .age suffix, got %q", got)
	}
	if _, err := RecordFile(Statement{PredicateType: "https://example.com/other/v1"}, false); err == nil {
		t.Error("an unknown predicate type must be refused")
	}
	if _, err := RecordFile(Statement{PredicateType: PredicateTypeOptOut}, false); err == nil {
		t.Error("a record without a subject digest must be refused")
	}
}

func TestWriteFeedPublishesAndPrunes(t *testing.T) {
	dir := t.TempDir()
	first := optOut(t, "https://github.com/acme/lib")
	second := optOut(t, "https://github.com/acme/other")
	if err := WriteFeed(dir, TierPublic, []Statement{first, second}, FeedKeys{}); err != nil {
		t.Fatal(err)
	}
	names, err := recordFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 2 {
		t.Fatalf("expected 2 records on the feed, got %v", names)
	}

	// A withdrawn opt-out must leave the feed, not sit next to the rest.
	if err := WriteFeed(dir, TierPublic, []Statement{first}, FeedKeys{}); err != nil {
		t.Fatal(err)
	}
	names, err = recordFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := RecordFile(first, false)
	if len(names) != 1 || names[0] != want {
		t.Fatalf("expected only %q to remain, got %v", want, names)
	}
}

func TestWriteFeedLeavesForeignFilesAlone(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("peer feed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := WriteFeed(dir, TierPublic, nil, FeedKeys{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "README.md")); err != nil {
		t.Fatalf("the feed repository's own files must survive an export: %v", err)
	}
}

func TestWriteFeedRefusesMisroutedRecord(t *testing.T) {
	dir := t.TempDir()
	err := WriteFeed(dir, TierPublic, []Statement{certificate(t, "bypass")}, FeedKeys{})
	if err == nil {
		t.Fatal("a non-clean certificate must never reach the public feed")
	}
	if names, _ := recordFiles(dir); len(names) != 0 {
		t.Fatalf("a refused export must write nothing, got %v", names)
	}
}

func TestWriteFeedRefusesMembersTierWithoutRecipients(t *testing.T) {
	if err := WriteFeed(t.TempDir(), TierMembers, []Statement{certificate(t, "bypass")}, FeedKeys{}); err == nil {
		t.Fatal("the members feed must refuse to publish without age recipients")
	}
}

func TestFeedRoundTripPlaintext(t *testing.T) {
	dir := t.TempDir()
	rec := optOut(t, "https://github.com/acme/lib")
	if err := WriteFeed(dir, TierPublic, []Statement{rec}, FeedKeys{}); err != nil {
		t.Fatal(err)
	}
	records, err := ReadFeed(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Err != nil {
		t.Fatalf("expected one readable record, got %+v", records)
	}
	var p OptOutPredicate
	if err := DecodePredicate(records[0].Statement, &p); err != nil {
		t.Fatal(err)
	}
	if p.Repository != "https://github.com/acme/lib" || !p.RequestedAt.Equal(time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)) {
		t.Fatalf("predicate did not survive the round trip: %+v", p)
	}
}

func TestFeedRoundTripEncrypted(t *testing.T) {
	dir := t.TempDir()
	id := testIdentity(t)
	rec := certificate(t, "regressed")
	if err := WriteFeed(dir, TierMembers, []Statement{rec}, FeedKeys{Recipients: []age.Recipient{id.Recipient()}, Identities: []age.Identity{id}}); err != nil {
		t.Fatal(err)
	}
	names, err := recordFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 1 || !strings.HasSuffix(names[0], ".json.age") {
		t.Fatalf("members records must be written encrypted, got %v", names)
	}
	raw, err := os.ReadFile(filepath.Join(dir, names[0]))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "regressed") {
		t.Fatal("the verdict must not be readable in the encrypted record")
	}
	records, err := ReadFeed(dir, []age.Identity{id})
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Err != nil {
		t.Fatalf("expected one readable record, got %+v", records)
	}
	var p CertificatePredicate
	if err := DecodePredicate(records[0].Statement, &p); err != nil {
		t.Fatal(err)
	}
	if p.Status != "regressed" {
		t.Fatalf("status did not survive the round trip: %+v", p)
	}
}

func TestReadFeedReportsUnreadableRecords(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "optout"), 0o755); err != nil {
		t.Fatal(err)
	}
	good := optOut(t, "https://github.com/acme/lib")
	if err := WriteFeed(dir, TierPublic, []Statement{good}, FeedKeys{}); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"optout/" + strings.Repeat("11", 32) + ".json": "{not json",
		"optout/" + strings.Repeat("22", 32) + ".json": `{"_type":"https://in-toto.io/Statement/v1","subject":[],"predicateType":"https://github.com/alpha-omega-security/scrutineer/interchange/optout/v1","predicate":{}}`,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	records, err := ReadFeed(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 3 {
		t.Fatalf("expected 3 record files, got %d", len(records))
	}
	var ok, failed int
	for _, rec := range records {
		if rec.Err == nil {
			ok++
		} else {
			failed++
		}
	}
	if ok != 1 || failed != 2 {
		t.Fatalf("expected the valid record plus two reported failures, got %d ok / %d failed", ok, failed)
	}
}

func TestReadFeedWithoutIdentityReportsEncryptedRecord(t *testing.T) {
	dir := t.TempDir()
	id := testIdentity(t)
	if err := WriteFeed(dir, TierMembers, []Statement{certificate(t, "bypass")}, FeedKeys{Recipients: []age.Recipient{id.Recipient()}, Identities: []age.Identity{id}}); err != nil {
		t.Fatal(err)
	}
	records, err := ReadFeed(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Err == nil {
		t.Fatalf("an undecryptable record must be reported, not silently skipped: %+v", records)
	}
}

// An unchanged record must keep its exact file on both tiers. On the
// members tier that cannot be a byte comparison: age derives a fresh file
// key per call, so re-encrypting the same record yields different
// ciphertext and every export would rewrite the whole feed.
func TestWriteFeedLeavesUnchangedRecordsUntouched(t *testing.T) {
	id := testIdentity(t)
	cases := []struct {
		name string
		tier Tier
		recs []Statement
		keys FeedKeys
	}{
		{"public", TierPublic, []Statement{optOut(t, "https://github.com/acme/lib")}, FeedKeys{}},
		{"members", TierMembers, []Statement{certificate(t, "bypass")},
			FeedKeys{Recipients: []age.Recipient{id.Recipient()}, Identities: []age.Identity{id}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := WriteFeed(dir, tc.tier, tc.recs, tc.keys); err != nil {
				t.Fatal(err)
			}
			names, err := recordFiles(dir)
			if err != nil {
				t.Fatal(err)
			}
			if len(names) != 1 {
				t.Fatalf("expected 1 record, got %v", names)
			}
			path := filepath.Join(dir, names[0])
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := WriteFeed(dir, tc.tier, tc.recs, tc.keys); err != nil {
				t.Fatal(err)
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(before) != string(after) {
				t.Fatal("re-exporting an unchanged record must not rewrite its file")
			}
		})
	}
}

func TestWriteFeedRewritesAChangedEncryptedRecord(t *testing.T) {
	dir := t.TempDir()
	id := testIdentity(t)
	keys := FeedKeys{Recipients: []age.Recipient{id.Recipient()}, Identities: []age.Identity{id}}
	if err := WriteFeed(dir, TierMembers, []Statement{certificate(t, "bypass")}, keys); err != nil {
		t.Fatal(err)
	}
	// Same advisory, so the same subject digest and therefore the same
	// file: only the verdict changed, and the feed must carry the new one.
	if err := WriteFeed(dir, TierMembers, []Statement{certificate(t, "regressed")}, keys); err != nil {
		t.Fatal(err)
	}
	records, err := ReadFeed(dir, []age.Identity{id})
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Err != nil {
		t.Fatalf("expected one readable record, got %+v", records)
	}
	var p CertificatePredicate
	if err := DecodePredicate(records[0].Statement, &p); err != nil {
		t.Fatal(err)
	}
	if p.Status != "regressed" {
		t.Fatalf("status = %q, want the updated verdict", p.Status)
	}
}

func TestReadFeedReturnsThePublishedBytes(t *testing.T) {
	dir := t.TempDir()
	rec := optOut(t, "https://github.com/acme/lib")
	if err := WriteFeed(dir, TierPublic, []Statement{rec}, FeedKeys{}); err != nil {
		t.Fatal(err)
	}
	names, err := recordFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	onDisk, err := os.ReadFile(filepath.Join(dir, names[0]))
	if err != nil {
		t.Fatal(err)
	}
	records, err := ReadFeed(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Err != nil {
		t.Fatalf("expected one readable record, got %+v", records)
	}
	// Raw is what an importer archives, so it must be the publisher's own
	// bytes rather than a re-encode through this version's structs.
	if strings.TrimSpace(string(onDisk)) != strings.TrimSpace(string(records[0].Raw)) {
		t.Fatalf("Raw is not the published bytes:\n%s\n---\n%s", onDisk, records[0].Raw)
	}
}

func TestWriteFeedIsByteStable(t *testing.T) {
	first, second := t.TempDir(), t.TempDir()
	recs := []Statement{certificate(t, CertificateStatusFixed), optOut(t, "https://github.com/acme/lib")}
	if err := WriteFeed(first, TierPublic, recs, FeedKeys{}); err != nil {
		t.Fatal(err)
	}
	// Reversed input: the feed is addressed by subject, so ordering the
	// records differently must not produce a different feed.
	if err := WriteFeed(second, TierPublic, []Statement{recs[1], recs[0]}, FeedKeys{}); err != nil {
		t.Fatal(err)
	}
	names, err := recordFiles(first)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 2 {
		t.Fatalf("expected 2 records, got %v", names)
	}
	for _, name := range names {
		a, err := os.ReadFile(filepath.Join(first, name))
		if err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(filepath.Join(second, name))
		if err != nil {
			t.Fatal(err)
		}
		if string(a) != string(b) {
			t.Fatalf("%s differs between two exports of the same records", name)
		}
	}
}
