package interchange

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"filippo.io/age"
	"filippo.io/age/armor"
)

// A feed is a directory a git remote serves, holding one file per record
// at <kind>/<subject-digest>.json (.json.age on the encrypted members
// tier). Deriving the name from the record itself means an unchanged record
// keeps its own file, so a feed commit diffs only what actually changed,
// and a record that stops applying disappears instead of accumulating
// alongside its replacement.
const (
	recordExt          = ".json"
	encryptedRecordExt = ".json.age"
	feedDirPerm        = 0o755
	recordPerm         = 0o644
)

// RecordFile returns the feed-relative path for a record: its kind
// directory plus the subject digest. Records are addressed by subject, so
// the same opt-out or certificate re-exported after a refresh replaces its
// own file rather than adding a second one.
func RecordFile(s Statement, encrypted bool) (string, error) {
	kind := Kind(s.PredicateType)
	if kind == "" {
		return "", fmt.Errorf("unknown predicate type %q", s.PredicateType)
	}
	if len(s.Subject) == 0 || s.Subject[0].Digest["sha256"] == "" {
		return "", errors.New("record has no subject sha256 digest")
	}
	ext := recordExt
	if encrypted {
		ext = encryptedRecordExt
	}
	return filepath.Join(kind, s.Subject[0].Digest["sha256"]+ext), nil
}

// FeedKeys are the age keys an encrypted tier needs. Recipients encrypt
// what it publishes; Identities read back what is already on the feed,
// which is what lets an unchanged record keep its existing ciphertext.
// Without them every export would re-encrypt every record under a fresh
// ephemeral key, so the whole feed would look changed on every tick.
type FeedKeys struct {
	Recipients []age.Recipient
	Identities []age.Identity
}

// WriteFeed makes dir hold exactly recs. Every record is validated against
// the shipped schema and refused when the tier does not carry its kind, so
// a misrouted record fails the export rather than leaking a live weakness
// onto a public remote. Record files already in dir but absent from recs
// are removed; everything else, .git included, is left alone. A record
// whose file already holds the same content is left byte-for-byte alone, so
// an unchanged feed produces no diff at all.
//
// The members tier is encrypted to keys.Recipients and refuses to write
// without them: writing those records in the clear is the one failure this
// whole two-tier split exists to prevent. The public tier is a plain git
// repository by definition, so it ignores keys entirely.
func WriteFeed(dir string, tier Tier, recs []Statement, keys FeedKeys) error {
	encrypted := tier == TierMembers
	if encrypted && len(keys.Recipients) == 0 {
		return fmt.Errorf("feed %s: age recipients required to publish encrypted records", tier)
	}
	// Refused rather than degraded: without an identity the writer cannot
	// tell an unchanged record from a changed one, so every export would
	// re-encrypt the whole feed under a fresh ephemeral key and push a full
	// rewrite forever. Silently churning is worse than not publishing.
	if encrypted && len(keys.Identities) == 0 {
		return fmt.Errorf("feed %s: an age identity is required to read back what was published", tier)
	}
	wanted := make(map[string][]byte, len(recs))
	for _, rec := range recs {
		if !tier.Carries(rec.PredicateType) {
			return fmt.Errorf("feed %s: refusing record of type %s", tier, rec.PredicateType)
		}
		raw, err := json.MarshalIndent(rec, "", "  ")
		if err != nil {
			return fmt.Errorf("feed %s: encode record: %w", tier, err)
		}
		if err := Validate(raw); err != nil {
			return fmt.Errorf("feed %s: invalid record: %w", tier, err)
		}
		name, err := RecordFile(rec, encrypted)
		if err != nil {
			return fmt.Errorf("feed %s: %w", tier, err)
		}
		wanted[name] = raw
	}
	stale, err := recordFiles(dir)
	if err != nil {
		return err
	}
	for _, name := range stale {
		if _, keep := wanted[name]; keep {
			continue
		}
		if err := os.Remove(filepath.Join(dir, name)); err != nil {
			return fmt.Errorf("feed %s: remove %s: %w", tier, name, err)
		}
	}
	for _, name := range slices.Sorted(maps.Keys(wanted)) {
		if err := writeRecord(filepath.Join(dir, name), wanted[name], encrypted, keys); err != nil {
			return fmt.Errorf("feed %s: write %s: %w", tier, name, err)
		}
	}
	return nil
}

// writeRecord writes one record file, leaving it untouched when it already
// holds this exact record. On an encrypted tier that check has to compare
// plaintexts: age derives a fresh file key per call, so identical records
// never encrypt to identical bytes and a straight byte comparison would
// rewrite everything every time.
func writeRecord(path string, raw []byte, encrypted bool, keys FeedKeys) error {
	existing, readErr := os.ReadFile(path)
	if !encrypted {
		body := slices.Concat(raw, []byte("\n"))
		if readErr == nil && bytes.Equal(existing, body) {
			return nil
		}
		return writeFile(path, body)
	}
	if readErr == nil {
		if plain, err := decryptRecord(existing, keys.Identities); err == nil && bytes.Equal(plain, raw) {
			return nil
		}
	}
	body, err := encryptRecord(raw, keys.Recipients)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}
	return writeFile(path, body)
}

func writeFile(path string, body []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), feedDirPerm); err != nil {
		return err
	}
	return os.WriteFile(path, body, recordPerm)
}

// FeedRecord is one record file read off a feed. Err is set instead of
// Statement when the file could not be read, decrypted, validated or
// decoded, so a single malformed record from a peer is reported without
// aborting the import of the rest. Raw is the validated record exactly as
// the peer published it, decrypted but otherwise untouched, so an importer
// can archive the publisher's own bytes rather than a re-encode through
// this version's structs.
type FeedRecord struct {
	Path      string
	Statement Statement
	Raw       []byte
	Err       error
}

// ReadFeed reads every record file under dir in path order. Encrypted
// records need identities; without a matching one the record comes back
// with Err set rather than silently skipped, since a members feed this
// instance cannot decrypt is a configuration problem the operator wants
// to see.
func ReadFeed(dir string, identities []age.Identity) ([]FeedRecord, error) {
	names, err := recordFiles(dir)
	if err != nil {
		return nil, err
	}
	out := make([]FeedRecord, 0, len(names))
	for _, name := range names {
		rec := FeedRecord{Path: name}
		if rec.Statement, rec.Raw, rec.Err = readRecord(filepath.Join(dir, name), identities); rec.Err != nil {
			rec.Statement, rec.Raw = Statement{}, nil
		}
		out = append(out, rec)
	}
	return out, nil
}

func readRecord(path string, identities []age.Identity) (Statement, []byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Statement{}, nil, err
	}
	if strings.HasSuffix(path, encryptedRecordExt) {
		if len(identities) == 0 {
			return Statement{}, nil, errors.New("encrypted record but no age identity configured")
		}
		if raw, err = decryptRecord(raw, identities); err != nil {
			return Statement{}, nil, fmt.Errorf("decrypt: %w", err)
		}
	}
	if err := Validate(raw); err != nil {
		return Statement{}, nil, fmt.Errorf("invalid record: %w", err)
	}
	var s Statement
	if err := json.Unmarshal(raw, &s); err != nil {
		return Statement{}, nil, fmt.Errorf("decode record: %w", err)
	}
	return s, raw, nil
}

// recordFiles lists the feed-relative record files under dir, sorted. Only
// the known kind directories are walked, so a feed repository's README,
// LICENSE and .git stay untouched by both the writer's pruning and the
// reader.
func recordFiles(dir string) ([]string, error) {
	var out []string
	for _, kind := range sortedKinds() {
		entries, err := os.ReadDir(filepath.Join(dir, kind))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			if name := e.Name(); strings.HasSuffix(name, recordExt) || strings.HasSuffix(name, encryptedRecordExt) {
				out = append(out, filepath.Join(kind, name))
			}
		}
	}
	slices.Sort(out)
	return out, nil
}

func encryptRecord(raw []byte, recipients []age.Recipient) ([]byte, error) {
	var buf bytes.Buffer
	armorW := armor.NewWriter(&buf)
	w, err := age.Encrypt(armorW, recipients...)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(raw); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	if err := armorW.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func decryptRecord(raw []byte, identities []age.Identity) ([]byte, error) {
	r, err := age.Decrypt(armor.NewReader(bytes.NewReader(raw)), identities...)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

func sortedKinds() []string {
	seen := make(map[string]struct{}, len(recordKinds))
	for _, kind := range recordKinds {
		seen[kind] = struct{}{}
	}
	return slices.Sorted(maps.Keys(seen))
}
