# Interchange and federation

Scrutineer instances (and non-scrutineer tools) can exchange a small set of
federation records without ever exchanging finding bodies. This page documents
the record envelope, the shipped JSON schema, the on-disk record layout, the
salted finding hash, the claim-check endpoint in both directions, and the two
feed tiers with the export and import jobs that keep them in sync. Sigstore
signing for the public tier is future work and not described here.

## Records

Every record is an
[in-toto Statement v1](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md)
envelope: `_type`, `subject`, `predicateType`, `predicate`. The
`predicateType` URI names the record kind:

| Kind | `predicateType` | Meaning |
|------|-----------------|---------|
| certificate | `.../scrutineer/interchange/certificate/v1` | An advisory's advertised fix was re-audited on the named repository and held. `status` is pinned to `fixed`. The local `GET /advisories/{id}/certificate.json` download attests the same audit but in a different, richer format (severity, CVSS, evidence) that is NOT an interchange record and must never be fed into a federation feed. |
| certificate | `.../scrutineer/interchange/certificate/v2` | Same shape, verdict widened to `bypass`, `variant` or `regressed`: the advertised fix did NOT hold. |
| claim | `.../scrutineer/interchange/claim/v1` | The publishing instance holds a finding whose salted hash is the subject digest, plus a contact to coordinate through. |
| optout | `.../scrutineer/interchange/optout/v1` | The repository's maintainer asked federated instances to neither scan the repository nor contact them about it. |
| route | `.../scrutineer/interchange/route/v1` | The validated disclosure route for a repository (email, GHSA URL, registry owner handle, or SECURITY.md URL), so other instances can skip re-deriving it. |

Certificates carry two revisions because the verdict decides which tier may
carry the record, so the split has to be visible in the `predicateType`
alone: a clean certificate says nothing about a live weakness, while a
non-clean one names a repository whose advertised fix does not hold. v1 stays
pinned to the clean case, so a consumer already reading v1 records keeps
handling exactly the values it always has and no coordinated update was
needed to introduce v2. `interchange.NewCertificate` picks the revision from
the verdict, and the schema refuses the crossed pairings in both directions.

The normative contract is
[`internal/interchange/interchange.schema.json`](../internal/interchange/interchange.schema.json),
embedded into the binary; `interchange.Validate` checks a raw record against
it. Predicate schemas set `additionalProperties: false` on purpose: records
never carry finding bodies, severity, CVSS, or health scores, and a record
that smuggles one in fails validation. The envelope itself stays open so
spec-legal in-toto extensions (subject `uri`, extra digest algorithms, ...)
from non-scrutineer producers validate fine.

## Record layout

A set of records is stored as a directory a git remote can serve, one file
per record at `<kind>/<subject-digest>.json`, or
`<kind>/<subject-digest>.json.age` when the set is encrypted. Deriving the
name from the record itself means an unchanged record keeps its own file, so
a commit over such a directory diffs only what actually changed, and a record
that stops applying is deleted rather than left beside its replacement. Files
that are not records (`README`, `LICENSE`, `.git`) are never touched: only
the kind directories are rewritten.

An encrypted record is left alone by comparing plaintexts, not bytes: age
derives a fresh file key per call, so re-encrypting an unchanged record
produces different ciphertext every time and a byte comparison would rewrite
everything on every pass. `interchange.WriteFeed` therefore refuses to write
an encrypted set without an identity as well as recipients: without one it
cannot read back what it published.

`interchange.Tier` names which kinds a set may carry, enforced at write time
so a misrouted record fails rather than leaking: the public tier takes
opt-outs, routes and clean `certificate/v1` records, the members tier takes
`certificate/v2` only, and claims are on neither, since publishing a hash set
would hand a member something to enumerate offline.

## The salted finding hash

Federation members share a secret salt out of band. A finding's federation
identifier is:

```
sha256(salt NUL repo NUL location NUL cwe)   hex-encoded
```

joined with NUL (`0x00`) bytes, where:

- `repo` is the repository URL lowercased, with any trailing `/` and `.git`
  stripped;
- `location` is the repo-root-relative file path: first line only, positional
  suffix stripped (`:42`, `:42:7`, and the `:10-20` range form), backslashes
  normalised to `/`, the scan `sub_path` prepended, lowercased;
- `cwe` is the finding's comma-joined CWE list canonicalised: elements
  trimmed, uppercased, empties dropped, sorted, deduplicated, joined with a
  bare comma (empty stays empty).

Two instances holding the same vulnerability derive the same hash without
coordinating; without the salt the hash reveals nothing enumerable. The
canonicalisation is a wire contract implemented once in
`internal/interchange` and deliberately independent from the internal
fingerprint helpers, so an internal normalisation tweak cannot silently
change published hashes.

## Claim-check endpoint

Before reporting a finding upstream, a federation peer can ask whether this
instance already holds it:

```
POST /claim-check
{"hash": "<64 hex chars>"}
```

Responses:

- `200 {"match": true, "contact": "<federation_contact>"}` -- a non-rejected,
  non-duplicate finding with that hash exists here; coordinate through the
  contact before reporting.
- `200 {"match": false}` -- no such finding; a miss reveals nothing else.
- `400` -- malformed JSON or hash.
- `404` -- `federation_salt` is not configured, or the method is not POST; a
  non-federated instance is indistinguishable from one without the endpoint.

The hash set is cached for up to a minute so request floods cost map lookups
rather than a findings-table scan each time; a match may therefore lag a
freshly written finding by that long.

## Asking peers before reporting

The other direction of the same endpoint: before this instance reports a
finding, every peer in `federation_peers` is asked with that finding's salted
hash. A peer that answers with a match means two instances are about to
report the same issue separately, so the attempt is refused, the matching
peers and their contacts are recorded on the finding
(`federation_claim_contacts`), and the finding page names them. A recorded
claim *is* the acknowledgement: the analyst has seen who to coordinate with,
so the next attempt goes through and the record is cleared once the finding
reaches `reported`.

Both ways of reporting are covered, and each is checked before any outreach
happens rather than after:

- the analyst marking a finding `reported` by hand, gated in the status
  handler;
- `report-upstream` and `public-issue`, gated when the skill is *enqueued*.
  Those two file with the maintainer (or open the public issue) and only then
  PATCH the status themselves, so gating their status write would leave the
  outreach done and the finding stuck.

The scan-scoped `PATCH /api/v1/findings/{id}` is deliberately not gated: by
the time a skill reaches it the report is already filed, and the enqueue gate
above is what stops that skill from starting.

A peer that errors, times out, or answers `404` is not a claim: a peer being
down must not stop an analyst from reporting. The whole round is bounded by
five seconds because it sits inside a click. A *local* failure is different
and refuses the attempt: the hash needs this instance's own repository row,
and answering "nobody claims it" because the database was busy would silently
open the gate.

The client refuses redirects. A claim-check answer is a boolean and a
contact, so it never legitimately redirects, and following one would let a
peer aim this instance's own POST anywhere: a `307` to
`http://127.0.0.1:8080/repositories/1/delete` would replay the request
against the admin UI, whose only authorization is the loopback `Host` check
and a `Sec-Fetch-Site` check that a redirected Go request satisfies.

## Feeds

Each tier is a git remote serving one record set in the layout above:

| Tier | Remote | Carries |
|------|--------|---------|
| public | `federation_public_feed`, plain git, anyone may clone | `optout`, `route`, and clean `certificate/v1` |
| members | `federation_members_feed`, every record age-encrypted to `recipients_file` | `certificate/v2` only |

The split is about what a record discloses. An opt-out, a disclosure route
and a clean certificate say nothing about a live weakness. A `certificate/v2`
says an advisory's advertised fix does not hold on a named repository, which
is exploitable information, so those records are encrypted with the same age
recipients as [encrypted sharing](encrypted-sharing.md).

Two exclusions apply to every record: an opted-out repository is withdrawn
from the `route` and `certificate` records as well as from scanning, since
republishing a maintainer's disclosure route works against the request not to
contact them, and a local (`file://`) repository is never published at all,
because its URL is a path on the operator's own filesystem. A disclosure
channel with no `disclosure_channel_at` is skipped too: `verified_at` has to
be a timestamp that only moves when the channel does, or every export would
rewrite the whole feed.

### Export and import jobs

Both run hourly from one goroutine, starting with an immediate pass so a
freshly configured feed populates without waiting out a tick. The job is
dormant when no feed is configured.

The export syncs each tier's working clone under `<data>/work/feeds/<tier>`,
hard-resetting to the branch's remote-tracking ref so local commits that
never landed are discarded rather than accumulating into a permanent push
conflict, rewrites the clone to exactly the records this instance currently
stands behind, and commits and pushes only if that changed something. An
unchanged feed costs a fetch. A clone that died partway leaves a destination
git refuses, so the leftovers are cleared before a re-clone rather than
wedging every later tick.

The import clones each remote in `federation_import_feeds` read-only under
`<data>/work/feeds/import/<digest>` and archives every record into
`interchange_records` exactly as the peer published it, keyed by
`(feed, predicate_type, subject_digest)` so two peers disagreeing about the
same subject each keep their row. A record that fails to decrypt, validate
or decode is logged and skipped: one bad file from a peer must not cost the
rest of the feed.

Two kinds also apply locally, and only when the peer's published bytes
actually changed: an unchanged record has already had its effect, and
re-applying it hourly would silently reinstate what an operator deliberately
cleared.

- an `optout` sets `federation_opt_out_at` on the matching repository
  whichever peer sent it, since refusing to scan is the conservative
  direction;
- a `route` fills `disclosure_channel` only when this instance has none and
  the repository has not opted out, suffixed with the peer feed so an analyst
  can tell a peer's hint from an address the `maintainers` skill read out of
  a verified SECURITY.md.

The repository row behind each decision is re-read per record rather than
taken from the index: opt-outs sort before routes, so an opt-out applied
earlier in the same pass has already changed what the route decision turns
on. Repositories are matched by the same canonical URL the records carry
(lowercased, trailing `/` and `.git` stripped), which is why the lookup is a
map built in Go rather than a SQL join.

## Configuration

```yaml
federation_salt: "shared secret distributed out of band"
federation_contact: "security@example.com"
federation_public_feed: "git@github.com:example/scrutineer-public-feed.git"
federation_members_feed: "git@github.com:example/scrutineer-members-feed.git"
federation_import_feeds:
  - "https://github.com/peer/scrutineer-public-feed.git"
federation_peers:
  - "https://peer.example.com"
```

Everything defaults to empty, and each part switches on independently: an
empty salt disables the claim-check endpoint in both directions, while the
feeds are driven by
their own remotes and run without a salt, since no feed record carries a
finding hash. Startup refuses a salt without a contact. The salt is
deliberately config-file only (no CLI flag): a secret in argv leaks via `ps`
and shell history. The contact may also be set with `-federation-contact`,
and the two feed remotes with `-federation-public-feed` /
`-federation-members-feed`. The import list is config-file only: a
repeatable flag would duplicate what a YAML sequence already expresses.

Startup also refuses `federation_members_feed` without both
`recipients_file` and `identity_file`, `federation_peers` without
`federation_salt` (the hash sent to a peer could never match theirs), the two
tiers sharing one git remote
(each would prune what the other publishes), any peer that is not an `http(s)` URL with a host
and nothing else, and any feed remote or peer carrying credentials: those
strings reach the job's error messages and log fields, so a token in one
would end up in the logs. Configure a git credential helper
on the host instead.

Feed remotes are pushed with the ambient git credentials and
`GIT_TERMINAL_PROMPT=0`, so a remote whose credentials are missing fails the
job fast instead of blocking it on a prompt nobody can answer.

Like the rest of the web surface, `/claim-check` sits behind the loopback
Host check (see [threatmodel.md](../threatmodel.md)). Exposing it to peers is
a deployment decision: front it with a reverse proxy that forwards only
`POST /claim-check` and sets `Host: 127.0.0.1:8080`.
