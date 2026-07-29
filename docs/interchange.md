# Interchange and federation

Scrutineer instances (and non-scrutineer tools) can exchange a small set of
federation records without ever exchanging finding bodies. This page documents
the interchange format foundations: the record envelope, the shipped JSON
schema, the on-disk record layout, the salted finding hash, and the
claim-check endpoint. The feeds themselves (public and members-only git
repositories), the export/import jobs, and Sigstore signing are future work
and not described here.

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

Keeping a record's existing ciphertext means access to it is frozen at the
recipient set it was encrypted to, so an encrypted directory also holds a
`.recipients` file: the sha256 of that set, its keys trimmed, lowercased,
sorted, deduplicated and joined with newlines. Nothing in an age file names
its own recipients, so this digest is the only way to notice a membership
change; when it differs from the set in play every record is re-encrypted,
which is what lets a member added to the feed read the records that did not
happen to change since they joined, and takes those same records away from a
member removed. It is written only after every record carries the new set, so
an interrupted rotation is retried rather than recorded as complete. A
recipient whose key cannot be rendered as text is refused outright, since its
removal could not be detected. Only age's own X25519 recipient can render one;
an SSH recipient, which is the documented default, keeps no handle on its key,
so the key is captured where the recipients file is parsed and carried with the
recipient. Its canonical `authorized_keys` form, at that: a trailing comment is
not part of the key and editing one must not read as a new member set.

A directory served this way is a checkout whose contents a peer controls, so
a symlink on a managed path (a kind directory, or a file where a record
belongs) fails the operation instead of being followed: writing and pruning
stay under the directory itself. A record-shaped path that is not a regular
file is still listed as a record, so reading reports it as a failed record
rather than omitting it silently, and an export prunes it, unlinking the entry
itself and never what it points at.

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

## Configuration

```yaml
federation_salt: "shared secret distributed out of band"
federation_contact: "security@example.com"
```

Both default to empty; an empty salt disables federation, and startup
refuses a salt without a contact. The salt is deliberately config-file only
(no CLI flag): a secret in argv leaks via `ps` and shell history. The
contact may also be set with `-federation-contact`.

Like the rest of the web surface, `/claim-check` sits behind the loopback
Host check (see [threatmodel.md](../threatmodel.md)). Exposing it to peers is
a deployment decision: front it with a reverse proxy that forwards only
`POST /claim-check` and sets `Host: 127.0.0.1:8080`.
