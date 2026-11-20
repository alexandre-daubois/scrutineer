# Scanning repositories

Click **Add repository** in the sidebar, paste a git HTTPS URL, and scrutineer enqueues the `triage` skill. To scan a maintained branch instead of the default, fill the **Branch** field (it suggests the remote's branches as you type and also accepts a tag or commit), or append a `/tree/<branch>` suffix to the URL; the suffix also works one-per-line when bulk-importing. Triage then enqueues the rest of the pipeline: independent skills run in parallel, and the deep-dive audits start once `threat-model` completes. Open the repo page and switch to the Scans tab to watch progress, or wait for the Findings tab to fill in.

The `triage` skill selects the scan set for the repository. See [skills.md](skills.md#bundled-skills) for the bundled skills and how to change the pipeline, and [diff-based-rescans.md](diff-based-rescans.md) for scanning changes since an earlier scan.

## Monorepos

To scan one package inside a monorepo, append `#<sub/dir>` to the URL -- e.g. `https://github.com/rails/rails#activesupport` (or paste a `.../tree/<branch>/<sub/dir>` URL). Scrutineer scopes the whole pipeline to that sub-folder and gives the sub-package its own page, findings, packages, advisories, disclosure channel, and export, instead of rolling every package up under the repository. By default a sub-package scan is confined to its own sub-folder (siblings pruned, `.git` kept), widening to the whole repository automatically if the sub-package cannot resolve its dependencies in isolation; set `subproject_scope: soft` to always scan against the whole tree, or `monorepo_attribution: false` to keep registry data repo-wide (see [`scrutineer.sample.yaml`](../scrutineer.sample.yaml)). The `subprojects` skill also auto-discovers a monorepo's sub-packages, so you can scan them from the repo page without composing URLs by hand. Findings, packages, advisories, the disclosure channel, and export are attributed per sub-package; dependents, maintainers, posture, and health stay repo-wide. There is no per-sub-package schedule -- to re-scan sub-packages on a cadence, drive the local API from cron or a systemd timer (see [`scripts/rescan-subprojects.sh`](../scripts/rescan-subprojects.sh)).

## Importing an organisation

To onboard a whole GitHub org at once, open **Add multiple** → **Import a whole org** and enter the org (or user) login. Scrutineer fetches every repository and queues each one with the default scan set, skipping forks, archived repos (unless you opt in), and any URL already in the database. Set `GITHUB_TOKEN` to raise GitHub's unauthenticated rate limit when importing large orgs.

## Local directories

You can also scan a directory on disk, useful before pushing, or for code not hosted on a git forge. Paste an absolute path (`/path/to/project`) in the same **Add repository** field. Scrutineer copies the directory into a per-scan workspace and runs the default skill set; skills that need a forge URL or ecosyste.ms enrichment (`advisories`, `exposure`, `fork`, `maintainers`, `metadata`, `packages`, `public-issue`, `report-upstream`) are skipped automatically. Symlinks are recreated as-is rather than dereferenced during the copy; in container mode their targets then resolve inside the container, so host files reached only through such a link are not visible to skills. Under `--no-container`, and for the skills listed in `host_skills`, the kernel dereferences them normally, so only point scrutineer at trees you trust.

## Investigating a report

To check a research lead, choose **Investigate a report** in the sidebar, enter the repository URL and paste the report. An optional branch, tag or commit selects the revision to check. This queues one focused investigation without the default scan pipeline. The scan retains the submitted text and records an assessment of each claim, with zero or more findings. Reproduced behaviour with unestablished security impact remains inconclusive; new High/Critical findings enter the existing revalidation workflow.

## Scan results

- **Structured findings** -- vulnerability reports parsed into a database with severity, CWE, location (linked to source), affected versions, and a six-step analysis trace
- **Threat model view** -- the project's security contract (components, entry-point trust table, properties provided and disclaimed, known non-findings) rendered from the `threat-model` scan, falling back to the deep-dive's boundaries and sink inventory on older repositories
- **Dependency exploration** -- dependency and dependent tables with one-click import to scan any package's source repository
- **Package registry data** -- downloads, dependents, versions, and registry links for every published package
- **Known advisories** -- existing CVEs and security advisories pulled automatically
- **Maintainer identification** -- model-backed skill combining commit history, issue/PR activity, and registry ownership to identify who to contact for disclosure
- **CWE catalogue** -- embedded MITRE CWE data with tooltips on finding tables and full descriptions on finding pages
- **Reachability analysis** -- trace sinks found in dependencies through application code to see which are actually reachable
- **Rescan dedup** -- findings carry a content fingerprint so re-running a scan updates existing rows instead of creating duplicates; same-fingerprint hits within one scan collapse to a single finding with a `+N` expandable location list, and findings that stop appearing are marked "not seen" with a miss count

## Trialling a candidate configuration

With `scan_experiments` configured (see [configuration.md](configuration.md#candidate-experiments)), the Run skill menu on the repository page gains an experiment selector. Picking one before a findings skill snapshots the experiment's entry on the ordinary scan, runs that scan as usual and, once it finalizes, queues a candidate scan with the snapshot's model, effort or skill on the commit the ordinary scan resolved, with the same sub-path, scope, runner profile, egress policy, cost cap and rescan mode. Editing or removing the entry afterwards does not change the candidate. Experiments only run on remote repositories, because a local directory is copied as a working tree and has no commit the candidate can be pinned to, and only when the candidate's skill runs in a container, because a host process (`--no-container` or `host_skills`) could read the operator token and bypass the candidate's callback restrictions. An experiment `skill` must stage the same files as the ordinary skill (same `paths`, `ignore_paths`, submodule and history settings). The candidate fails rather than running on different inputs when its commit or scope differ from the ordinary scan's, or when the scan config, threat model and analyst feedback staged for it differ from what was staged for the ordinary scan's own run (which also catches feedback added, or a promotion retired, in between, and accepts a scan config the ordinary scan itself finished under after a resume). A candidate that cannot start at all, for instance because its model is no longer configured, shows up as a failed candidate run naming the reason. It never widens a hard sub-path scope to the whole repository on its own, so a dependency resolution failure fails it instead. A candidate starts once the ordinary scan has recorded its findings, so none starts when it is cancelled or fails before that, while one still starts after a skill's `fail_on` threshold marks it failed. Retrying the ordinary scan keeps the snapshot while its model and skill still resolve, so a successful retry starts its own candidate. Retrying a candidate reruns its snapshot and is refused once its model is no longer configured.

A candidate never touches the repository's findings. Its report and streamed findings land in `candidate_observations`, it starts no revalidate, verify, dedup, focus-area, reflection or disclosure work, and its callback token is refused every write except streaming into its own observations and validating its own report. Other scans cannot list or read it through the skill API, and it never counts as the repository's latest scan, a prerequisite or a diff baseline.

The comparison page (`/scans/{id}/experiment`, linked from both scan pages) lists the ordinary scan and every candidate run with status, commit, duration, tokens and cost, then the selected run's findings by fingerprint: reported by both, ordinary only and candidate only, each with the matching repository finding and its status. Each candidate observation takes an assessment (`confirmed`, `false_positive`, `unsure`), an optional analyst time in minutes and a note. The summary counts additional confirmed vulnerabilities (confirmed candidate-only observations that match no repository finding), confirmed candidate-only observations the repository already knew from an earlier scan, vulnerabilities the candidate missed (baseline-only findings an analyst triaged as real), candidate false positives, baseline false positives (baseline findings the analyst rejected, out of those triaged past new), assessed observations, analyst time, failed candidate runs and incomplete ones (cancelled, cost-capped or out of turns), and the cost of every candidate run, retries included, beside the ordinary scan's. A count that depends on assessments reads as unavailable until one is recorded and says how many observations it rests on while only some are assessed, the baseline false positives read as unavailable until a baseline finding is triaged, analyst time says how many observations it covers, and the baseline's analyst time reads as unavailable because Scrutineer records none on repository findings. Each row expands to the CWE, confidence, reachability, rating and evidence each side reported. A cost, duration, token count or analyst time that was never measured reads as unavailable, never as zero. A configuration reaches ordinary scans only through an explicit decision, which the form never preselects: rejecting records it, and adopting, after a confirmation that names the change, records it and sets the experiment's model on the ordinary scan's skill when the experiment changed only the model. A changed effort is a global setting and a changed skill is another skill, so adopting leaves those to the operator and the recorded decision says so.

## Navigating the UI

Every index page has a search box plus filter and sort dropdowns; the specifics vary by page. The sidebar groups its pages under Work, Inventory, Insights and Configuration, in this order:

- **Findings** -- every vulnerability across all repos. A finding page shows where the finding stands on its lifecycle, its scoring fields and the next step, then groups the rest into Analysis (the six-step analysis: trace, boundary, validation, prior art, reach, rating, plus observations and verification history), Remediation, Disclosure (draft, fields, communications log, references) and Activity (notes, reviews, labels, change history, chat) tabs.
- **Scans** -- every scan that has run. Queued scans can be paused/resumed, running or queued scans can be cancelled and failed ones retried.
- **Audit** -- random sample of recent low and false-positive verdicts for spot-checking the cheap-classifier output. Each row records the analyst's agreement-or-overturn verdict, and a small dashboard shows the running overturn rate.
- **Repositories** -- your scanned repos with language, last-scan status, and finding counts. Choose Priority in the sort menu to rank dependencies by local consumer counts, with Needs inventory, Refresh inventory and Review signals queues. Click into one for tabs covering Summary, Findings, Threat Model, Compliance, Packages, Dependencies, Dependents, Advisories, Maintainers, Data, Scans, and Chat, plus "Export report" in the header's More menu for a markdown rollup.
- **Organizations** -- repos, findings, and maintainers grouped by owning org, with per-org markdown exports.
- **Packages** -- registry entries discovered across all repos.
- **SBOMs** -- uploaded CycloneDX/SPDX documents. Each component is resolved to a source repository and can be imported for scanning.
- **Advisories** -- known CVEs and security advisories pulled for any scanned package.
- **Maintainers** -- people identified as maintainers, with their linked repos and findings.
- **Reporting** -- corpus-wide activity over a rolling window (24 hours, 7 days, 30 days, or all time) with a minimum-severity floor on findings: repositories scanned, runs started and completed, findings, a per-day breakdown, and the per-scan cost and token averages beside their all-time figures. Downloadable as CSV or JSON; JSON exports pulled from several discrete scanner instances can be combined into one corpus-wide report with `go run ./scripts/merge-reports a/report.json b/report.json`; see [docs/reporting.md](reporting.md).
- **Usage** -- token and cost totals across all scans, broken down by skill.
- **Skills** -- installed skills from disk and from the UI; view, edit, or run any of them.
- **Settings** -- theme, colour scheme, model tiers, runner concurrency (restarts the runner to apply, cancelling in-flight scans) and default turn cap (applied to the next scan), plus system stats (record counts, DB size, paths). The chat pool is sized at half the concurrency the server started with and is not resized here, so a change only takes effect for chat after a restart.

Scan logs and status changes stream through SSE. The Scans page, repositories list and a repository's Scans tab refresh their tables when scans start, finish, are cancelled, paused, resumed or queued, while preserving scroll position, filters and sort order. Elapsed times update in the browser. Settings also provides six colour themes and a light/dark/system toggle.

## Finding workflow

Each finding from the `security-deep-dive` skill starts at **new** and moves through a guided workflow:

1. **new** -- just identified. High/Critical from `security-deep-dive` and every imported finding auto-enqueue a `revalidate` pass first, which records `true_positive` / `false_positive` / `already_fixed` / `uncertain` on the finding. Every true positive chains into the release-build `critic`; High/Critical true positives also chain into `verify`. Outside that path: click "Run verification" to start independent confirmation using model tokens, "Mark triaged" if you have already verified it independently, or "Reject"
2. **enriched** -- verification confirmed it, or revalidation classed it as a true positive. Review and click "Mark triaged" to save your decision
3. **triaged** -- confirmed real. Review the critic's release-build assessment, then click "Draft disclosure" (a model scan) to generate the draft. An exact `NON_VIABLE` assessment blocks private disclosure, public issues, and upstream reporting; `VIABLE`, `SAMPLE_OR_TEST`, `CONDITIONAL_VIABLE`, and unassessed findings remain analyst decisions
4. **ready** -- draft prepared. Run the `report-upstream` skill to file it via GitHub PVR (github.com only, requires `gh` auth), run `public-issue` for reviewed low-severity hardening findings that are safe to file publicly, or click "Mark as reported" after sending it yourself. When upstream has no PVR, follow the runbook in [docs/disclosure-fallback.md](disclosure-fallback.md): route to a CNA when `cna-match` names one, otherwise contact the channel `maintainers` returned. With `federation_peers` configured, every route out of this state (the button, the `report-upstream` and `public-issue` skills, and the VINCE submission) first asks each peer whether it already holds the same finding and, on a match, names their contact so you coordinate before proceeding (see [docs/interchange.md](interchange.md))
5. **reported** -- sent to maintainer. Click "Acknowledged" when they respond
6. **acknowledged** -- maintainer working on fix. Click "Mark fixed" when it ships
7. **fixed** -- patch available. Click "Mark published" to issue the advisory
8. **published** -- done

When upstream has already fixed the issue, click "Fixed upstream" from any status before **acknowledged** to jump straight to **fixed** without generating or sending a report.

- **Exploited-in-the-wild flag** -- analyst-only `yes`/`no` field on findings with free-text evidence, surfaced on the finding page, in the OSV `database_specific` block, in CSAF audit notes, and in markdown report exports
- **Breaking-change classifier** -- the `breaking-change` skill runs over a suggested-fix diff plus the top dependents, recording `breaking` / `non_breaking` / `unknown` with a rationale and the list of affected dependents
- **Mitigation guidance** -- the `mitigate` skill drafts short-term workarounds and an optional semgrep rule per finding, separate from the code fix
- **CVSS v3.1 and v4.0** -- both vectors stored side by side with derived scores; analyst form, OSV/CSAF exports, and the `disclose` skill all carry both forward, with the v4 metric set kept distinct from v3
- **Release watch** -- the `release-watch` skill closes the gap between fix-landed and fix-shipped: once a finding reaches `fixed`, the skill polls upstream releases and records the release tag, URL, and timestamp when it appears
- **CNA matching** -- identify the CVE Numbering Authority whose scope covers a repo so disclosures go to the right contact

A PVR report is hard to unsend; before pointing this at an external repository, run it once end-to-end against a repository you control with PVR enabled to confirm the body shape and patch attachment land the way you expect.

Each finding page has a notes section for recording triage reasoning and communication history.

### Federation opt-out

The repository page carries a Federation opt-out control: recording one cancels the repository's queued, running and paused scans, then refuses every new scan on it, including scheduled runs and automatic follow-ups. It also withdraws the repository from the interchange feeds, and, when the public feed is configured, publishes the request so other federated instances honour it too; an opt-out arriving on a peer feed sets it here the same way. See [docs/interchange.md](interchange.md).

### Chat

The Chat tab on a repository or a finding opens a read-only conversation with the agent about that code: it works from a copy of the clone plus a snapshot of the findings, and is restricted to reading and searching, so it can explain and cross-check but never modify anything. Each conversation keeps its own working copy on disk, so delete the ones you are done with from the conversation page to reclaim the space.

### Patches and re-attack

A `patch` run whose diff survives the applicability gate (the diff parses, targets files that exist, touches the flagged file, and passes `git apply --check`) creates an immutable numbered remediation attempt and updates the finding's `suggested_fix` projection. The current diff is downloadable from the finding page as a `.patch` file and included in markdown report exports. To iterate on your own edits, push them to a branch, scan that branch, then run `patch` against the new scan. `Re-attack patch` checks out an attempt's exact base commit, applies its exact diff, and independently exercises at least three distinct root-cause variants plus a benign control. Only a complete `failed_to_bypass` result derives `verified_secure`; a same-class, same-sink bypass is retained as evidence and staged for later patch attempts, while missing or inconsistent evidence remains `verification_incomplete`. Earlier attempts and bypass evidence remain immutable.

## Exploring dependencies

The Dependencies tab on a repo groups packages by name and shows all manifest files where each appears. It shows runtime dependencies by default, with a toggle for test/build/dev rows. The import button (arrow icon) next to a dependency resolves it to a repository URL via packages.ecosyste.ms and queues the full pipeline for it. Dependencies you've already imported show a link icon instead.

The same applies to the Dependents tab -- you can import any dependent's repository with one click.

## Imports and exports

- **SBOM import** -- upload a CycloneDX or SPDX document, resolve each component to a source repository, and queue scans automatically
- **Finding import** -- POST SARIF, CSV, markdown, or minimal-JSON findings from external scanners and pentest reports into the same workflow as native scans, with fingerprint dedup against re-imports
- **OSS-CRS import** -- POST an `oss-crs archive` tarball to import a run's SARIF bug candidates into one scan and retain its PoV inputs, patches and report bundles as downloadable evidence, attached to a finding only when the candidate names them, with an attached PoV found at the finding's revision becoming its captured PoC. See [docs/import.md](import.md#oss-crs-runs)
- **Free-form ingest** -- when the format sniffer in `/api/v1/import` cannot place a payload, the `ingest` skill normalises it against the source checkout (resolving locations) before it enters the findings table
- **CSAF export** -- download any finding as a schema-validated CSAF 2.0 advisory document
- **OSV export** -- download any finding as a schema-validated OSV record, aligned with the OSS-SIRT advisory template (credits, CWE IDs, withdrawn, SEMVER ranges, CVSS v3 + v4 severity entries)
- **JSONL export** -- stream all findings or scans as line-delimited JSON for ingestion elsewhere
- **Markdown report export** -- download a single consolidated `report.md` per repository or organisation
- **Disclosure bundle** -- download `bundle.tar.gz` per finding: OSV, CSAF, markdown report, patch.diff, a runnable `poc/` directory extracted from the finding's Validation step, and a manifest naming the contents; ready to hand to a coordinator or attach to a private email when filing outside GitHub PVR
- **CERT/CC VINCE submission** -- map a reviewed disclosure into VINCE's authenticated vulnerability-report form, review every field and attachment, then send one multipart request and record the returned VRF ID. The action requires a config-file API key; see [docs/disclosure-fallback.md](disclosure-fallback.md#submit-to-certcc-vince)
- **Encrypted sharing / archival bundle** -- export a repository's findings as a self-contained JSON bundle that round-trips through `/api/v1/import`, optionally age-encrypted to your team's keys. The default bundle is share-safe (finding substance only); `include=all` produces a lossless archival superset -- enrichment, disclosure fields, notes, communications, and references -- for backing up or moving a repo's findings between your own instances. See [docs/encrypted-sharing.md](encrypted-sharing.md)

Scrutineer can ingest findings produced elsewhere so they enter the same triage and disclosure workflow:

    curl -H "Authorization: Bearer $(cat data/operator-token)" --data-binary @report.sarif http://127.0.0.1:8080/api/v1/import

SARIF 2.1.0, CSV, markdown, and a minimal JSON shape are all accepted; the format is sniffed from the body. See [docs/import.md](import.md) for the full request and response shape, the per-format field mapping, and how to add support for a new format.
