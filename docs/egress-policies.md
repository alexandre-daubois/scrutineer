# Per-skill egress policies

Under `--hardened` the egress allowlist is deliberately tiny and `egress_allow`
is ignored. A skill that needs one more service (the bundled `metadata` skill
talks to ecosyste.ms) would otherwise force you to drop `--hardened` for every
scan. Egress policies let you grant named skills a few `host:port` destinations
while every other skill keeps the strict allowlist and the isolated network.

## Configuration

```yaml
hardened: true

egress_policies:
  metadata:
    allow:
      - packages.ecosyste.ms:443
      - repos.ecosyste.ms:443
      - advisories.ecosyste.ms:443
```

The key is the skill name. Each `allow` entry is `host:port`:

- The port is mandatory. A granted host is reachable on the ports you list and
  nowhere else, so a grant for `packages.ecosyste.ms:443` does not open
  `packages.ecosyste.ms:22`.
- The host is a DNS name or `*.domain` (which matches subdomains but not the
  apex, so list the apex separately if you need it).
- Schemes, paths, userinfo, IP addresses, `localhost`, `*.localhost` and
  `host.docker.internal` are rejected when the config loads, as is any
  wildcard that would cover `localhost` or `host.docker.internal` (for example
  `*.internal`).

## Requirements

- `--hardened` (or `hardened: true`). Each scan then runs on its own
  `--internal` network where the egress proxy is the only way out, so a scan
  that clears its proxy environment variables reaches nothing. Startup fails if
  `egress_policies` or `scan_egress_policies` is set without `--hardened` or
  together with `--no-container`.
- On Docker Desktop and rootless podman the proxy is a per-scan sidecar started
  from the runner image. The image must include a `scrutineer` binary from this
  version or newer. Pull or rebuild the runner image after upgrading. An older
  image cannot enforce ports and refuses to start, which fails the scan closed
  instead of running it with unrestricted grants. With policies configured,
  scrutineer also checks the image at startup when it is already present
  locally. Either key counts as configuring policies for this check.

## Per-scan policies

A skill policy applies to every scan of that skill. To give one scan extra
egress without changing the skill, define a named policy under
`scan_egress_policies`:

```yaml
hardened: true
scan_egress_policies:
  registries:
    allow:
      - registry.npmjs.org:443
      - pypi.org:443
      - files.pythonhosted.org:443
```

Entries follow the same `host:port` rules as `egress_policies`. The policy name
must be 1 to 64 characters of lowercase letters, digits, `.`, `_` and `-`. It
must start with a letter or digit.

When the key is set, the Run skill menu on the repository page gains an "Egress
policy" selector. Choose a policy then pick the skill. The default, "No extra
egress", adds nothing. The scan's effective grants are the skill's own policy
plus the chosen scan policy, with ports merged per host. Retrying a scan keeps
its policy. If the policy has been removed from the config since, the retry is
refused (HTTP 422) instead of running without the egress the scan was launched
with. The scan page shows the policy that was used.

Only the operator UI can attach a scan policy. The scan-token skill API ignores
any `egress_policy` it is sent and every automatic follow-up scan (hooks such
as revalidate, dedup, exploratory, focus-area, reflection and triage children)
starts without one, so a scan cannot hand its egress to the scans it starts.
The one exception is a candidate scan from a `scan_experiments` trial, which
inherits the policy the operator picked for the scan it is compared against so
both run with the same egress.
Request bodies never carry hosts or ports, only a policy name that must already
exist in the config.

## Who can grant egress

Only the operator's config file can define a policy while only the operator's
browser session can attach a scan policy to a scan. Repository content, skill
files and agent output have no way to add or widen a policy. A scan cannot see
the policy beyond what its proxy allows. Skill policies key on the skill name
that scrutineer itself passes to the runner. Scan policies are selected by name
from the repository page and stored on the scan row.

## What is recorded

At the start of every scan whose skill has a policy or that was launched with a
scan policy, scrutineer adds an event to the scan log:

```
egress-policy: skill=metadata grants=advisories.ecosyste.ms:443,packages.ecosyste.ms:443,repos.ecosyste.ms:443
```

With a scan policy the line also names it. The grants are the merged set:

```
egress-policy: skill=security-deep-dive scan_policy=registries grants=files.pythonhosted.org:443,pypi.org:443,registry.npmjs.org:443
```

Requests the proxy refuses appear in the same log as `egress-proxy:` lines. A
request to a granted host on an undeclared port is logged with the reason
`port not granted by egress policy`.

## Limits

- Hosts that are already on the base allowlist (for example the model API) are
  not port-restricted. A policy only adds hosts.
- Skills listed in `host_skills` run on the host without a container, so they
  ignore policies. Startup logs a warning if a policy names one.
- A policy that names a skill which does not exist is ignored with a startup
  warning.
- Policies do not change what happens for skills without one. Their container
  arguments, environment and allowlist are exactly what they were before.
- The granted host is still subject to the proxy's rule that hostnames must
  resolve to public addresses.
