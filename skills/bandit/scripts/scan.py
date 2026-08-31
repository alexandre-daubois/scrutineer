#!/usr/bin/env python3
"""Run bandit against ./src and emit the findings in scrutineer's shape.

Requires bandit on PATH. Writes structured JSON to stdout. Stderr carries
progress and errors.

bandit is invoked with cwd=./src so paths in results are repo-relative; it
still prefixes each one with `./`, which is stripped here so a location reads
`lib/foo.py:42` like every other skill's.

Results are grouped by (test_id, issue_text): a plugin interpolates the
offending name into its message when it considers the matches distinct, so an
identical message is bandit's own signal that the hits are the same issue.
Each group becomes one finding carrying every file:line in `locations`.
"""
import json
import os
import shutil
import subprocess
from collections import defaultdict

SEVERITY_MAP = {
    "LOW": "Low",
    "MEDIUM": "Medium",
    "HIGH": "High",
}

# bandit's own levels stop at HIGH, so nothing maps to Critical: promoting its
# top level would let a linter hit outrank a finding another scanner genuinely
# rated critical.

CONFIDENCE_MAP = {
    "LOW": "low",
    "MEDIUM": "medium",
    "HIGH": "high",
}

# -x replaces bandit's built-in exclude list rather than adding to it, so the
# VCS and build directories it skips by default are repeated here. The rest
# covers test and spec code, which is not shipped to production and mirrors
# what the semgrep skill excludes.
EXCLUDES = [
    ".svn",
    "CVS",
    ".bzr",
    ".hg",
    ".git",
    "__pycache__",
    ".tox",
    ".eggs",
    "*.egg",
    "*/test",
    "*/tests",
    "*/spec",
    "*/specs",
    "*/test_*.py",
    "*_test.py",
    "*/conftest.py",
]


def main():
    if not os.path.isdir("./src"):
        print(json.dumps({"findings": [], "error": "no ./src directory"}))
        return

    if shutil.which("bandit") is None:
        print(json.dumps({"findings": [], "error": "bandit not on PATH"}))
        return

    proc = subprocess.run(
        ["bandit", "-r", "-q", "-f", "json", "-x", ",".join(EXCLUDES), "."],
        cwd="./src",
        capture_output=True,
        text=True,
    )
    # exit code 1 means findings; 0 means clean; anything else is failure.
    if proc.returncode not in (0, 1):
        print(json.dumps({"findings": [], "error": proc.stderr.strip()[:2000]}))
        return

    try:
        data = json.loads(proc.stdout) if proc.stdout else {"results": []}
    except json.JSONDecodeError as exc:
        print(json.dumps({"findings": [], "error": f"bandit json: {exc}"}))
        return

    groups = defaultdict(list)
    for r in data.get("results", []):
        key = (r.get("test_id") or "bandit", (r.get("issue_text") or "").strip())
        groups[key].append(r)

    findings = []
    for i, ((test_id, issue_text), results) in enumerate(groups.items(), start=1):
        first = results[0]
        severity = SEVERITY_MAP.get(str(first.get("issue_severity", "")).upper(), "Medium")
        locations = sorted({result_location(r) for r in results})
        n = len(locations)
        suffix = f" ({n} locations)" if n > 1 else ""
        finding = {
            "id": f"F{i}",
            "title": f"{test_id} {first.get('test_name') or ''}".strip(),
            "severity": severity,
            "cwe": result_cwe(first),
            "location": locations[0],
            "locations": locations,
            "trace": issue_text,
            "rating": f"{severity} from bandit test {test_id}{suffix}",
        }
        confidence = CONFIDENCE_MAP.get(str(first.get("issue_confidence", "")).upper())
        if confidence:
            finding["confidence"] = confidence
        more_info = first.get("more_info")
        if more_info:
            finding["references"] = [{
                "url": more_info,
                "summary": f"bandit docs: {test_id}",
                "tags": "docs",
            }]
        findings.append(finding)

    out = {"findings": findings}
    # bandit records a file it could not parse in `errors` and carries on with
    # an exit code that says nothing went wrong, so an unreported error reads
    # as a clean file rather than an unscanned one.
    errors = data.get("errors") or []
    if errors:
        skipped = ", ".join(
            f"{e.get('filename', '?')} ({e.get('reason', 'unknown')})" for e in errors[:20]
        )
        more = f" and {len(errors) - 20} more" if len(errors) > 20 else ""
        out["notes"] = f"bandit could not read {len(errors)} file(s): {skipped}{more}"
    print(json.dumps(out))


def result_location(r):
    path = str(r.get("filename", "")).removeprefix("./")
    if not path:
        return "unknown"
    line = r.get("line_number")
    return f"{path}:{line}" if line else path


def result_cwe(r):
    cwe = r.get("issue_cwe") or {}
    cwe_id = cwe.get("id") if isinstance(cwe, dict) else None
    return f"CWE-{cwe_id}" if isinstance(cwe_id, int) else ""


if __name__ == "__main__":
    main()
