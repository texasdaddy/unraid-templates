#!/usr/bin/env python3
"""Fail the build if any tracked file contains internal identifying information.

WHY THIS EXISTS
    These repos are public, and so are the images they build. A hostname, an internal IP, an
    appdata pool path or a personal address committed to either is PERMANENT: removing it in a
    later commit does not remove it, because it stays in the history and in whatever already
    mirrored the repo. Cleaning it up afterwards costs a full history rewrite and a force-push
    across every clone (that is what batch 10 was). This guard is the thing that stops it
    coming back a sixth time.

WHAT COUNTS
    Host/server codenames, the private infra domain, RFC1918 + Tailscale-CGNAT addresses,
    `*.ts.net`, Unraid `/mnt/<pool>` paths, personal addresses and names, and Cloudflare
    Access policy UUIDs. Documentation ranges (RFC5737) and `example.com`/`.example` are the
    ALLOWED way to write an address or a host in a doc, a comment, or a test.

USAGE
    python scripts/check_no_internal_info.py            # scan tracked files, exit 1 on a hit
    python scripts/check_no_internal_info.py --selftest # prove the patterns still bite

    As a pre-commit hook (one-time, per clone):
        git config core.hooksPath .githooks

IF IT FIRES ON SOMETHING LEGITIMATE
    Add the exact literal to ALLOW_LITERALS below, in the same commit, with a comment saying
    why. That edit is visible in review — which is the point. Do not loosen a pattern, and
    never add a blanket per-file skip: this file's whole value is that it cannot be satisfied
    by looking away.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

# --------------------------------------------------------------------------- the denylist
PATTERNS: list[tuple[str, str]] = [
    ("host codename", r"\b(?:titan|genisys|fatal-ryzen)\b"),
    ("infra domain", r"\breinlie\b"),
    ("personal name/address", r"\bscott\b|texasdaddy@|[\w.+-]+@(?:gmail|outlook|hotmail|yahoo)\."),
    # RFC1918. Bounded on both sides so a version string or a decimal doesn't trip it.
    ("private IPv4 (RFC1918)",
     r"(?<![\w.])(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
     r"|192\.168\.\d{1,3}\.\d{1,3}"
     r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})(?![\w.])"),
    # Tailscale CGNAT 100.64.0.0/10 + tailnet names.
    ("tailscale address",
     r"(?<![\w.])100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d{1,3}\.\d{1,3}(?![\w.])"),
    ("tailnet name", r"\b[\w-]+\.ts\.net\b"),
    ("unraid pool path", r"/mnt/(?:apps|user|cache|remotes|disks)\b"),
    ("cloudflare access app", r"\bunRAID Agents\b"),
    ("uuid (access policy?)",
     r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"),
]

# Literals that LOOK like a hit but are allowed. Keep each one justified.
ALLOW_LITERALS: tuple[str, ...] = (
    # The GitHub/GHCR owner path is functional — neutralizing it breaks image pulls and the
    # icon URLs the Unraid templates point at. It is the account name, not infrastructure.
    "github.com/texasdaddy",
    "githubusercontent.com/texasdaddy",
    "ghcr.io/texasdaddy",
)

# Substrings that neutralize a match on the SAME line: the documented way to write one.
ALLOW_CONTEXT: tuple[str, ...] = (
    "192.0.2.",       # RFC5737 TEST-NET-1
    "198.51.100.",    # RFC5737 TEST-NET-2
    "203.0.113.",     # RFC5737 TEST-NET-3
    "example.com",
    ".example",       # your-domain.example
)

SKIP_SUFFIXES = (".png", ".jpg", ".jpeg", ".ico", ".gif", ".svg", ".pdf", ".zip", ".gz",
                 ".woff", ".woff2", ".ttf", ".db", ".sqlite")

SELF = "check_no_internal_info"


def tracked_files(root: Path) -> list[Path]:
    out = subprocess.run(["git", "ls-files", "-z"], cwd=root, capture_output=True, check=True)
    return [root / p for p in out.stdout.decode("utf-8").split("\0") if p]


def scan_text(text: str, compiled: list[tuple[str, re.Pattern[str]]]) -> list[tuple[int, str, str]]:
    hits: list[tuple[int, str, str]] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        stripped = line
        for lit in ALLOW_LITERALS:
            stripped = stripped.replace(lit, "")
        if any(ctx in stripped for ctx in ALLOW_CONTEXT):
            continue
        for label, rx in compiled:
            m = rx.search(stripped)
            if m:
                hits.append((lineno, label, m.group(0)))
    return hits


def selftest(compiled: list[tuple[str, re.Pattern[str]]]) -> int:
    """The guard is only worth its CI minute if the patterns still bite. Each string below is
    a real shape that was found in these repos before the scrub."""
    must_fail = [
        "deploy it to Titan and check the badge",
        "SCHWAB_CALLBACK_URL=https://tape-dev.reinlie.com/v1/admin/callback",
        'DATABASE_URL=postgresql://tape:x@192.168.1.64:5432/tape',
        "allowlist = '10.0.0.0/8'",
        "peer 172.16.0.1 is not allowed",
        "agent at 100.68.10.96:8043",
        "https://titan.tailnet-abc.ts.net/",
        'Default="/mnt/apps/appdata/tape/data"',
        "_UA = 'Research texasdaddy@gmail.com'",
        "per Scott directive 2026-06-10",
    ]
    must_pass = [
        "host='198.51.100.5'  # RFC5737",
        "APP_BASE_URL=https://tape.your-domain.example",
        "see https://github.com/texasdaddy/tape/issues/31",
        "icon: https://raw.githubusercontent.com/texasdaddy/unraid-templates/main/icons/tape.png",
        "ntfy example: https://ntfy.example.com",
        "version 10.16.2 of the driver",          # not an IP
        "bind 0.0.0.0:5000",
    ]
    bad = []
    for s in must_fail:
        if not scan_text(s, compiled):
            bad.append(f"SHOULD have been caught: {s!r}")
    for s in must_pass:
        hits = scan_text(s, compiled)
        if hits:
            bad.append(f"false positive on {s!r}: {hits}")
    if bad:
        print("SELFTEST FAILED:")
        for b in bad:
            print("  " + b)
        return 1
    print(f"selftest ok: {len(must_fail)} denied shapes caught, {len(must_pass)} allowed "
          "shapes passed")
    return 0


def main(argv: list[str]) -> int:
    compiled = [(label, re.compile(rx, re.IGNORECASE)) for label, rx in PATTERNS]
    if "--selftest" in argv:
        return selftest(compiled)

    root = Path(subprocess.run(["git", "rev-parse", "--show-toplevel"], capture_output=True,
                               check=True, text=True).stdout.strip())
    findings: list[str] = []
    scanned = 0
    for path in tracked_files(root):
        if path.suffix.lower() in SKIP_SUFFIXES or SELF in path.name:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, FileNotFoundError):
            continue  # binary, or a file listed in the index but absent from the worktree
        scanned += 1
        rel = path.relative_to(root).as_posix()
        findings += [f"{rel}:{n}: {label}: {match!r}" for n, label, match in scan_text(text, compiled)]

    if findings:
        print(f"INTERNAL INFO FOUND in {len(findings)} place(s) - this repo is public:\n")
        for f in findings:
            print("  " + f)
        print("\nReplace with a placeholder (<your-unraid-host>, your-domain.example, "
              "/mnt/POOL/..., RFC5737 addresses) or take the value from an env Variable.")
        print("If a hit is genuinely legitimate, add the literal to ALLOW_LITERALS in "
              "scripts/check_no_internal_info.py with a comment saying why.")
        return 1
    print(f"no internal info found ({scanned} tracked text files scanned)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
