#!/usr/bin/env python3
"""Fail the build if any tracked file contains internal identifying information.

WHY THIS EXISTS
    These repos are public, and so are the images they build. A hostname, an internal IP, an
    appdata pool path or a personal address committed to either is PERMANENT: removing it in a
    later commit does not remove it, because it stays in the history and in whatever already
    mirrored the repo. Cleaning it up afterwards costs a full history rewrite and a force-push
    across every clone. This guard is what stops it coming back.

WHAT COUNTS
    Host/server codenames, the private infra domain, RFC1918 + Tailscale-CGNAT addresses,
    `*.ts.net`, Unraid `/mnt/<pool>` paths, personal addresses and names, and Cloudflare
    Access policy UUIDs. Documentation ranges (RFC5737) and `example.com`/`.example` are the
    ALLOWED way to write an address or a host in a doc, a comment, or a test.

    ⚠️ THE DENYLIST ITSELF NAMES THE REAL VALUES, and it has to: you cannot match a host
    codename without writing it down. So this file DOES republish, in one greppable place,
    the very strings it exists to remove -- and it is the one file the scan skips, so it can
    never catch itself. That is an accepted, deliberate trade, not an oversight; do not let a
    reader conclude otherwise. The `_MUST_FAIL` cases likewise use the real codenames and
    domain -- what makes them safe is not that they are synthetic (they are not) but that
    they add NO exposure beyond what PATTERNS already carries. Where a case can be defanged
    without weakening it, it is: `.invalid` hosts (RFC 2606), implausible-but-valid octets,
    and placeholder UUIDs.

    ⚠️ Corollary, learned the hard way: a COMPILED copy of this file (`__pycache__/*.pyc`)
    embeds those same literals and is not human-readable, so it is easy to commit by accident.
    One was found tracked in the public templates repo. The skip below is therefore matched on
    the EXACT relative path -- an earlier substring match on the filename also matched the
    `.pyc`, which is precisely how it stayed invisible. Keep `__pycache__/` gitignored.

KNOWN LIMITS (state them; do not pretend to coverage)
    Line-based and literal: a value split across lines (implicit string concatenation, a YAML
    folded scalar) or encoded (base64, percent-encoding) is not detected. The guard raises the
    cost of an accidental leak; it is not a control against a determined one.

USAGE
    python scripts/check_no_internal_info.py            # scan tracked files, exit 1 on a hit
    python scripts/check_no_internal_info.py --selftest # prove the patterns still bite

    As a pre-commit hook (one-time, per clone):
        git config core.hooksPath .githooks

IF IT FIRES ON SOMETHING LEGITIMATE
    Add the exact literal to ALLOW_LITERALS below, in the same commit, with a comment saying
    why. That edit is visible in review -- which is the point. Do not loosen a pattern, and
    never add a blanket per-file skip: this file's whole value is that it cannot be satisfied
    by looking away.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

# --------------------------------------------------------------------------- the denylist
# Every entry MUST have at least one deny case and one near-miss allow case in `selftest`;
# `test_every_pattern_is_exercised` below enforces that, because a pattern with no case can be
# deleted or broken and the green check will still say "the patterns bite".
PATTERNS: list[tuple[str, str]] = [
    ("host codename", r"\b(?:titan|genisys|fatal-ryzen)\b"),
    ("infra domain", r"\breinlie\b"),
    # `Scott` is CASE-SENSITIVE: the personal name is capitalized, while lowercase `scott` is
    # scipy/seaborn's KDE bandwidth rule (`bw_method="scott"`) — a live false positive in a
    # data/finance repo. The (?-i:...) group opts out of the IGNORECASE applied to the rest.
    ("personal name/address",
     r"(?-i:\bScott\b)|texasdaddy@|[\w.+-]+@(?:gmail|outlook|hotmail|yahoo|icloud|proton)\."),
    # RFC1918. Left-bounded so a decimal doesn't trip it; the right bound must still reject a
    # 5th octet while ALLOWING a sentence-final period — `the host is <addr>.` is the most
    # natural way to write one in prose, and was invisible to an earlier `(?![\w.])`.
    ("private IPv4 (RFC1918)",
     (r"(?<![\w.])(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
      r"|192\.168\.\d{1,3}\.\d{1,3}"
      r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})(?![\w]|\.\d)")),
    # Tailscale CGNAT 100.64.0.0/10 + tailnet names.
    ("tailscale address",
     r"(?<![\w.])100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d{1,3}\.\d{1,3}(?![\w]|\.\d)"),
    ("tailnet name", r"\b[\w-]+\.ts\.net\b"),
    ("unraid pool path", r"/mnt/(?:apps|user|cache|remotes|disks)\b"),
    ("cloudflare access app", r"\bunRAID Agents\b"),
    # Any UUID. Cloudflare Access policy ids look like this, and so do tenant/app ids — all of
    # which identify the estate. A legitimate one (a fixture, a migration revision) is meant to
    # be added to ALLOW_LITERALS deliberately rather than waved through by a looser pattern.
    ("uuid (access policy / tenant id)",
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

# The documented ways to write an address or a host. These are NEUTRALIZED IN PLACE rather
# than used to skip the line: skipping the line meant one `.env.example` mention could hide a
# real leak sitting beside it, and `.example` matches `.env.example`, which appears in every
# repo's docs.
ALLOW_SPANS: tuple[str, ...] = (
    r"(?<![\w.])192\.0\.2\.\d{1,3}",        # RFC5737 TEST-NET-1
    r"(?<![\w.])198\.51\.100\.\d{1,3}",     # RFC5737 TEST-NET-2
    r"(?<![\w.])203\.0\.113\.\d{1,3}",      # RFC5737 TEST-NET-3
    r"[\w.-]*\bexample\.(?:com|org|net)\b",  # example.com and friends
    r"[\w.-]+\.example\b",                  # your-domain.example
    r"\.env\.example\b",
)

# Text-bearing formats are NEVER skipped — an SVG is XML and carries <title>/<desc>/href, and
# the leak this batch removed was literally an icon URL inside one.
SKIP_SUFFIXES = (".png", ".jpg", ".jpeg", ".ico", ".gif", ".pdf", ".zip", ".gz",
                 ".woff", ".woff2", ".ttf", ".db", ".sqlite")

# The ONE file the scan cannot clear, matched by EXACT repo-relative path. It was previously
# `SELF in path.name`, a substring test that also matched
# `scripts/__pycache__/check_no_internal_info.cpython-312.pyc` -- a tracked, binary, literal-
# bearing copy that the scan therefore skipped in silence. Anything that is not exactly this
# path gets scanned, and a `.pyc` is deliberately NOT in SKIP_SUFFIXES so it surfaces as
# unreadable-and-therefore-not-cleared rather than being waved through.
SELF_RELPATH = "scripts/check_no_internal_info.py"

_ALLOW_SPAN_RX = re.compile("|".join(ALLOW_SPANS), re.IGNORECASE)


def tracked_files(root: Path) -> list[Path]:
    out = subprocess.run(["git", "ls-files", "-z"], cwd=root, capture_output=True, check=True)
    return [root / p for p in out.stdout.decode("utf-8").split("\0") if p]


def _neutralize(line: str) -> str:
    for lit in ALLOW_LITERALS:
        line = line.replace(lit, "")
    return _ALLOW_SPAN_RX.sub("", line)


def scan_text(text: str, compiled: list[tuple[str, re.Pattern[str]]]) -> list[tuple[int, str, str]]:
    hits: list[tuple[int, str, str]] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        stripped = _neutralize(line)
        for label, rx in compiled:
            m = rx.search(stripped)
            if m:
                hits.append((lineno, label, m.group(0)))
    return hits


# Deny cases reproduce shapes that were REAL findings in these repos, and they use the real
# codenames/domain/name because that is what the patterns match on -- see the module
# docstring: this file already carries those literals in PATTERNS, so the cases add nothing.
# Hosts are `.invalid` (RFC 2606) and the addresses are implausible so nothing here resolves.
_MUST_FAIL: list[tuple[str, str]] = [
    ("host codename", "deploy it to Titan and check the badge"),
    ("host codename", "the genisys box hosts the reverse proxy"),
    ("host codename", "built on fatal-ryzen"),
    ("infra domain", "CALLBACK_URL=https://app-dev.reinlie.invalid/v1/admin/callback"),
    ("private IPv4 (RFC1918)", "DATABASE_URL=postgresql://u:p@192.168.77.77:5432/db"),
    ("private IPv4 (RFC1918)", "allowlist = '10.99.99.0/24'"),
    ("private IPv4 (RFC1918)", "peer 172.31.255.254 is not allowed"),
    # The bare-prose form: a sentence-final period must not hide it.
    ("private IPv4 (RFC1918)", "The database lives at 192.168.77.77."),
    ("tailscale address", "agent reachable on 100.127.255.254:8043"),
    ("tailnet name", "https://host-a.tailnet-example.ts.net/"),
    ("unraid pool path", 'Default="/mnt/apps/appdata/svc/data"'),
    ("unraid pool path", "Run from: cd /mnt/user/appdata/svc"),
    ("personal name/address", "_UA = 'Research someone@gmail.invalid'"),
    ("personal name/address", "per Scott directive 2026-06-10"),
    ("cloudflare access app", "policy attached to the unRAID Agents application"),
    ("uuid (access policy / tenant id)", "access_app = '11111111-2222-3333-4444-555555555555'"),
]

_MUST_PASS: list[str] = [
    "host='198.51.100.5'  # RFC5737",
    "peer 192.0.2.1 rejected",
    "doc range 203.0.113.9 is fine",
    "APP_BASE_URL=https://svc.your-domain.example",
    "ntfy example: https://ntfy.example.com",
    "see https://github.com/texasdaddy/tape/issues/31",
    "icon: https://raw.githubusercontent.com/texasdaddy/unraid-templates/main/icons/tape.png",
    "version 10.16.2 of the driver",              # not an address
    "the 172.315 basis-point spread",             # not an address
    "bind 0.0.0.0:5000",
    'kde = gaussian_kde(x, bw_method="scott")',   # scipy, not a person
    "titanium alloy pricing feed",                # not the codename
    "copy .env.example and fill it in",
    # The reason ALLOW_SPANS neutralizes a SPAN and not the LINE: a permitted token must not
    # grant amnesty to a real leak sharing the line with it.
]

_MUST_FAIL_COMBINED = "# see example.com; real host is host-a.reinlie.invalid"


def selftest(compiled: list[tuple[str, re.Pattern[str]]]) -> int:
    bad: list[str] = []
    exercised: set[str] = set()
    for want_label, s in _MUST_FAIL:
        hits = scan_text(s, compiled)
        if not hits:
            bad.append(f"SHOULD have been caught ({want_label}): {s!r}")
            continue
        labels = {label for _, label, _ in hits}
        exercised |= labels
        if want_label not in labels:
            bad.append(f"caught by the WRONG pattern ({sorted(labels)}, wanted {want_label}): {s!r}")
    for s in _MUST_PASS:
        hits = scan_text(s, compiled)
        if hits:
            bad.append(f"false positive on {s!r}: {hits}")
    if not scan_text(_MUST_FAIL_COMBINED, compiled):
        bad.append("an allowed token on the same line hid a real leak: "
                   f"{_MUST_FAIL_COMBINED!r}")
    missing = {label for label, _ in PATTERNS} - exercised
    if missing:
        bad.append(f"pattern(s) with no deny case, so nothing proves they still work: "
                   f"{sorted(missing)}")
    if bad:
        print("SELFTEST FAILED:")
        for b in bad:
            print("  " + b)
        return 1
    print(f"selftest ok: {len(_MUST_FAIL) + 1} denied shapes caught across "
          f"{len(PATTERNS)} patterns, {len(_MUST_PASS)} allowed shapes passed")
    return 0


def main(argv: list[str]) -> int:
    compiled = [(label, re.compile(rx, re.IGNORECASE)) for label, rx in PATTERNS]
    if "--selftest" in argv:
        return selftest(compiled)

    root = Path(subprocess.run(["git", "rev-parse", "--show-toplevel"], capture_output=True,
                               check=True, text=True).stdout.strip())
    findings: list[str] = []
    unreadable: list[str] = []
    scanned = 0
    for path in tracked_files(root):
        rel = path.relative_to(root).as_posix()
        if rel == SELF_RELPATH or path.suffix.lower() in SKIP_SUFFIXES:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except FileNotFoundError:
            # Tracked but absent from the worktree. This used to `continue` silently, which
            # is the same "waved it through" shape as the .pyc bug: the blob is still staged
            # and would still be committed, we just could not read it. Not clearing it.
            unreadable.append(f"{rel} (tracked, but not in the working tree)")
            continue
        except UnicodeDecodeError:
            # NOT silent: a file this scanner cannot read is a file it cannot vouch for.
            unreadable.append(rel)
            continue
        scanned += 1
        findings += [f"{rel}:{n}: {label}: {match!r}"
                     for n, label, match in scan_text(text, compiled)]

    if unreadable:
        print(f"NOT SCANNED, therefore NOT CLEARED ({len(unreadable)}):")
        for u in unreadable:
            print("  " + u)
        print("Add a binary suffix to SKIP_SUFFIXES if that is what it is, or fix the "
              "encoding.\n")
    if findings:
        print(f"INTERNAL INFO FOUND in {len(findings)} place(s) - this repo is public:\n")
        for f in findings:
            print("  " + f)
        print("\nReplace with a placeholder (<your-unraid-host>, your-domain.example, "
              "/mnt/POOL/..., RFC5737 addresses) or take the value from an env Variable.")
        print("If a hit is genuinely legitimate, add the literal to ALLOW_LITERALS in "
              "scripts/check_no_internal_info.py with a comment saying why.")
    if findings or unreadable:
        return 1
    print(f"no internal info found ({scanned} tracked text files scanned)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
