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

    ⚠️ NOTHING IN THIS FILE IS WRITTEN OUT IN PLAINTEXT -- not the self-test examples, and not
    the denylist itself. A guard that spells out the values it denies republishes, in one
    greppable place, exactly what it exists to remove, and it is the one file the tree scan
    skips (SELF_RELPATH), so it could never catch itself doing it. Two mechanisms, both
    load-bearing:
      * The denied TOKENS (codenames, infra domain, pool names, personal name, Access app name)
        are base64 in `_CODENAMES`/`_DOMAIN`/`_POOLS`/`_PERSON`/`_CFAPP`, decoded at import.
        Every pattern and every self-test case interpolates them; none retypes one.
      * The surrounding EXAMPLES are invented -- `.invalid` hosts (RFC 2606) and out-of-range
        octets exercise the same patterns and leak nothing.
    Base64 is not secrecy and is not meant to be; it defeats a grep, a code search and a
    scraper, which is what actually turns a committed literal into an exposure. The GitHub
    account name stays plaintext throughout: it is in the repo's own URL and in every icon URL
    the templates point at, so encoding it here would buy nothing and break ALLOW_LITERALS.
    `--selftest` proves the patterns still bite, and `test_guard_source_carries_no_plaintext_
    token` in tests/ asserts no decoded token has crept back in as a literal.

KNOWN LIMITS (state them; do not pretend to coverage)
    Line-based and literal: a value split across lines (implicit string concatenation, a YAML
    folded scalar) or encoded (base64, percent-encoding) is not detected. The guard raises the
    cost of an accidental leak; it is not a control against a determined one.

    `--range` reads each commit's diff against its FIRST parent. For an ordinary commit that is
    exactly "what this commit added". For a merge it is "everything the merged side brought in",
    which is redundant when those commits are themselves in the range and is the safe direction
    to be wrong in — a guard may re-scan, it may not skip. What it does NOT see is a value that
    was never added as a whole line by any commit in the range (the same line-based limit as
    above), or history OUTSIDE the range you hand it.

WHY --range EXISTS (the working-tree scan is not enough)
    Scanning the working tree answers "is the leak here NOW". Pushing publishes HISTORY. A
    codename committed in one commit and deleted in the next is absent from the tree, passes the
    tree scan, and is still permanently readable at the earlier commit once the branch is on the
    remote — which is the expensive case this whole file exists to prevent (it costs a history
    rewrite and a force-push across every clone). So the tree scan and the range scan answer two
    different questions and BOTH are run: the tree scan on every commit, the range scan on
    everything about to reach the remote.

    ⚠️ AND THE TREE SCAN IS BLIND TO A BRAND-NEW FILE. It reads `git ls-files`, which lists
    TRACKED files only, so a file that does not exist in the index yet is not scanned at all —
    it is not a hit, it is not "unreadable", it is simply absent from the run that prints "no
    internal info found". That is how a synthetic internal hostname reached a public remote:
    the guard was run BEFORE `git add`, reported clean on a tree that did not yet contain the
    new file, and the very next commit published it. Two consequences, both load-bearing:
      1. ALWAYS run the tree scan AFTER `git add`, never before. The pre-commit hook is on the
         right side of that line by construction; a human running it by hand is not.
      2. The range scan does not care either way — it reads what each COMMIT added, and a new
         file's first commit adds every one of its lines. It is the layer that actually closes
         this, which is why it runs on the push path and in CI rather than only locally.

USAGE
    python scripts/check_no_internal_info.py            # scan tracked files, exit 1 on a hit
    python scripts/check_no_internal_info.py --selftest # prove the patterns still bite
    python scripts/check_no_internal_info.py --range origin/main..HEAD  # scan the COMMITS

    As a pre-commit + pre-push hook (one-time, per clone):
        git config core.hooksPath .githooks

IF IT FIRES ON SOMETHING LEGITIMATE
    Add the exact literal to ALLOW_LITERALS below, in the same commit, with a comment saying
    why. That edit is visible in review -- which is the point. Do not loosen a pattern, and
    never add a blanket per-file skip: this file's whole value is that it cannot be satisfied
    by looking away.
"""

from __future__ import annotations

import base64
import re
import subprocess
import sys
from pathlib import Path
from typing import NamedTuple

# ------------------------------------------------------------------ the denied tokens, encoded
# ⚠️ THE DENYLIST IS BASE64, NOT PLAINTEXT, AND THAT IS THE WHOLE POINT.
#
# A literal denylist in a PUBLIC repo republishes, in one greppable place, exactly the values it
# exists to remove — and this is the one file the tree scan skips (SELF_RELPATH), so it could
# never catch itself doing it. Written out whole, the codenames, the infra domain, the pool names
# and the personal name would be readable here, on GitHub code search, forever. A history rewrite
# was already spent once to remove them from everywhere ELSE; leaving them here would have made
# that rewrite pointless.
#
# WHAT THIS DOES AND DOES NOT BUY. Base64 is not secrecy — anyone reading this comment can decode
# it in one line, and it is not meant to stop them. It stops the things that actually cause the
# leak: a grep, a GitHub code search, a scraper, and the next scanner that reads this repo. That
# is the same threat model the rest of the file states plainly in KNOWN LIMITS.
#
# The tokens are DECODED AT IMPORT and the patterns are assembled from them below, so the
# compiled regexes are byte-identical to the plaintext version that preceded this. `selftest`
# proves every one of them still bites, and `test_guard_source_carries_no_plaintext_token` in
# tests/ asserts that no decoded token has crept back into this file as a literal.


def _d(b: str) -> str:
    """Decode one denied token. ASCII by construction; every pattern in this file is ASCII."""
    return base64.b64decode(b).decode("ascii")


# Host codenames, pipe-joined (3). Infra domain (1). Unraid pool names, pipe-joined (5).
# Personal given name (1). Cloudflare Access application name (1).
_CODENAMES = _d("dGl0YW58Z2VuaXN5c3xmYXRhbC1yeXplbg==")
_DOMAIN = _d("cmVpbmxpZQ==")
_POOLS = _d("YXBwc3x1c2VyfGNhY2hlfHJlbW90ZXN8ZGlza3M=")
_PERSON = _d("U2NvdHQ=")
_CFAPP = _d("dW5SQUlEIEFnZW50cw==")

# Indexed access for the self-test cases below, so those do not re-spell a token either.
_CODENAME = _CODENAMES.split("|")
_POOL = _POOLS.split("|")

# --------------------------------------------------------------------------- the denylist
# Every entry MUST have at least one deny case and one near-miss allow case in `selftest`;
# `test_every_pattern_is_exercised` below enforces that, because a pattern with no case can be
# deleted or broken and the green check will still say "the patterns bite".
PATTERNS: list[tuple[str, str]] = [
    ("host codename", rf"\b(?:{_CODENAMES})\b"),
    ("infra domain", rf"\b{_DOMAIN}\b"),
    # The personal name is CASE-SENSITIVE: capitalized it is the person, lowercased it is
    # scipy/seaborn's KDE bandwidth rule (`bw_method="<name>"`) — a live false positive in a
    # data/finance repo. The (?-i:...) group opts out of the IGNORECASE applied to the rest.
    ("personal name/address",
     rf"(?-i:\b{_PERSON}\b)|texasdaddy@|[\w.+-]+@(?:gmail|outlook|hotmail|yahoo|icloud|proton)\."),
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
    ("unraid pool path", rf"/mnt/(?:{_POOLS})\b"),
    ("cloudflare access app", rf"\b{_CFAPP}\b"),
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
# ⚠️ The two host spans anchor each label with `(?:[\w-]+\.)*` rather than a flat `[\w.-]*`.
#
# WHY: `[\w.-]*` overlaps the `\.` that follows it, so every added character doubled the
# backtracking. Measured on one line of `z`: 4 000 chars 0.29 s, 16 000 chars 4.6 s, 32 000
# chars 29 s — a 200 KB minified line or a base64 data URI extrapolates to ~19 MINUTES.
# Survivable while this only ran over a tracked tree; `--range` puts it on the push path and in
# CI, where a hang is precisely the failure mode the no-silent-hangs directive forbids.
# Anchored: 16 000 chars in 0.001 s.
#
# NOT match-for-match identical, and an earlier version of this comment wrongly said it was:
# a differential over thousands of strings found cases the anchored form REPORTS and the flat
# one swallowed (all of the `<label>-example.tld` shape) and ZERO in the other direction. So the
# change is strictly FAIL-CLOSED, which is the property that matters for a leak guard.
ALLOW_SPANS: tuple[str, ...] = (
    r"(?<![\w.])192\.0\.2\.\d{1,3}",        # RFC5737 TEST-NET-1
    r"(?<![\w.])198\.51\.100\.\d{1,3}",     # RFC5737 TEST-NET-2
    r"(?<![\w.])203\.0\.113\.\d{1,3}",      # RFC5737 TEST-NET-3
    # example.com and friends, with any number of leading labels
    r"(?<![\w.-])(?:[\w-]+\.)*example\.(?:com|org|net)\b",
    r"(?<![\w.-])(?:[\w-]+\.)*[\w-]+\.example\b",   # your-domain.example
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
#
# ⚠️ BOTH SCANS USE THIS, and they must agree. The range scan gets its paths from the
# `diff --git a/X b/X` header, which is already repo-relative and posix-separated -- the same
# shape as the tree scan's `path.relative_to(root).as_posix()`. If the two disagreed about
# which single file is exempt, one of them would be lying about its coverage.
SELF_RELPATH = "scripts/check_no_internal_info.py"

_ALLOW_SPAN_RX = re.compile("|".join(ALLOW_SPANS), re.IGNORECASE)


def tracked_files(root: Path) -> list[Path]:
    out = subprocess.run(["git", "ls-files", "-z"], cwd=root, capture_output=True,
                         check=True, timeout=_GIT_TIMEOUT_S)
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


# --------------------------------------------------------------- scanning the COMMITS
# The empty tree. `git diff <EMPTY_TREE> <sha>` is how the very first commit in a repository is
# diffed, since it has no parent to diff against and `<sha>^` simply fails there.
_EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"

_HUNK_RX = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")

# EVERY git call this makes is bounded — `_git` and the fallback re-diff alike. A guard that can
# hang on the push path is the failure the no-silent-hangs directive forbids, and a wedged git is
# indistinguishable from a slow one. These are local operations with no network, so the risk is
# small but not nil: `git diff` can invoke a `.gitattributes` textconv filter that shells out.
# Generous enough that a large repository is never the reason it fires.
#
# ⚠️ An earlier version defined this and then passed it ONLY to the fallback, while the comment
# claimed everything was bounded — backwards from the risk, since the per-commit `git diff` is
# the call measured at 15.9 s on a large blob. A guarantee stated and not implemented is worse
# than one never claimed.
_GIT_TIMEOUT_S = 120


def _git(root: Path, *args: str) -> str:
    """Run git and return stdout as text.

    `errors="replace"` and not strict: a diff can carry a byte sequence that is not valid UTF-8
    (a latin-1 file, a half-binary blob git decided to treat as text), and a scanner that DIES on
    the content it is meant to inspect fails open — the push goes through unscanned. Replacement
    characters cannot create a false hit: every pattern is ASCII.
    """
    out = subprocess.run(["git", *args], cwd=root, capture_output=True, check=True,
                         timeout=_GIT_TIMEOUT_S)
    return out.stdout.decode("utf-8", errors="replace")


def commits_in_range(root: Path, rev_range: str) -> list[str]:
    """The commits the range covers, oldest first. Empty is a legitimate answer (nothing new).

    Whitespace-split so multi-token selectors work as well as `A..B` — the pre-push hook needs
    `<sha> --not --remotes` for a BRAND-NEW branch, which has no remote counterpart to diff
    against and would otherwise be scanned as zero commits.
    """
    return list(reversed(_git(root, "rev-list", *rev_range.split()).split()))


class ParsedDiff(NamedTuple):
    """What one commit's diff contributes: lines we CAN scan, and paths we cannot."""

    added: list[tuple[str, int, str]]   # (path, new-file line number, content)
    unscannable: list[str]              # paths git served as binary — see `parse_diff`


def parse_diff(diff: str) -> ParsedDiff:
    """Parse a `--unified=0` diff into added lines plus the paths that could not be read.

    Pure, so the parsing can be tested without a repository — the git side of this is two
    commands and the fiddly part is all here.

    Added lines are the whole question: a value enters the permanent history at the commit that
    added it, and stays readable there no matter what a later commit does. Removed lines are
    ignored for the same reason — deleting a leak is exactly what makes it invisible to the tree
    scan while leaving it in the history.

    ⚠️ THE PATH COMES FROM `diff --git`, NOT FROM `+++ ` (verification finding). Keying on the
    `--- `/`+++ ` header pair looks sufficient and is not: a REMOVED content line beginning
    `-- ` renders as `--- …` and an ADDED one beginning `++ ` renders as `+++ …`, so an ordinary
    pair of prose lines is byte-identical to a file header. Proven against real git output — an
    added line reading `++ logo.png` made every following line attribute to `logo.png`, which
    `scan_added` then skipped as a binary asset, and a genuine leak on the next line scanned
    CLEAN. `in_hunk` closes it structurally: once `@@` has been seen, nothing until the next
    `diff --git` can be a header, which is exactly git's own grammar.

    ⚠️ A BINARY DIFF CARRIES NO LINES, so it must be REPORTED rather than passed over. The tree
    scan already refuses to vouch for what it cannot decode (`UNREADABLE as UTF-8 … not scanned,
    so not cleared`); a UTF-16 file is invisible to both scans otherwise, which is a hole rather
    than a limit.
    """
    added: list[tuple[str, int, str]] = []
    unscannable: list[str] = []
    path = ""
    lineno = 0
    in_hunk = False
    deleted = False
    for line in diff.splitlines():
        if line.startswith("diff --git "):
            # `a/X b/X`. Split on " b/" so a path containing a space still resolves; git quotes
            # genuinely pathological names, and those fall back to the whole tail.
            tail = line[len("diff --git "):]
            path = tail.split(" b/", 1)[1] if " b/" in tail else tail
            in_hunk = False
            deleted = False
            continue
        if not in_hunk and line.startswith("+++ "):
            raw = line[4:].strip()
            # `/dev/null` on the new side means the file was DELETED — a deletion adds nothing.
            path = "" if raw == "/dev/null" else raw.removeprefix("b/")
            continue
        if line.startswith("deleted file mode "):
            # `GIT binary patch` (only emitted under `--binary`, which this never passes) carries
            # no `/dev/null` marker, so the deletion has to be recognised from the mode line.
            # `parse_diff` is a documented pure function with its own tests; it should not depend
            # on its one caller's flags for correctness.
            deleted = True
            continue
        if not in_hunk and (line.startswith("Binary files ") or line == "GIT binary patch"):
            # ⚠️ A DELETION PUBLISHES NOTHING (verification finding). `Binary files a/x and
            # /dev/null differ` is a removal, and reporting it would make every commit that
            # deletes a binary — or the delete half of a binary rename — fail forever. That is
            # the same trap the removed-lines rule above avoids: a guard that punishes cleanup
            # is a guard that gets switched off.
            if path and not deleted and not line.rstrip().endswith("and /dev/null differ"):
                unscannable.append(path)
            path = ""
            continue
        if not path:
            continue
        m = _HUNK_RX.match(line)
        if m:
            lineno = int(m.group(1))
            in_hunk = True
            continue
        if in_hunk and line.startswith("+"):
            added.append((path, lineno, line[1:]))
            lineno += 1
    return ParsedDiff(added, unscannable)


def added_lines(root: Path, sha: str) -> ParsedDiff:
    """`parse_diff` over this commit's diff against its FIRST parent, then RESOLVE the paths git
    served as binary by actually reading them.

    First parent, so a merge reports what its side brought in rather than nothing at all —
    `git diff <merge> <merge>` is empty, and a merge would otherwise always scan clean.

    ⚠️ "git called it binary" IS NOT "it is unreadable" (verification finding). git says that for
    a `.gitattributes` `-diff`/`binary` attribute too — standard practice for a generated
    lockfile, and this repo generates a 99 KB `requirements.txt` — and for UTF-8 text carrying
    one stray NUL. Reporting those as "not scanned" reddens ordinary work with remediation advice
    that is simply wrong ("commit the file as UTF-8 text" — it already IS).

    So each flagged path is RE-DIFFED with `--text`, which forces git to emit real hunks, and the
    result is decoded strictly. Decodes → those are the lines this commit added, scanned like any
    other. Fails → the content genuinely is not UTF-8, and it stays unscannable so the run
    refuses to clear it.

    ⚠️ RE-DIFF, NOT RE-READ. The first version of this fetched the whole blob and scanned every
    line of it. A third verification pass measured what that costs: 15.9 s per commit on a 24 MB
    `-diff` blob, so a 200-commit PR touching a large lockfile extrapolates to ~50 MINUTES, on
    the push path and in CI — the hang the no-silent-hangs directive forbids, re-entering through
    a door I opened while closing another. It also attributed a PRE-EXISTING leak to whichever
    innocent commit last touched the file, and told the operator to rewrite that one.

    Both faults are the same mistake: the unit of this scan is what a commit ADDED, and reading
    the blob threw that away. The `--text` diff restores it, and bounds the cost by the change
    rather than by the file.

    Skipped suffixes are filtered FIRST, so a 100 MB `.png` is never fetched only to be discarded.
    """
    try:
        parent = _git(root, "rev-parse", "--verify", f"{sha}^").strip() or _EMPTY_TREE
    except subprocess.CalledProcessError:
        parent = _EMPTY_TREE  # the root commit has no parent
    parsed = parse_diff(
        _git(root, "diff", "--unified=0", "--no-color", "--no-renames", parent, sha))
    pending = [p for p in parsed.unscannable if not _skipped(p)]
    if not pending:
        return ParsedDiff(parsed.added, [])

    added = list(parsed.added)
    still_unreadable: list[str] = []
    for path in pending:
        try:
            raw = subprocess.run(
                ["git", "diff", "--unified=0", "--no-color", "--no-renames", "--text",
                 parent, sha, "--", path],
                cwd=root, capture_output=True, check=True, timeout=_GIT_TIMEOUT_S).stdout
            text = raw.decode("utf-8")
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, UnicodeDecodeError):
            # Cannot read it → cannot vouch for it. Fail closed, exactly like the tree scan.
            still_unreadable.append(path)
            continue
        added += parse_diff(text).added
    return ParsedDiff(added, still_unreadable)


def _skipped(path: str) -> bool:
    """Files both scans decline to read: known binary suffixes, and this scanner's own source
    (which carries synthetic deny cases by design).

    `path` is repo-relative and posix-separated, so the self-check is an EXACT comparison and
    not a substring one — see SELF_RELPATH for the `.pyc` that the substring form waved through.
    """
    return path == SELF_RELPATH or path.lower().endswith(SKIP_SUFFIXES)


def scan_added(sha: str, parsed: ParsedDiff,
               compiled: list[tuple[str, re.Pattern[str]]]) -> tuple[list[str], list[str]]:
    """(findings, unscannable) for one commit. Skips the same files the tree scan skips, or the
    two scans would disagree about what this repository contains."""
    findings: list[str] = []
    for path, lineno, content in parsed.added:
        if _skipped(path):
            continue
        for _, label, match in scan_text(content, compiled):
            findings.append(f"{sha[:10]} {path}:{lineno}: {label}: {match!r}")
    return findings, [f"{sha[:10]} {p}" for p in parsed.unscannable if not _skipped(p)]


class RangeResult(NamedTuple):
    findings: list[str]
    unscannable: list[str]
    commits: int


def scan_range(root: Path, rev_range: str,
               compiled: list[tuple[str, re.Pattern[str]]]) -> RangeResult:
    """Scan every line added by every commit in `rev_range`."""
    findings: list[str] = []
    unscannable: list[str] = []
    commits = commits_in_range(root, rev_range)
    for sha in commits:
        hits, blind = scan_added(sha, added_lines(root, sha), compiled)
        findings += hits
        unscannable += blind
    return RangeResult(findings, unscannable, len(commits))


# Deny cases are SYNTHETIC stand-ins for shapes that were real findings in these repos: the
# surrounding sentence is invented, and `.invalid` is reserved by RFC 2606 so the hosts resolve
# nowhere. The denied TOKEN itself is interpolated from the decoded table above rather than
# retyped — a deny case that spelled it out would put it back in this file in plaintext, which is
# the leak the encoding exists to prevent.
_MUST_FAIL: list[tuple[str, str]] = [
    ("host codename", f"deploy it to {_CODENAME[0].capitalize()} and check the badge"),
    ("host codename", f"the {_CODENAME[1]} box hosts the reverse proxy"),
    ("host codename", f"built on {_CODENAME[2]}"),
    ("infra domain", f"CALLBACK_URL=https://app-dev.{_DOMAIN}.invalid/v1/admin/callback"),
    ("private IPv4 (RFC1918)", "DATABASE_URL=postgresql://u:p@192.168.77.77:5432/db"),
    ("private IPv4 (RFC1918)", "allowlist = '10.99.99.0/24'"),
    ("private IPv4 (RFC1918)", "peer 172.31.255.254 is not allowed"),
    # The bare-prose form: a sentence-final period must not hide it.
    ("private IPv4 (RFC1918)", "The database lives at 192.168.77.77."),
    # The port is arbitrary — the ADDRESS is what this case exercises, and 100.127.255.254 is the
    # top of the CGNAT range rather than any host here.
    ("tailscale address", "agent reachable on 100.127.255.254:9999"),
    ("tailnet name", "https://host-a.tailnet-example.ts.net/"),
    ("unraid pool path", f'Default="/mnt/{_POOL[0]}/appdata/svc/data"'),
    ("unraid pool path", f"Run from: cd /mnt/{_POOL[1]}/appdata/svc"),
    ("personal name/address", "_UA = 'Research someone@gmail.invalid'"),
    ("personal name/address", f"per {_PERSON} directive 2026-06-10"),
    ("cloudflare access app", f"policy attached to the {_CFAPP} application"),
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
    # Both near-misses interpolate the real token deliberately: the point of each case is that
    # the token IS present and must still not match — lowercased in the first (the pattern is
    # case-sensitive there), and only as a prefix of a longer word in the second (`\b` holds).
    f'kde = gaussian_kde(x, bw_method="{_PERSON.lower()}")',   # scipy, not a person
    f"{_CODENAME[0]}ium alloy pricing feed",                   # not the codename
    "copy .env.example and fill it in",
    # The reason ALLOW_SPANS neutralizes a SPAN and not the LINE: a permitted token must not
    # grant amnesty to a real leak sharing the line with it.
]

_MUST_FAIL_COMBINED = f"# see example.com; real host is host-a.{_DOMAIN}.invalid"


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
            bad.append(f"caught by the WRONG pattern ({sorted(labels)}, "
                       f"wanted {want_label}): {s!r}")
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
                               check=True, text=True, timeout=_GIT_TIMEOUT_S).stdout.strip())

    if "--range" in argv:
        i = argv.index("--range")
        if i + 1 >= len(argv):
            print("--range needs a revision range, e.g. --range origin/main..HEAD")
            return 2
        rev_range = argv[i + 1]
        try:
            result = scan_range(root, rev_range, compiled)
        except subprocess.CalledProcessError as exc:
            # A range git cannot resolve is NOT a pass. A shallow clone, an unfetched base or a
            # typo would otherwise scan zero commits and print a clean result — the one failure
            # mode a guard must never have.
            print(f"could not scan {rev_range!r}: git exited {exc.returncode}. "
                  f"Fetch the base ref (CI needs fetch-depth: 0) or check the range.")
            return 1
        if result.unscannable:
            # Same posture as the tree scan's `undecodable` list: a blob this cannot read is a
            # blob it cannot vouch for. Silence here would be worse than the tree scan, which at
            # least refuses to clear what it could not decode.
            print(f"BINARY / UNREADABLE in {len(result.unscannable)} added file(s) - not "
                  f"scanned, so NOT CLEARED:")
            for u in result.unscannable:
                print("  " + u)
            print("Add a binary suffix to SKIP_SUFFIXES if that is what it is, or commit the "
                  "file as UTF-8 text.\n")
        if result.findings:
            print(f"INTERNAL INFO FOUND in {len(result.findings)} line(s) ADDED by {rev_range} - "
                  f"this repo is public and pushing publishes HISTORY:\n")
            for f in result.findings:
                print("  " + f)
            print("\nRemoving it in a LATER commit does not help: the value stays readable at "
                  "the commit that added it. Rewrite the offending commits (git rebase -i / "
                  "filter-repo) BEFORE pushing, then re-run this.")
        if result.findings or result.unscannable:
            return 1
        print(f"no internal info added across {result.commits} commit(s) in {rev_range}")
        return 0
    # ⚠️ TRACKED FILES ONLY (`git ls-files`). A file that is not in the index yet is invisible
    # here — see the module docstring: run this AFTER `git add`, and rely on the range scan for
    # the case where nobody did.
    findings: list[str] = []
    undecodable: list[str] = []
    scanned = 0
    for path in tracked_files(root):
        rel = path.relative_to(root).as_posix()
        if _skipped(rel):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except FileNotFoundError:
            # Tracked but absent from the worktree. This used to `continue` silently, which
            # is the same "waved it through" shape as the .pyc bug: the blob is still staged
            # and would still be committed, we just could not read it. Not clearing it.
            undecodable.append(f"{rel} (tracked, but not in the working tree)")
            continue
        except UnicodeDecodeError:
            # NOT silent: a file this scanner cannot read is a file it cannot vouch for.
            undecodable.append(rel)
            continue
        scanned += 1
        findings += [f"{rel}:{n}: {label}: {match!r}"
                     for n, label, match in scan_text(text, compiled)]

    if undecodable:
        print(f"NOT SCANNED, therefore NOT CLEARED ({len(undecodable)}):")
        for u in undecodable:
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
    if findings or undecodable:
        return 1
    print(f"no internal info found ({scanned} tracked text files scanned)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
