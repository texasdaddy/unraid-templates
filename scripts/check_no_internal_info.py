#!/usr/bin/env python3
"""Fail the build if any tracked file contains internal identifying information.

WHY THIS EXISTS
    These repos are public, and so are the images they build. An internal IP, an appdata pool
    path or a personal address committed to either is PERMANENT: removing it in a later commit
    does not remove it, because it stays in the history and in whatever already mirrored the
    repo. Cleaning it up afterwards costs a full history rewrite and a force-push across every
    clone. This guard is what stops it coming back.

⭐ THIS GUARD MATCHES SHAPES, NOT VALUES — AND THAT IS DELIBERATE.
    Every pattern below describes a CLASS of value (an RFC1918 address, a `/mnt/<pool>` path, a
    `.lan` host, a freemail address, a UUID). Not one of them names a real host, a real domain,
    a real address or a real person.

    The reason is that a denylist of REAL LITERALS cannot live in a public repo. Written out
    here, the codenames and the infra domain would be readable on GitHub code search forever —
    the guard would BE the leak, republishing in one greppable place exactly what it exists to
    remove. Worse, this is the one file the scan skips (SELF_PATH, below), so it could never
    catch itself doing it. Encoding the list (base64) was tried and is not a fix: it defeats a
    grep, but the values are still shipped, still decodable in one line, and still there.

    ⚠️ SO THIS GUARD IS NOT THE WHOLE CONTROL, AND MUST NOT BE TREATED AS ONE. It catches the
    shapes. The REAL-LITERAL check — the one that knows the actual host codenames, the actual
    infra domain and the operator's name — lives OUTSIDE every repo, in the project working
    directory, and is run against the staged tree before every push. A value that is real but
    shape-less (a bare codename such as a machine's pet name, with no domain or address around
    it) is invisible HERE and is caught THERE. Both layers are required; neither is sufficient.

WHAT COUNTS HERE
    RFC1918 and CGNAT addresses, `*.ts.net` tailnet names, `.lan`/`.local` host names, Unraid
    `/mnt/<pool>` paths, freemail personal addresses, and bare UUIDs (Cloudflare
    Access policy ids, tenant ids and app ids all take that shape, and all identify the estate).
    Documentation ranges (RFC5737) and `example.com`/`.example` are the ALLOWED way to write an
    address or a host in a doc, a comment, or a test.

    ⚠️ EVERY EXAMPLE IN THIS FILE IS SYNTHETIC — `.invalid` hosts (RFC 2606), out-of-range
    octets and reserved documentation ranges exercise the same patterns and leak nothing.

KNOWN LIMITS (state them; do not pretend to coverage)
    Line-based and literal: a value split across lines (implicit string concatenation, a YAML
    folded scalar) or encoded (base64, percent-encoding) is not detected. The guard raises the
    cost of an accidental leak; it is not a control against a determined one.

    Shape-based, per the note above: it cannot see a real value that has no recognisable shape.

    `--range` reads each commit's diff against its FIRST parent. For an ordinary commit that is
    exactly "what this commit added". For a merge it is "everything the merged side brought in",
    which is redundant when those commits are themselves in the range and is the safe direction
    to be wrong in — a guard may re-scan, it may not skip. What it does NOT see is a value that
    was never added as a whole line by any commit in the range (the same line-based limit as
    above), or history OUTSIDE the range you hand it.

WHY --range EXISTS (the working-tree scan is not enough)
    Scanning the working tree answers "is the leak here NOW". Pushing publishes HISTORY. A value
    committed in one commit and deleted in the next is absent from the tree, passes the tree
    scan, and is still permanently readable at the earlier commit once the branch is on the
    remote — which is the expensive case this whole file exists to prevent. So the tree scan and
    the range scan answer two different questions and BOTH are run: the tree scan on every
    commit, the range scan on everything about to reach the remote.

    ⚠️ AND THE TREE SCAN IS BLIND TO A BRAND-NEW FILE. It reads `git ls-files`, which lists
    TRACKED files only, so a file not yet in the index is not scanned at all — it is not a hit,
    it is not "unreadable", it is simply absent from the run that prints "no internal info
    found". That is how a synthetic internal hostname once reached a public remote: the guard
    ran BEFORE `git add`, reported clean on a tree that did not yet contain the new file, and
    the very next commit published it. Two consequences, both load-bearing:
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

import re
import subprocess
import sys
from pathlib import Path
from typing import NamedTuple

# --------------------------------------------------------------------------- the denylist
# SHAPES ONLY. See the module docstring: a real literal in this list would make this file the
# leak. Every entry MUST have at least one deny case in `_MUST_FAIL` and at least one near-miss
# in `_MUST_PASS` — a shape that looks like it and must NOT fire. What `selftest` actually
# enforces: it fails on a pattern with no deny case (nothing would then prove the pattern still
# bites), and it fails on any `_MUST_PASS` sample that trips (which is how a pattern widened
# until it matches ordinary text gets caught). It CANNOT check that a given pattern has a
# near-miss, because `_MUST_PASS` is a flat list with no pattern labels — that half is
# convention, and it is the half that catches widening, so add it with the pattern, not later.
PATTERNS: list[tuple[str, str]] = [
    # RFC1918. Left-bounded so a decimal doesn't trip it; the right bound must still reject a
    # 5th octet while ALLOWING a sentence-final period — `the host is <addr>.` is the most
    # natural way to write one in prose, and was invisible to an earlier `(?![\w.])`.
    ("private IPv4 (RFC1918)",
     (r"(?<![\w.])(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
      r"|192\.168\.\d{1,3}\.\d{1,3}"
      r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})(?![\w]|\.\d)")),
    # Carrier-grade NAT 100.64.0.0/10 — the range Tailscale assigns from.
    ("cgnat address",
     r"(?<![\w.])100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d{1,3}\.\d{1,3}(?![\w]|\.\d)"),
    # ⚠️ Left-bounded, and with `(?<![\w-])` specifically — NOT `(?<![\w.-])`.
    # `\b[\w-]+\.` was an instance of the unbounded-leading-class defect this file has been bitten
    # by three times: `-` is in the class but is not a word character, so `\b` held at every
    # hyphen, giving one restart per position. Measured on hyphenated input: 0.12/0.48/1.96/7.27 s
    # at 4k/8k/16k/32k. Not theoretical — base64url is exactly `[\w-]`, and a 128 KB token line
    # made a real `git push` take 2m06s. Bounded, the same input takes 0.0015 s.
    # Including `.` in the lookbehind would be the obvious copy-paste and it BREAKS the pattern:
    # a match must be able to start right after a dot, or `foo.bar.ts.net` stops being caught.
    ("tailnet name", r"(?<![\w-])[\w-]+\.ts\.net\b"),
    # Private/LAN search domains. The trailing `(?![\w.-])` is LOAD-BEARING and is not the `\b`
    # the other patterns use: `\b` matches before a `.`, so `[\w-]+\.local\b` fires on
    # `settings.local.json` / `config.local.yml` / `.claude/settings.local.json`, which exist in
    # ordinary repos and would redden CI on a file that leaks nothing. Requiring that NO further
    # label follows keeps the hostname reading (`http://nas-a.lan/`, `ping printer.local`) and
    # drops the filename one.
    #
    # ⚠️ `.internal` IS DELIBERATELY NOT IN THIS LIST, and re-adding it is a regression. ICANN
    # reserved `.internal` in 2024 precisely so it could be used freely, which made it the
    # conventional way to spell a SYNTHETIC host in a fixture — `db.internal` in a test config is
    # a placeholder, not an estate. Denying it produced a false positive on exactly that, and a
    # guard that fires on the approved placeholder convention is a guard people switch off. There
    # is a `_MUST_PASS` case pinning this. If an estate ever genuinely adopts `.internal`, it
    # belongs in the project-side real-literal guard, not here.
    ("private lan domain", r"(?<![\w-])[\w-]+\.(?:lan|local)(?![\w.-])"),
    # Unraid share/pool roots. The PATH is what identifies an estate's storage layout; the bare
    # words are ordinary technical English (`__pycache__`, `--not --remotes`) and matching those
    # produced false failures, so this is anchored to `/mnt/`.
    ("unraid pool path", r"/mnt/(?:apps|user|cache|remotes|disks)\b"),
    # A personal address on a consumer mail provider. Shape, not a specific mailbox.
    # ⚠️ LEFT-BOUNDED with `(?<![\w.+-])`. Without it `[\w.+-]+@` can start at every position in a
    # run of word characters and rescan to the end of the line, so the cost is quadratic in line
    # length: measured at 0.10/0.41/1.62/6.34 s for 4k/8k/16k/32k characters, a clean 4x per
    # doubling. Bounded, 64k takes 0.005 s. The two forms are equivalent, not merely close: over
    # 60 014 strings they agreed on match/no-match in every case — the bound only pins where a
    # match may START, and any match that exists has a leftmost start that no `[\w.+-]` precedes.
    ("personal mail address",
     r"(?<![\w.+-])[\w.+-]+@(?:gmail|outlook|hotmail|yahoo|icloud|proton)\."),
    # Any UUID. Cloudflare Access policy ids look like this, and so do tenant/app ids — all of
    # which identify the estate. A legitimate one (a fixture, a migration revision) is meant to
    # be added to ALLOW_LITERALS deliberately rather than waved through by a looser pattern.
    ("uuid (access policy / tenant id)",
     r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"),
]

# Per-PATH exemptions for a single pattern, as (pattern label, path regex).
#
# EMPTY HERE, AND THAT IS THE EXPECTED STATE for a shape-based denylist: every pattern above
# describes a value that has no business appearing anywhere in this repo, including in build
# output. The mechanism exists because the engine is shared verbatim with the project-side
# real-literal guard, which DOES need one (a scan for the operator's given name false-positives
# on the home-directory path baked into `__pycache__` bytecode). Keeping the two engines
# byte-identical except for their data is what stops them drifting into disagreeing about what
# a repository contains.
#
# ⚠️ This is a per-PATTERN, per-PATH carve-out and never a blanket file skip. Adding a whole
# file here would recreate exactly the "satisfied by looking away" hole the docstring forbids.
PATH_EXEMPT: tuple[tuple[str, str], ...] = ()

# Literals that LOOK like a hit but are allowed. Keep each one justified.
# ⚠️ As of today all three are INERT: none of them matches any current pattern, so removing the
# neutralisation would change no verdict. They are kept as a deliberate carve-out for the
# functional owner path in case a future pattern would catch it — stated here so nobody reads
# this list as evidence that the neutralisation is exercised. `_neutralize` is pinned directly
# (test_the_allow_literals_are_removed_from_a_line), not through a scan verdict that would pass
# either way.
ALLOW_LITERALS: tuple[str, ...] = (
    # The GitHub/GHCR owner path is functional — neutralizing it breaks image pulls and the
    # icon URLs the Unraid templates point at. It is the account name, not infrastructure, and
    # it is in this repository's own clone URL.
    "github.com/texasdaddy",
    "githubusercontent.com/texasdaddy",
    "ghcr.io/texasdaddy",
)

# The documented ways to write an address or a host. These are NEUTRALIZED IN PLACE rather
# than used to skip the line: skipping the line meant one `.env.example` mention could hide a
# real leak sitting beside it, and `.example` matches `.env.example`, which appears in every
# repo's docs.
#
# ⚠️ The host spans are LEFT-BOUNDED and anchor each label with `(?:[\w-]+\.)*`, rather than
# leading with a bare `[\w.-]*` as this file used to. An unbounded leading `[\w.-]*` overlaps the
# `\.` that follows it AND can start at every position in a run of word characters, so the cost
# is quadratic in line length: 2 000 chars 0.06 s, 4 000 chars 0.21 s, 8 000 chars 0.84 s,
# 16 000 chars 3.40 s — a clean 4x per doubling. Bounded and anchored, 16 000 chars complete in
# 0.0005 s.
#
# ⚠️ THE LEFT BOUND IS WHAT MATTERS, and it is easy to mis-attribute: adding `(?<![\w.-])` to the
# OLD flat body also makes it linear, so a "revert" that keeps the bound looks like evidence that
# the anchoring was pointless. It is not the same form. The rule to carry away is that any
# unbounded leading character class is quadratic.
#
# The anchored body is not match-for-match identical to the flat one: it REPORTS cases the flat
# form swallowed (the `<label>-example.tld` shape) and none in the other direction — so the
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
# the leak an earlier batch removed was literally an icon URL inside one.
SKIP_SUFFIXES = (".png", ".jpg", ".jpeg", ".ico", ".gif", ".pdf", ".zip", ".gz",
                 ".woff", ".woff2", ".ttf", ".db", ".sqlite")

# ⛔ THE EXACT PATH, not a substring of the file NAME. This file carries synthetic deny cases by
# design and so cannot be scanned; nothing else earns that exemption. Matching `SELF in name` —
# which this file and its siblings used to do — silently exempts any file whose name merely
# CONTAINS it, `tests/test_check_no_internal_info.py` being the obvious one, and
# `scripts/__pycache__/check_no_internal_info.cpython-312.pyc` being the one that actually bit:
# a tracked, binary, literal-bearing copy the scan skipped in silence. A `.pyc` is deliberately
# NOT in SKIP_SUFFIXES so it surfaces as unreadable-and-therefore-not-cleared instead.
#
# ⚠️ BOTH SCANS USE THIS, and they must agree. The range scan gets its paths from the
# `diff --git a/X b/X` header, which is already repo-relative and posix-separated — the same
# shape as the tree scan's `path.relative_to(root).as_posix()`. If the two disagreed about which
# single file is exempt, one of them would be lying about its coverage.
#
# ⚠️ The project-side real-literal guard deliberately does NOT skip this path. Scanning THIS file
# for real values is the check that keeps the shapes-only promise above honest, and a guard that
# skipped it could not perform that check.
SELF_PATH = "scripts/check_no_internal_info.py"

_ALLOW_SPAN_RX = re.compile("|".join(ALLOW_SPANS), re.IGNORECASE)
_PATH_EXEMPT_RX: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (label, re.compile(rx)) for label, rx in PATH_EXEMPT)

# EVERY git call this makes is bounded — `tracked_files`, the per-commit diff and the fallback
# re-diff alike. A guard that can hang on the push path is the failure the no-silent-hangs
# directive forbids, and a wedged git is indistinguishable from a slow one. These are local
# operations with no network, so the risk is small but not nil: `git diff` can invoke a
# `.gitattributes` textconv filter that shells out. Generous enough that a large repository is
# never the reason it fires.
_GIT_TIMEOUT_S = 120


def _skipped(rel_path: str) -> bool:
    """Files BOTH scans decline to read: known binary suffixes, and this scanner's own source.

    Shared on purpose. If the two scans disagreed about which files count, one of them would be
    lying about its coverage.
    """
    return rel_path.lower().endswith(SKIP_SUFFIXES) or rel_path == SELF_PATH


def _exempt(label: str, rel_path: str) -> bool:
    """Is this PATTERN excused on this PATH? See PATH_EXEMPT — normally nothing is."""
    return any(lb == label and rx.search(rel_path) for lb, rx in _PATH_EXEMPT_RX)


def tracked_files(root: Path) -> list[Path]:
    out = subprocess.run(["git", "ls-files", "-z"], cwd=root, capture_output=True,
                         check=True, timeout=_GIT_TIMEOUT_S)
    return [root / p for p in out.stdout.decode("utf-8").split("\0") if p]


def _neutralize(line: str) -> str:
    for lit in ALLOW_LITERALS:
        line = line.replace(lit, "")
    return _ALLOW_SPAN_RX.sub("", line)


def scan_text(text: str, compiled: list[tuple[str, re.Pattern[str]]],
              rel_path: str = "") -> list[tuple[int, str, str]]:
    """(line number, label, matched text) for every hit in `text`.

    `rel_path` is only consulted for PATH_EXEMPT and defaults to "" so the function stays
    callable on a bare string — which is what `selftest` and most of the tests do.
    """
    hits: list[tuple[int, str, str]] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        stripped = _neutralize(line)
        for label, rx in compiled:
            if rel_path and _exempt(label, rel_path):
                continue
            m = rx.search(stripped)
            if m:
                hits.append((lineno, label, m.group(0)))
    return hits


# --------------------------------------------------------------- scanning the COMMITS
# The empty tree. `git diff <EMPTY_TREE> <sha>` is how the very first commit in a repository is
# diffed, since it has no parent to diff against and `<sha>^` simply fails there.
_EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"

_HUNK_RX = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


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


def resolves(root: Path, rev: str) -> bool:
    """Does `rev` name a commit that exists in THIS clone?

    `^{commit}` and not a bare `--verify`: a 40-hex string that is not an object still parses as
    a SHA-1 for some git subcommands, and the question here is whether the object is present.
    """
    try:
        _git(root, "rev-parse", "--verify", "-q", f"{rev}^{{commit}}")
        return True
    except subprocess.CalledProcessError:
        return False


def commits_in_range(root: Path, rev_range: str) -> list[str]:
    """The commits the range covers, oldest first. Empty is a legitimate answer (nothing new).

    Whitespace-split so multi-token selectors work as well as `A..B` — the pre-push hook needs
    `<sha> --not --remotes` for a BRAND-NEW branch, which has no remote counterpart to diff
    against and would otherwise be scanned as zero commits.
    """
    return list(reversed(_git(root, "rev-list", *rev_range.split()).split()))


def widen_unreachable_base(root: Path, rev_range: str) -> tuple[str, str | None]:
    """Return (range to actually scan, message) — repairing an `A..B` whose BASE is gone.

    ⚠️ THE CASE THIS EXISTS FOR. After a history rewrite, the next push sends
    `github.event.before` = the OLD tip, which no longer exists in the rewritten history. The
    workflow already handles the null sha (branch creation) but not an unreachable one, so the
    range failed to resolve and the guard exited 1 — a RED on the first push after every rewrite,
    for a repository that is in fact clean. Treating it as a hard failure trains people to
    ignore this check, which is worse than any single leak it might catch.

    ⭐ THE REPAIR IS DELIBERATELY FAIL-CLOSED: an unreachable base widens the scan to ALL of the
    head's history, which is strictly MORE than `A..B` would have covered, never less. It is the
    same answer the workflow's branch-creation branch already gives, for the same reason —
    "I could not work out a range" must never be a pass.

    What is NOT repaired, on purpose:
      * an unresolvable HEAD — there is nothing to widen TO, so it stays an error;
      * a multi-token selector (`<sha> --not --remotes`) — it has no single base to lose;
      * a typo'd base that happens to be a valid ref — indistinguishable from a real one, and
        widening is safe anyway.
    A base that DOES resolve is left completely alone, so the ordinary path is untouched.
    """
    if ".." not in rev_range or " " in rev_range.strip():
        return rev_range, None
    base, sep, head = rev_range.partition("...")
    if not sep:
        base, _, head = rev_range.partition("..")
    if not base or not head or resolves(root, base):
        return rev_range, None
    if not resolves(root, head):
        # Nothing to widen to. Fall through unchanged so the normal failure path reports it.
        return rev_range, None
    # ⚠️ ASCII ONLY in anything PRINTED. Every other message in this file is ASCII too, and that
    # is not an accident: this runs from a pre-push hook, where stdout is a pipe and Python falls
    # back to the locale encoding (cp1252 on these workstations). A stray non-ASCII character
    # there raises UnicodeEncodeError and the guard dies mid-verdict. Comments and docstrings are
    # free to use whatever they like; the print path is not.
    return head, (
        f"BASE {base!r} is not present in this clone - almost certainly a history rewrite, "
        f"where the previous tip no longer exists.\n"
        f"WIDENING to {head!r}: every commit reachable from the head is scanned. That is MORE "
        f"than {rev_range!r} asked for, never less, so this is not a way to pass unscanned.")


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

    ⚠️ THE PATH COMES FROM `diff --git`, NOT FROM `+++ `. Keying on the `--- `/`+++ ` header pair
    looks sufficient and is not: a REMOVED content line beginning `-- ` renders as `--- …` and an
    ADDED one beginning `++ ` renders as `+++ …`, so an ordinary pair of prose lines is
    byte-identical to a file header. Proven against real git output — an added line reading
    `++ logo.png` made every following line attribute to `logo.png`, which `scan_added` then
    skipped as a binary asset, and a genuine leak on the next line scanned CLEAN. `in_hunk`
    closes it structurally: once `@@` has been seen, nothing until the next `diff --git` can be a
    header, which is exactly git's own grammar.

    ⚠️ A BINARY DIFF CARRIES NO LINES, so it must be REPORTED rather than passed over. The tree
    scan already refuses to vouch for what it cannot decode; a UTF-16 file is invisible to both
    scans otherwise, which is a hole rather than a limit.
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
            # ⚠️ A DELETION PUBLISHES NOTHING. `Binary files a/x and /dev/null differ` is a
            # removal, and reporting it would make every commit that deletes a binary — or the
            # delete half of a binary rename — fail forever. That is the same trap the
            # removed-lines rule above avoids: a guard that punishes cleanup gets switched off.
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

    ⚠️ "git called it binary" IS NOT "it is unreadable". git says that for a `.gitattributes`
    `-diff`/`binary` attribute too — standard practice for a generated lockfile — and for UTF-8
    text carrying one stray NUL. Reporting those as "not scanned" reddens ordinary work with
    remediation advice that is simply wrong ("commit the file as UTF-8 text" — it already IS).

    So each flagged path is RE-DIFFED with `--text`, which forces git to emit real hunks, and the
    result is decoded strictly. Decodes → those are the lines this commit added, scanned like any
    other. Fails → the content genuinely is not UTF-8, and it stays unscannable so the run
    refuses to clear it.

    ⚠️ RE-DIFF, NOT RE-READ. The first version of this fetched the whole blob and scanned every
    line of it. That costs 15.9 s per commit on a 24 MB `-diff` blob, so a 200-commit PR touching
    a large lockfile extrapolates to ~50 MINUTES, on the push path and in CI — the hang the
    no-silent-hangs directive forbids, re-entering through a door opened while closing another.
    It also attributed a PRE-EXISTING leak to whichever innocent commit last touched the file.
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


def scan_added(sha: str, parsed: ParsedDiff,
               compiled: list[tuple[str, re.Pattern[str]]]) -> tuple[list[str], list[str]]:
    """(findings, unscannable) for one commit. Skips the same files the tree scan skips, or the
    two scans would disagree about what this repository contains."""
    findings: list[str] = []
    for path, lineno, content in parsed.added:
        if _skipped(path):
            continue
        for _, label, match in scan_text(content, compiled, path):
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


# Deny cases are SYNTHETIC by construction — reserved documentation ranges (RFC5737), the top of
# the CGNAT block, `.invalid` hosts (RFC 2606) and invented labels. None of them is a value from
# any real estate, and none needs to be: these patterns match SHAPES, so a synthetic instance of
# the shape exercises them exactly as well as a real one would.
_MUST_FAIL: list[tuple[str, str]] = [
    ("private IPv4 (RFC1918)", "DATABASE_URL=postgresql://u:p@192.168.77.77:5432/db"),
    ("private IPv4 (RFC1918)", "allowlist = '10.99.99.0/24'"),
    ("private IPv4 (RFC1918)", "peer 172.31.255.254 is not allowed"),
    # The bare-prose form: a sentence-final period must not hide it.
    ("private IPv4 (RFC1918)", "The database lives at 192.168.77.77."),
    # 100.127.255.254 is the very top of the CGNAT block rather than any host anywhere.
    ("cgnat address", "agent reachable on 100.127.255.254:9999"),
    ("tailnet name", "https://host-a.tailnet-example.ts.net/"),
    ("private lan domain", "AGENT_URL=http://host-a.lan:9999/mcp"),
    ("private lan domain", "ping printer-b.local"),
    ("unraid pool path", 'Default="/mnt/apps/appdata/svc/data"'),
    ("unraid pool path", "Run from: cd /mnt/user/appdata/svc"),
    ("personal mail address", "_UA = 'Research someone@gmail.invalid'"),
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
    "copy .env.example and fill it in",
    # ⭐ The `.local` FILENAME cases the `(?![\w.-])` bound exists for. All three occur in
    # ordinary repositories, and `[\w-]+\.local\b` reddens CI on every one of them.
    'cp .claude/settings.local.json.tmpl .claude/settings.local.json',
    "load_config('config.local.yml')",
    "docker compose -f compose.local.yaml up",
    # ⭐ Pins the deliberate `.internal` exclusion documented on the pattern above. This exact
    # string is a real fixture in one of the fleet repos; if someone re-adds `.internal` to the
    # denylist, this case fails and says why rather than reddening that repo's CI mysteriously.
    'DATABASE_URL=postgresql://u:p@db.internal:5432/app',
    # near-misses for the five patterns that had none. Each is a shape that LOOKS like its
    # pattern and must not fire, which is what fails if that pattern is ever widened.
    "cgnat neighbours 100.63.255.254 and 100.128.0.1 are outside the range",
    'import helper from "./net.ts" then re-export',
    "store it under /mnt/POOL/appdata/runner-REPO/docker",
    "contact noreply@example.com or support@github.com",
    "pinned action SHA 3d3c42e5aac5ba805825da76410c181273ba90b1",
    # The reason ALLOW_SPANS neutralizes a SPAN and not the LINE: a permitted token must not
    # grant amnesty to a real leak sharing the line with it.
]

_MUST_FAIL_COMBINED = "# see example.com; real host is host-a.private-example.lan"


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


# ------------------------------------------------------------------------ the command line
USAGE = """usage: check_no_internal_info.py [--selftest | --range <revision-range>] [--repo <path>]

  (no arguments)              scan the tracked working TREE
  --selftest                  prove the denylist patterns still bite
  --range <A..B>              scan the lines ADDED by every commit in the range
  --range=<A..B>              the same, joined form
  --repo <path>               the repository to scan (default: the one containing $PWD)
  -h, --help                  this message

exit codes: 0 clean | 1 a finding, something unreadable, or a range git could not resolve
            2 a usage error (this message)"""


class UsageError(Exception):
    """An argument this scanner does not understand.

    Its own exception type so `main` cannot accidentally swallow it with the git failures, and so
    a caller embedding this module gets something catchable rather than a bare exit.
    """


class Args(NamedTuple):
    selftest: bool
    rev_range: str | None
    repo: str | None
    help: bool


def _value_for(flag: str, argv: list[str], i: int) -> str:
    """The argument after `flag`, rejecting a missing one and a following flag alike.

    `--range --selftest` would otherwise swallow the flag as a revision range and fail later with
    "could not scan '--selftest'" — fail-closed, but it reports the wrong problem, and a contract
    headed "every argument is parsed" should not have a hole where an argument is silently
    consumed as a value.
    """
    if i + 1 >= len(argv):
        raise UsageError(f"{flag} needs a value")
    value = argv[i + 1]
    if value.startswith("-"):
        raise UsageError(f"{flag} takes a value, not another flag (got {value!r})")
    return value


def parse_args(argv: list[str]) -> Args:
    """Parse the command line STRICTLY.

    Every token is either recognised or an error. There is no fall-through, because the
    fall-through WAS the bug: a version of this scanner tested `"--selftest" in argv` and IGNORED
    everything else, so the documented `--range origin/dev..HEAD` scan was a TREE scan run twice,
    reporting clean regardless of the commits being pushed. An unrecognised argument leaving the
    caller believing a commit-range scan had run is the one failure mode a guard cannot have.
    """
    selftest = False
    rev_range: str | None = None
    repo: str | None = None
    want_help = False
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg in ("-h", "--help"):
            want_help = True
        elif arg == "--selftest":
            selftest = True
        elif arg == "--range":
            rev_range = _value_for("--range", argv, i)
            i += 1
        elif arg.startswith("--range="):
            rev_range = arg[len("--range="):]
            if not rev_range:
                raise UsageError("--range needs a revision range, e.g. --range origin/main..HEAD")
            # The same check the spaced form makes. Leaving it out of this branch was the "fixed
            # the instance, not the class" shape all over again, one `elif` away from the fix.
            if rev_range.startswith("-"):
                raise UsageError(
                    f"--range takes a revision range, not another flag (got {rev_range!r})")
        elif arg == "--repo":
            repo = _value_for("--repo", argv, i)
            i += 1
        elif arg.startswith("--repo="):
            repo = arg[len("--repo="):]
            if not repo:
                raise UsageError("--repo needs a path")
        else:
            # Includes a BARE revision range. `check_no_internal_info.py origin/main..HEAD` reads
            # like it would scan the range and would otherwise have run a tree scan and called it
            # clean — the same silent substitution this whole change exists to remove.
            raise UsageError(f"unrecognised argument: {arg!r}")
        i += 1
    if selftest and rev_range is not None:
        raise UsageError("--selftest and --range do different things; run them one at a time")
    if want_help and (selftest or rev_range is not None):
        # `--range A..B --help` printed the usage and exited 0 — an accepted argument combination
        # that substitutes "no scan" for a scan and reports success. That is the same shape as the
        # ignored-argument defect, just harder to reach, so it is an error rather than a silent
        # preference.
        raise UsageError("--help does not combine with a scan; run one or the other")
    return Args(selftest, rev_range, repo, want_help)


def _scan_tree(root: Path, compiled: list[tuple[str, re.Pattern[str]]]) -> int:
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
            continue  # in the index but not the worktree
        except (OSError, UnicodeDecodeError):
            # NOT silent: a file this scanner cannot read is a file it cannot vouch for.
            # `OSError` as well as the decode error, because `git ls-files` lists things that are
            # not readable files: a submodule gitlink is a DIRECTORY here (IsADirectoryError on
            # POSIX, PermissionError on Windows), and a dangling symlink lands here too. Those
            # escaped as a traceback rather than a verdict, which blocks every commit in such a
            # repository while explaining nothing.
            undecodable.append(rel)
            continue
        scanned += 1
        findings += [f"{rel}:{n}: {label}: {match!r}"
                     for n, label, match in scan_text(text, compiled, rel)]

    if undecodable:
        print(f"UNREADABLE as UTF-8 ({len(undecodable)}) - not scanned, so not cleared:")
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
              f"{SELF_PATH} with a comment saying why.")
    if findings or undecodable:
        return 1
    print(f"no internal info found ({scanned} tracked text files scanned)")
    return 0


def is_shallow(root: Path) -> bool:
    """Is this a truncated clone? `--is-shallow-repository` prints `true`/`false`."""
    try:
        return _git(root, "rev-parse", "--is-shallow-repository").strip() == "true"
    except subprocess.CalledProcessError:  # pragma: no cover - git predating the flag
        return False


def _scan_commits(root: Path, rev_range: str,
                  compiled: list[tuple[str, re.Pattern[str]]]) -> int:
    if is_shallow(root):
        # ⛔ A SHALLOW CLONE DOES NOT FAIL LOUDLY ON ITS OWN. `git rev-list` succeeds against the
        # truncated history and returns the truncated count, and the boundary commit's missing
        # parent falls into the empty-tree branch — so the scan degenerates to "this one commit's
        # whole tree", prints a cheerful `no internal info added across 1 commit(s)`, and exits 0
        # having never seen the history the range names. The workflows pin `fetch-depth: 0`, so
        # this is not live; the point is that the safety net has to exist rather than be asserted,
        # or the day someone drops that line the guard fails OPEN and silently.
        print("REFUSING to scan a SHALLOW clone: the history is truncated, so a range scan here "
              "would report on commits it cannot see.")
        print("Fetch the full history first (CI: `fetch-depth: 0`, locally: "
              "`git fetch --unshallow`).")
        return 1
    rev_range, widened = widen_unreachable_base(root, rev_range)
    if widened:
        print(widened)
    try:
        result = scan_range(root, rev_range, compiled)
    except subprocess.CalledProcessError as exc:
        # A range git cannot resolve is NOT a pass. A shallow clone, an unfetched base or a typo
        # would otherwise scan zero commits and print a clean result — the one failure mode a
        # guard must never have.
        print(f"could not scan {rev_range!r}: git exited {exc.returncode}. "
              f"Fetch the base ref (CI needs fetch-depth: 0) or check the range.")
        return 1
    if result.unscannable:
        # Same posture as the tree scan's `undecodable` list: a blob this cannot read is a blob
        # it cannot vouch for.
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


def repo_root(start: str | None) -> Path:
    """The top level of the repository to scan."""
    return Path(subprocess.run(["git", "rev-parse", "--show-toplevel"], cwd=start,
                               capture_output=True, check=True, text=True,
                               timeout=_GIT_TIMEOUT_S).stdout.strip())


def main(argv: list[str]) -> int:
    try:
        args = parse_args(argv)
    except UsageError as exc:
        print(f"{exc}\n\n{USAGE}", file=sys.stderr)
        return 2
    if args.help:
        print(USAGE)
        return 0

    compiled = [(label, re.compile(rx, re.IGNORECASE)) for label, rx in PATTERNS]
    if args.selftest:
        return selftest(compiled)

    root = repo_root(args.repo)
    if args.rev_range is not None:
        return _scan_commits(root, args.rev_range, compiled)
    return _scan_tree(root, compiled)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
