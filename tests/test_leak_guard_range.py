"""The leak guard must scan the COMMITS being pushed, not just the working tree.

WHY THIS FILE EXISTS
    `scripts/check_no_internal_info.py` scanned `git ls-files` and nothing else. That answers
    "is the leak here NOW", and it has two blind spots that a push turns permanent:

    1. A BRAND-NEW FILE IS NOT TRACKED YET. `git ls-files` lists the index, so a file that has
       not been `git add`ed is not scanned, not reported unreadable, and not counted — it is
       simply absent from the run that prints "no internal info found". Run the guard before
       staging and it clears a tree that does not contain the very file you just wrote. That is
       how a synthetic internal hostname reached a public remote.
    2. A VALUE COMMITTED AND THEN DELETED is absent from the tree too, and stays permanently
       readable at the commit that added it once the branch reaches the remote.

    Both are recoverable only by a history rewrite and a force-push across every clone.

    `test_a_leak_in_a_BRAND_NEW_UNTRACKED_file_...` and
    `test_a_leak_added_then_deleted_...` are the tests that would have caught them. Each
    asserts BOTH halves — the tree scan's blindness AND the range scan closing it — so they
    fail if the range scan is removed and they document why the tree scan alone was never
    enough.

SHAPE
    The diff PARSING is a pure function (`parse_diff`), so most of this runs with no repository
    at all. The tests that build a real repo do so because the claim is about real git history,
    and a synthetic diff would be assuming the thing under test. Those are slow on Windows — a
    commit costs seconds once a virus scanner is watching `.git` — so they carry explicit
    timeouts.

⚠️ EVERY LEAKING LITERAL HERE IS BUILT AT RUNTIME, and every one of them is synthetic
    (`.invalid` is reserved by RFC 2606; the addresses are implausible). Written out whole, they
    would make THIS FILE a finding of the very scanner it tests: the guard skips exactly one
    file, its own source, and the working-tree scan runs on every commit.

    ⭐ THE DENYLIST IS SHAPES ONLY, so there is no longer a real token for this file to avoid
    naming. It used to hold real values — first as plaintext, then base64-encoded — and both
    forms shipped those values in a public repo. They now live in a guard kept in the project
    working directory that is never committed anywhere, and that guard is what runs against the
    staged tree before every push.

    That relocation is why `test_guard_source_carries_no_plaintext_token` is gone: a repository
    that no longer knows the real tokens cannot assert their absence, and a test that pretended
    to would be checking nothing. What CAN be asserted from here is that no real-literal denylist
    has crept back in at all — see `test_the_guard_carries_no_real_literal_denylist` and
    `test_the_denylist_is_the_agreed_shape_set`, which pin the structure rather than the values.
"""

from __future__ import annotations

import importlib.util
import re
import subprocess
import sys
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "check_no_internal_info.py"

# `scripts/` is not a package, so import the module by path rather than by name.
_spec = importlib.util.spec_from_file_location("check_no_internal_info_under_test", _SCRIPT)
assert _spec and _spec.loader
guard = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(guard)

# ⛔ `guard.compile_patterns()`, NOT an inlined `re.compile(rx, re.IGNORECASE)`. This file used
# to inline the identical line, which meant the tests held their OWN correct copy of the flags:
# dropping `re.IGNORECASE` from the shipped scan would have left this suite and CI entirely green
# while a real repository containing an uppercase LAN host or a mixed-case freemail address
# scanned clean and exited 0. The tests must exercise what ships.
COMPILED = guard.compile_patterns()

# ⚠️ SPLIT FRAGMENTS AGAIN, AND FOR A BETTER REASON THAN THE FIRST TIME.
#
# These were fragments (`"rein" + "lie"`), then a read-back from the guard's base64 token table.
# Both were workarounds for one underlying problem: the denylist held REAL values, so this file
# could not name a deny case without republishing one. That problem is gone — the denylist is
# shapes only. Every value below is synthetic.
#
# They stay split because THIS FILE IS SCANNED BY THE GUARD. Only
# `scripts/check_no_internal_info.py` is exempt (SELF_PATH); a test file that spelled a deny case
# out whole would make the guard fail on its own test suite. Neither fragment matches alone.
_POOL = "/mnt/" + "apps"
_LEAK = f"{_POOL}/appdata/example/data"
# Matches "private lan domain". A `.lan` name is private by definition and resolves nowhere off
# the network that defines it.
_HOST = "nas-a." + "lan"
# Matches "private IPv4 (RFC1918)". Synthetic: .77.77 is not a host on any network here.
_ADDR = "192.168." + "77.77"


def _added(diff: str) -> list[tuple[str, int, str]]:
    return guard.parse_diff(diff).added


def _binary(diff: str) -> list[str]:
    return guard.parse_diff(diff).unscannable


def _hits(sha: str, added: list[tuple[str, int, str]]) -> list[str]:
    return guard.scan_added(sha, guard.ParsedDiff(added, []), COMPILED)[0]


def _git(repo: Path, *args: str) -> str:
    out = subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.com", *args],
        cwd=repo, capture_output=True, check=True)
    return out.stdout.decode("utf-8", errors="replace")


def _tree_findings(repo: Path) -> list[str]:
    """The tree scan's own logic, minus `main()`'s printing: what `git ls-files` yields, skipping
    what the guard skips. Deliberately mirrors `main()` so the assertions below are about the
    real code path and not a convenient stand-in."""
    out = []
    for p in guard.tracked_files(repo):
        rel = p.relative_to(repo).as_posix()
        # ⚠️ `repo` and `rel` ARE PASSED, matching production exactly. Dropping them made this
        # stand-in skip MORE files and scan LESS than `_scan_tree` does — and since it is used to
        # establish NEGATIVE premises ("the files are clean, only the author is not"), a laxer
        # stand-in makes those premises easier to satisfy, which is the wrong direction.
        if guard._skipped(rel, repo):
            continue
        try:
            text = p.read_text(encoding="utf-8")
        except (FileNotFoundError, UnicodeDecodeError):
            continue
        out += [f"{rel}:{n}: {label}" for n, label, _ in guard.scan_text(text, COMPILED, rel)]
    return out


def _init(repo: Path) -> None:
    repo.mkdir(parents=True, exist_ok=True)
    _git(repo, "init", "-q", "-b", "main")


# ------------------------------------------------------------------ THE regression (untracked)


@pytest.mark.timeout(300)
def test_a_leak_in_a_BRAND_NEW_UNTRACKED_file_is_invisible_to_the_tree_scan_and_caught_by_range(
    tmp_path: Path,
):
    """⭐ THE ONE THIS BATCH EXISTS FOR, on a real repository because the claim is about `git
    ls-files` and real history.

    The sequence that leaked: write a new file, run the guard (it reads the INDEX, which does
    not contain the file yet, and prints "no internal info found"), then `git add` + commit +
    push. Nothing ever looked at the file's contents.

    Three halves are asserted:
      1. the file is genuinely untracked — `tracked_files` does not list it;
      2. the tree scan therefore reports NOTHING, which is the blind spot, not a bug in it;
      3. once committed, the range scan reports it and names the commit to rewrite.

    Delete the range scan and (3) fails. "Fix" the tree scan to somehow see untracked files and
    (2) tells you the premise changed.
    """
    repo = tmp_path / "untracked"
    _init(repo)
    (repo / "README.md").write_text("clean\n", encoding="utf-8")
    _git(repo, "add", "README.md")
    _git(repo, "commit", "-qm", "base")
    base = _git(repo, "rev-parse", "HEAD").strip()

    # The new file. NOT staged — this is the state the guard was run in.
    leaky = repo / "templates" / "new-service.xml"
    leaky.parent.mkdir(parents=True, exist_ok=True)
    leaky.write_text(
        f'<Config Name="Data" Target="/data" Default="{_LEAK}"/>\n'
        f"<!-- reachable at {_HOST} ({_ADDR}) -->\n",
        encoding="utf-8",
    )

    # (1) genuinely untracked.
    tracked = [p.relative_to(repo).as_posix() for p in guard.tracked_files(repo)]
    assert "templates/new-service.xml" not in tracked, (
        "the premise is broken: the file is supposed to be UNTRACKED at this point"
    )

    # (2) so the tree scan clears a tree that does not contain it. This is the leak.
    assert _tree_findings(repo) == [], (
        "the tree scan is expected to MISS an unstaged file — it reads the index, and that "
        "blindness is the entire reason --range exists"
    )

    # ...and now it gets committed, exactly as it did when this leaked.
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "add the new template")
    head = _git(repo, "rev-parse", "HEAD").strip()

    # (3) the range scan sees what the commit ADDED, so a new file's first commit is all of it.
    result = guard.scan_range(repo, f"{base}..{head}", COMPILED)
    assert result.commits == 1
    assert result.unscannable == []
    labels = " ".join(result.findings)
    assert "unraid pool path" in labels, f"the pool path was not caught: {result.findings}"
    assert "private lan domain" in labels, f"the hostname was not caught: {result.findings}"
    assert "private IPv4 (RFC1918)" in labels, f"the address was not caught: {result.findings}"
    assert all("templates/new-service.xml" in f for f in result.findings)
    assert all(head[:10] in f for f in result.findings), (
        "the offending COMMIT must be named — that is what gets rewritten"
    )


@pytest.mark.timeout(300)
def test_the_CLI_catches_the_untracked_file_case_and_exits_1(tmp_path: Path):
    """The same regression through the entry point CI and the hook actually call. The exit code
    IS the contract: a scan that finds this and returns 0 gates nothing."""
    repo = tmp_path / "untracked-cli"
    _init(repo)
    (repo / "README.md").write_text("clean\n", encoding="utf-8")
    _git(repo, "add", "README.md")
    _git(repo, "commit", "-qm", "base")
    base = _git(repo, "rev-parse", "HEAD").strip()

    (repo / "notes.md").write_text(f"see {_HOST}\n", encoding="utf-8")
    # The tree scan, run BEFORE staging, is clean — reproduce that explicitly.
    before_add = _cli(repo)
    assert before_add.returncode == 0, (
        "the pre-`git add` tree scan is expected to pass; if it now fails, this test's premise "
        f"changed:\n{before_add.stdout}"
    )
    assert "no internal info found" in before_add.stdout

    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "adds an untracked-until-now file")
    head = _git(repo, "rev-parse", "HEAD").strip()

    # After `git add` the tree scan would now catch it too — assert that, because it is the
    # reason "run the scan AFTER git add" is the documented order.
    after_add = _cli(repo)
    assert after_add.returncode == 1, (
        f"once tracked, the tree scan must see it:\n{after_add.stdout}"
    )

    ranged = _cli(repo, "--range", f"{base}..{head}")
    assert ranged.returncode == 1, f"the range scan must fail on this:\n{ranged.stdout}"
    assert "pushing publishes HISTORY" in ranged.stdout
    assert "private lan domain" in ranged.stdout


# --------------------------------------------------------------- the added-then-deleted case


@pytest.mark.timeout(300)
def test_a_leak_added_then_deleted_passes_the_tree_scan_and_fails_the_range_scan(tmp_path: Path):
    """The other tree-scan blind spot: a value that is gone from the tree but permanent in the
    history. Both halves asserted, same reasoning as the untracked case."""
    repo = tmp_path / "throwaway"
    _init(repo)

    def commit(body: str, message: str) -> str:
        (repo / "notes.md").write_text(body, encoding="utf-8")
        _git(repo, "add", "notes.md")
        _git(repo, "commit", "-qm", message)
        return _git(repo, "rev-parse", "HEAD").strip()

    base = commit("nothing here\n", "base")
    commit(f"host path is {_LEAK}\n", "adds a leak")
    head = commit("nothing here\n", "removes it again")

    assert _tree_findings(repo) == [], (
        "the tree scan is expected to MISS this — it is the other reason --range exists")

    result = guard.scan_range(repo, f"{base}..{head}", COMPILED)
    assert result.commits == 2
    assert result.unscannable == []
    assert len(result.findings) == 1, f"expected one added leak, got {result.findings}"
    assert "unraid pool path" in result.findings[0]


# --------------------------------------------------------------------- the diff parser


def test_added_lines_are_returned_with_their_new_file_line_numbers():
    diff = (
        "diff --git a/a.md b/a.md\n"
        "--- a/a.md\n"
        "+++ b/a.md\n"
        "@@ -0,0 +7,2 @@\n"
        "+first\n"
        "+second\n"
    )
    assert _added(diff) == [("a.md", 7, "first"), ("a.md", 8, "second")]


def test_removed_lines_are_ignored():
    """Reporting removals would make every cleanup commit fail forever — the guard would punish
    the fix and get switched off."""
    diff = (
        "diff --git a/a.md b/a.md\n"
        "--- a/a.md\n"
        "+++ b/a.md\n"
        "@@ -3,1 +3,0 @@\n"
        f"-{_LEAK}\n"
    )
    assert _added(diff) == []


def test_a_deleted_file_contributes_nothing():
    diff = (
        "diff --git a/gone.md b/gone.md\n"
        "--- a/gone.md\n"
        "+++ /dev/null\n"
        "@@ -1,1 +0,0 @@\n"
        f"-{_LEAK}\n"
    )
    assert _added(diff) == []


def test_a_removed_line_and_an_added_line_cannot_FAKE_a_file_header():
    """GUARD ATTACK. A removed content line beginning `-- ` renders as `--- …`; an added one
    beginning `++ ` renders as `+++ …`. The pair is byte-identical to a real header, so a parser
    keying on it reads `logo.png` as the current file — which `scan_added` then skips as a binary
    asset, and a genuine leak on the very next line scans CLEAN. Taking the path from
    `diff --git` and gating on `in_hunk` closes it structurally: that is git's own grammar."""
    diff = (
        "diff --git a/notes.md b/notes.md\n"
        "--- a/notes.md\n"
        "+++ b/notes.md\n"
        "@@ -2 +2,3 @@ line one\n"
        "--- was a caption\n"
        "+++ logo.png\n"
        f"+{_LEAK}\n"
    )
    added = _added(diff)
    assert [a[0] for a in added] == ["notes.md", "notes.md"], (
        f"the faked header stole the path: {added}")
    assert _hits("abc", added), "the leak after a faked header was not reported"


def test_multiple_hunks_and_files_each_restart_their_line_count():
    diff = (
        "diff --git a/a.md b/a.md\n"
        "--- a/a.md\n"
        "+++ b/a.md\n"
        "@@ -0,0 +2,1 @@\n"
        "+in a\n"
        "@@ -0,0 +40,1 @@\n"
        "+also in a\n"
        "diff --git a/b.md b/b.md\n"
        "--- a/b.md\n"
        "+++ b/b.md\n"
        "@@ -0,0 +1,1 @@\n"
        "+in b\n"
    )
    assert _added(diff) == [
        ("a.md", 2, "in a"), ("a.md", 40, "also in a"), ("b.md", 1, "in b")]


# --------------------------------------------------------------- what gets scanned


def test_scan_added_reports_a_leak_with_its_file_and_line():
    findings = _hits("abcdef1234567890", [("notes.md", 12, f"path {_LEAK}")])
    assert len(findings) == 1
    assert "notes.md:12" in findings[0]
    assert "unraid pool path" in findings[0]
    assert "abcdef1234" in findings[0]


def test_scan_added_passes_a_clean_line():
    assert _hits("abc", [("notes.md", 1, "/srv/data/example is fine")]) == []


def test_binary_suffixes_are_skipped_exactly_as_the_tree_scan_skips_them():
    """If the two scans disagree about which files count, one of them is lying about coverage."""
    for suffix in guard.SKIP_SUFFIXES:
        assert _hits("abc", [(f"assets/asset{suffix}", 1, _LEAK)]) == [], suffix


def test_the_guards_own_source_is_skipped_in_range_mode_BY_EXACT_PATH_ONLY():
    """⭐ The self-skip is an EXACT repo-relative path, not a substring of the filename.

    The substring form (`SELF in path.name`) also matched
    `scripts/__pycache__/check_no_internal_info.cpython-312.pyc` — a tracked, binary,
    literal-bearing copy of the scanner that the scan therefore skipped in silence. Both
    directions are pinned here, in RANGE mode, because the range scan is the newer of the two
    and the one most likely to be re-derived from a repo that still has the loose form.
    """
    assert _hits("abc", [(guard.SELF_PATH, 5, _LEAK)]) == [], (
        "the guard's own source must be skipped — it carries synthetic deny cases by design")
    assert _hits("abc", [
        ("scripts/__pycache__/check_no_internal_info.cpython-312.pyc", 5, _LEAK)
    ]), "a .pyc copy of the scanner is NOT the scanner and must still be scanned"
    assert _hits("abc", [("docs/check_no_internal_info.py", 5, _LEAK)]), (
        "only the real path is exempt; a same-named file elsewhere is not")


def test_allow_spans_still_apply_to_added_lines():
    """The range scan must share the tree scan's allowlist, or a documented RFC5737 example in a
    new file would block a push."""
    assert _hits("abc", [("README.md", 1, "host 192.0.2.5 # RFC5737")]) == []


def test_an_allowed_token_does_not_grant_amnesty_to_a_leak_sharing_the_line():
    findings = _hits("abc", [("README.md", 1, f"see example.com; real path {_LEAK}")])
    assert findings, "a permitted token on the same line hid a real leak"


def test_the_allow_spans_are_linear_not_quadratic():
    """⭐ A HANG IS THE FAILURE MODE A PUSH-PATH GUARD CANNOT HAVE.

    The flat `[\\w.-]*\\bexample\\.(?:com|org|net)` form backtracked quadratically: ~0.29 s at
    4 000 chars, 4.6 s at 16 000, 29 s at 32 000 — a 200 KB minified line or a base64 data URI
    extrapolates to ~19 minutes. Survivable while this only scanned a tracked tree; `--range`
    puts it on the push path and in CI. Anchoring each label with `(?:[\\w-]+\\.)*` makes it
    linear: 16 k chars in ~0.001 s. Bounded rather than timed precisely — the point is the ORDER
    of growth, and a tight wall-clock assertion on a shared runner is its own flake.
    """
    import time

    line = "z" * 16_000
    start = time.perf_counter()
    guard.scan_text(line, COMPILED)
    elapsed = time.perf_counter() - start
    assert elapsed < 2.0, (
        f"scanning one 16k-char line took {elapsed:.1f}s — the allow-spans are backtracking "
        f"quadratically again; anchor each label with (?:[\\w-]+\\.)*"
    )


# ------------------------------------------------------- unreadable content is not cleared


def test_a_binary_file_is_reported_as_NOT_CLEARED_rather_than_passed_over():
    """A UTF-16 file carries no diff lines, so the range scan would simply see nothing — and once
    a later commit deletes it, the tree scan is clean too and the content was never read by
    anything. The tree scan refuses to vouch for what it cannot decode; the range scan takes the
    same posture or it is quieter than the scan it exists to reinforce."""
    diff = (
        "diff --git a/u16.txt b/u16.txt\n"
        "new file mode 100644\n"
        "index 0000000..1111111\n"
        "Binary files /dev/null and b/u16.txt differ\n"
    )
    assert _binary(diff) == ["u16.txt"]
    _, blind = guard.scan_added("abc", guard.parse_diff(diff), COMPILED)
    assert blind == ["abc u16.txt"]


def test_DELETING_a_binary_file_is_not_reported():
    """A deletion publishes nothing. Reporting it would make every commit that removes a binary —
    and the delete half of a binary rename — fail forever, which is the same trap the
    removed-lines rule avoids: a guard that punishes cleanup gets switched off."""
    diff = ("diff --git a/old.xlsx b/old.xlsx\n"
            "deleted file mode 100644\n"
            "Binary files a/old.xlsx and /dev/null differ\n")
    assert _binary(diff) == []
    assert _added(diff) == []


# ------------------------------------- the entry point CI and the hook actually call


def _cli(repo: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(_SCRIPT), *args],
                          cwd=repo, capture_output=True, text=True, check=False)


@pytest.mark.timeout(300)
def test_the_CLI_entrypoint_returns_the_exit_codes_CI_and_the_hook_depend_on(tmp_path: Path):
    """⭐ `.github/workflows/ci.yml` and `.githooks/pre-push` call this entry point and nothing
    else, so these exit codes ARE the contract. The load-bearing one is the unresolvable range:
    a shallow clone or an unfetched base must not scan zero commits and print a clean bill of
    health."""
    repo = tmp_path / "cli"
    _init(repo)

    def commit(body: str, message: str) -> str:
        (repo / "notes.md").write_text(body, encoding="utf-8")
        _git(repo, "add", "notes.md")
        _git(repo, "commit", "-qm", message)
        return _git(repo, "rev-parse", "HEAD").strip()

    base = commit("clean\n", "base")
    commit(f"path {_LEAK}\n", "adds a leak")
    head = commit("clean again\n", "removes it")

    leaky = _cli(repo, "--range", f"{base}..{head}")
    assert leaky.returncode == 1, f"a leak in history exited {leaky.returncode}: {leaky.stdout}"
    assert "pushing publishes HISTORY" in leaky.stdout

    clean = _cli(repo, "--range", f"{head}..{head}")
    assert clean.returncode == 0, f"an empty range must pass: {clean.stdout}"

    # An unreachable BASE widens to the head's whole history rather than failing -- see
    # test_an_unreachable_base_widens_instead_of_redding for why. It must still REPORT the leak
    # that history contains, which is what this asserts: widening is not a way to pass.
    widened = _cli(repo, "--range", "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef..HEAD")
    assert "WIDENING" in widened.stdout, (
        "an unreachable base must say so, not fail silently: " + widened.stdout)
    assert widened.returncode == 1, (
        "WIDENING MUST NOT LOSE THE FINDING -- it scans MORE history, not less: " + widened.stdout)

    # An unresolvable HEAD is a different matter: there is nothing to widen TO, so it stays an
    # error. This is the half of the old contract that must not be relaxed.
    broken = _cli(repo, "--range", "HEAD..deadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
    assert broken.returncode == 1, (
        "AN UNRESOLVABLE HEAD MUST NOT REPORT CLEAN: " + broken.stdout)
    assert "could not scan" in broken.stdout

    assert _cli(repo, "--range").returncode == 2, "a missing argument is a usage error"

@pytest.mark.timeout(300)
def test_an_unreachable_base_widens_instead_of_redding(tmp_path: Path):
    """⭐ THE POST-REWRITE RED. After a history rewrite the previous tip stops existing, so the
    very next push hands CI `github.event.before..HEAD` with a base that is no longer in the
    repository. The workflow already special-cases the NULL sha (branch creation); it never
    handled an UNREACHABLE one, so the guard exited 1 on a repository that was in fact clean --
    and a required check that reds for a reason nobody can act on is a check people route around.

    The repair is deliberately fail-closed: an unreachable base widens to every commit reachable
    from the head, which is strictly MORE than the named range covered, never less. Here the
    history is clean, so it passes -- and says plainly that it widened.
    """
    repo = tmp_path / "rewritten"
    _init(repo)
    (repo / "README.md").write_text("clean\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "clean root, as if just after a rewrite")

    result = _cli(repo, "--range", "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef..HEAD")
    assert result.returncode == 0, (
        "a clean history behind an unreachable base must PASS, not red: " + result.stdout)
    assert "WIDENING" in result.stdout, (
        "the widening has to be announced -- a silent change of scope is its own defect: "
        + result.stdout)
    assert "no internal info added" in result.stdout


def test_the_selftest_still_passes_through_the_CLI():
    """`--selftest` proves the PATTERNS still bite. Both hooks and both CI paths run it first."""
    result = _cli(_SCRIPT.parents[1], "--selftest")
    assert result.returncode == 0, result.stdout


# ------------------------------------------------- the wiring, without which none of it runs


def test_neither_git_hook_probes_python3_the_way_windows_lies_about():
    """⭐ `git config core.hooksPath .githooks` — the one-time opt-in both hooks document —
    installs BOTH. On Windows `command -v python3` returns 0 because it resolves the Microsoft
    Store App Execution Alias stub, which then refuses to run: every commit and every push
    aborts with "Python was not found" and no mention of the guard. Pinned for both hooks,
    because fixing one of two is exactly the mistake this catches."""
    hooks = _SCRIPT.parents[1] / ".githooks"
    for hook in ("pre-commit", "pre-push"):
        text = (hooks / hook).read_text(encoding="utf-8")
        # COMMENT lines are excluded on purpose: both hooks explain in prose why
        # `command -v python3` is wrong, and a naive substring check flags its own rationale.
        code = [ln for ln in text.splitlines() if not ln.lstrip().startswith("#")]
        assert not any("command -v python3" in ln for ln in code), (
            f".githooks/{hook} probes with `command -v python3`, which succeeds on Windows for "
            f"a stub that then refuses to run")
        assert any('python3 -c ""' in ln for ln in code), (
            f".githooks/{hook} has no working interpreter probe")


def test_the_pre_push_hook_runs_the_RANGE_scan():
    """The hook exists to catch what the tree scan cannot. One that ran the tree scan again
    would be pure ceremony."""
    hook = (_SCRIPT.parents[1] / ".githooks" / "pre-push").read_text(encoding="utf-8")
    code = [ln for ln in hook.splitlines() if not ln.lstrip().startswith("#")]
    assert any("--range" in ln for ln in code), ".githooks/pre-push does not run the range scan"
    assert any("--not --remotes" in ln for ln in code), (
        "a BRAND-NEW branch has no remote counterpart to diff against and would scan zero "
        "commits — the most likely moment for a leak")


def test_the_CI_workflow_runs_BOTH_scans_on_BOTH_paths_with_full_history():
    """The range scan is worth nothing if CI does not run it, and it CANNOT run on the default
    shallow checkout — `git rev-list base..head` fails there, which the script turns into exit 1.
    The tag trigger matters because a tag can point at a commit that never went through a PR."""
    ci = (_SCRIPT.parents[1] / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "--range" in ci, "CI does not run the commit-range scan"
    assert "fetch-depth: 0" in ci, "the range scan needs full history to resolve the base"
    assert "pull_request" in ci, "the PR path is not covered"
    assert 'tags: ["v*"]' in ci, "the tag/release path is not covered"
    assert "origin/main" in ci, "the tag path needs a base to diff against"
    # The tree scan must still be there — the two answer different questions.
    assert "--selftest" in ci


def test_both_hooks_are_committed_EXECUTABLE():
    """⭐ GIT SILENTLY SKIPS A HOOK WITHOUT THE EXECUTABLE BIT.

    `.githooks/pre-push` shipped 100644 while `pre-commit` shipped 100755, and nothing noticed:
    git-for-windows runs a hook with a shebang regardless of the mode bit, so it fired on the
    workstation that authored it. On Linux — a WSL clone, a container, anywhere else this repo
    gets worked on — git checks the executable bit and skips the hook WITHOUT A WORD. A guard
    that is silently not running is worse than one that was never installed, because its absence
    looks exactly like a pass, which is the failure mode this whole file exists to remove.

    The bit lives in the INDEX, not on disk: core.filemode is false on Windows, so `chmod +x`
    alone changes nothing that gets committed and the mode looks right locally either way.
    `git update-index --chmod=+x` is what actually moves it. This reads the index for that
    reason — checking the worktree would pass while the committed hook stayed inert.
    """
    root = _SCRIPT.parents[1]
    # ⚠️ SKIP, don't ERROR, outside a repository. This test reads the INDEX, which only exists in
    # a real clone — and the verification gate runs the suite on `git archive` extractions that
    # deliberately have no `.git`. Erroring there produced a git traceback in every gate round
    # that looked like a code failure and had to be re-diagnosed as environmental each time.
    if not (root / ".git").exists():
        pytest.skip("not a git repository (an isolated archive copy): the index is unavailable")
    out = subprocess.run(
        ["git", "ls-files", "-s", ".githooks/pre-commit", ".githooks/pre-push"],
        cwd=root, capture_output=True, check=True, text=True).stdout.strip().splitlines()
    assert len(out) == 2, f"expected both hooks to be tracked, got: {out}"
    for line in out:
        mode = line.split()[0]
        name = line.split("\t")[-1]
        assert mode == "100755", (
            f"{name} is committed {mode}, so git will silently skip it on Linux. "
            f"Fix with: git update-index --chmod=+x {name}")


# --------------------------------------------- the denylist must stay free of real values
#
# ⛔ WHAT REPLACED `test_guard_source_carries_no_plaintext_token`, AND WHY IT HAD TO GO.
#
# That test decoded the guard's base64 token table and asserted no decoded token appeared in the
# guard's source as a literal. It was the only check that could see past `SELF_PATH`, and it was
# genuinely load-bearing while the guard still carried real values.
#
# It cannot survive the move to a shapes-only denylist, because it depended on the repo knowing
# the real tokens in order to look for them. The whole point of the change is that the repo does
# NOT know them any more: plaintext republished them, and base64 still shipped them one `b64decode`
# away. Keeping a version of that test would mean keeping the values here to test against, which
# is the leak it was written to detect.
#
# So the real-literal assertion moved OUT of this repository, to a guard in the project working
# directory that is never committed and is run against the staged tree before every push. What
# these two tests do instead is pin the STRUCTURE: no encoded table, no decoder, and exactly the
# agreed set of shape patterns. Neither can prove "no real value is present" — nothing inside a
# repo that does not know the values can — and they are written not to imply otherwise.

_SHAPE_LABELS = {
    "private IPv4 (RFC1918)",
    "cgnat address",
    "tailnet name",
    "private lan domain",
    "unraid pool path",
    "personal mail address",
    "uuid (access policy / tenant id)",
    # Added deliberately: a Windows profile path names the operator in its third segment, the
    # same way an Unraid share root names the array. Anchored to a `Users` segment rather than to a
    # drive letter, so ordinary `C:\dev\...` instructions do not fire — see the near-misses in
    # the guard's `_MUST_PASS`.
    "windows profile path",
}


def test_the_denylist_is_the_agreed_shape_set():
    """The denylist is exactly these eight shapes -- no additions, no removals.

    A REMOVAL silently reduces coverage. An ADDITION is the more interesting failure: the way a
    real value gets back into this file is somebody adding a pattern for one ("host codename",
    "infra domain"), which is precisely what happened before. Pinning the set means that edit
    cannot land quietly -- it fails here, and the fix is to put the value in the project-side
    guard instead.
    """
    assert {label for label, _ in guard.PATTERNS} == _SHAPE_LABELS


def test_the_guard_carries_no_real_literal_denylist():
    """No encoded token table, and no decoder to read one.

    The previous design base64-encoded the real tokens and decoded them at import. That defeated
    a grep and a code search, which is a real improvement over plaintext, but it still SHIPPED the
    values -- `base64.b64decode` in the same file is the key sitting next to the lock. This test
    exists so that reintroducing the mechanism fails loudly rather than looking like a hardening
    step.

    ⚠️ WHAT THIS DOES NOT PROVE. It cannot show that no real value appears anywhere in the guard;
    a codename typed straight into a comment would pass this and every other test in this file.
    Only the project-side guard, which holds the actual list, can make that statement -- run it
    against this repo after `git add` and before pushing. Stated plainly here because a test whose
    limits are implied gets read as a guarantee it never made.
    """
    src = _SCRIPT.read_text(encoding="utf-8")
    assert "b64decode" not in src, (
        "the guard decodes an encoded token table again. Encoding does not un-ship a value -- "
        "put the real list in the project-side guard, which is never committed.")
    assert not re.search(r"^import base64|^from base64", src, re.MULTILINE), (
        "the guard imports base64, which it needs only to carry an encoded denylist")
    for attr in ("_CODENAMES", "_CODENAME", "_DOMAIN", "_POOLS", "_PERSON", "_CFAPP"):
        assert not hasattr(guard, attr), (
            f"guard.{attr} is back: that is the decoded real-token table this design removed")


# --------------------------------------------------------------------------------------------
# Two claims the guard's own comments make about their enforcement. Both named a test by name;
# neither test existed, so both comments were assertions about a guard's strength that nothing
# checked — the exact thing this repo treats as a defect rather than a doc nit.


def test_every_pattern_is_exercised():
    """`PATTERNS` says every entry MUST have a deny case AND a near-miss allow case.

    `selftest()` enforces the deny half per pattern and fails on any `_MUST_PASS` sample that
    trips, and it is run by `test_the_selftest_still_passes_through_the_CLI` — widening a
    pattern to `.*` fails it on the corpus, which was checked rather than assumed. What
    nothing enforces is that a given pattern HAS a near-miss: `_MUST_PASS` is unlabelled, so
    deleting every near-miss for one pattern leaves selftest green. That half is convention.

    What it adds is a named, specific failure inside the suite: selftest reports a wall of
    false-positive lines, this says which pattern label has no deny case. Keep it cheap and
    keep its claims small.
    """
    deny = {label for label, _ in guard._MUST_FAIL}
    labels = {label for label, _ in guard.PATTERNS}
    assert labels - deny == set(), f"pattern(s) with no deny case: {sorted(labels - deny)}"

    compiled = guard.compile_patterns()
    assert guard._MUST_PASS, "no near-miss allow cases at all"
    for sample in guard._MUST_PASS:
        hits = guard.scan_text(sample, compiled)
        assert not hits, (
            f"a near-miss sample now trips {[h[1] for h in hits]}: a pattern has been widened "
            f"until it fires on ordinary text — {sample!r}"
        )


def test_the_allow_literals_are_recognised_as_permitted_spans():
    """`_permitted_spans` is pinned DIRECTLY, because a scan verdict would pass either way.

    Every entry in `ALLOW_LITERALS` is currently inert — none matches any live pattern — so
    asserting `scan_text` returns clean proves nothing about the carve-out: it would return clean
    with the whole allowlist deleted. Assert the mechanism itself.

    ⚠️ THIS REPLACED `test_the_allow_literals_are_removed_from_a_line`, and the difference is the
    entire point of the fix. The old test asserted that `_neutralize` DELETED the literal from the
    line — and deletion was the amnesty bug, because whatever a span can grow over, it can erase.
    A span's only power now is to suppress a hit it CONTAINS, so what must be pinned is the SPAN's
    extent, never a rewritten line. A test that still demanded deletion would be pressure to
    reintroduce the defect.
    """
    assert guard.ALLOW_LITERALS, "the carve-out list is empty; this test is then vacuous"
    for lit in guard.ALLOW_LITERALS:
        line = f"see https://{lit}/unraid-templates for the icon"
        spans = guard._permitted_spans(line)
        start = line.index(lit)
        assert (start, start + len(lit)) in spans, (
            f"{lit!r} is in ALLOW_LITERALS but is not recognised as a permitted span")
        # ⭐ THE SPAN MUST NOT REACH BEYOND THE LITERAL, IN EITHER DIRECTION. Asserted as an EXACT
        # extent: an earlier version of this checked only that the span did not contain the
        # substring "unraid-templates", which any leftward growth over "see https://" satisfied —
        # and leftward is precisely the direction the "no span may consume anything to its left"
        # rule exists for. A weaker assertion under a stronger comment is the shape this repo
        # treats as a defect.
        for s, e in spans:
            assert line[s:e] in guard.ALLOW_LITERALS, (
                f"a permitted span {line[s:e]!r} is not exactly one carve-out literal — it has "
                f"grown over its neighbours and could mask a leak written there")


def test_a_repeated_allow_literal_is_recognised_at_EVERY_occurrence() -> None:
    """`_permitted_spans` loops `line.find(lit, start + 1)`; nothing pinned the loop.

    Collapsing it to a single `find` left the whole suite green, because every other case puts one
    literal on a line. A second occurrence going unrecognised would report it as a hit.
    """
    a, b = guard.ALLOW_LITERALS[0], guard.ALLOW_LITERALS[1]
    line = f"{a} and again {a} and also {b}"
    spans = guard._permitted_spans(line)
    covered = sorted(line[s:e] for s, e in spans)
    assert covered.count(a) == 2, f"the repeated literal was found once, not twice: {covered}"
    assert b in covered, f"a second, different literal on the same line was missed: {covered}"


def test_a_permitted_span_still_suppresses_what_it_actually_contains():
    """The other direction: removing amnesty must not have made the allowlist inert.

    `scan_text` suppresses a hit that lies ENTIRELY inside a permitted span. With the current
    denylist no deny pattern can match inside an RFC5737 address, so this constructs the
    containment case directly against a pattern that CAN — proving the suppression arm runs at
    all, rather than trusting a clean verdict that would hold either way.
    """
    # An Unraid share-root hit sitting wholly inside a synthetic permitted span. Assembled from
    # fragments: this file is scanned by the guard, so the literal cannot be written out whole.
    leak = "/mnt/" + "user"
    # ⛔ TAKEN FROM THE SHIPPED SET BY LABEL, never re-spelled here. An inline `re.compile(...)`
    # copy of a shipped pattern is the exact drift `compile_patterns()` exists to stop: it keeps
    # passing against a stale regex after the real one changes, and this one had silently dropped
    # `re.IGNORECASE` too.
    rx = [(label, r) for label, r in COMPILED if label == "unraid pool path"]
    assert rx, "the 'unraid pool path' pattern has been renamed; this test would be vacuous"
    assert guard.scan_text(f"prefix {leak} suffix", rx), "the pattern does not bite at all"

    line = f"prefix {leak} suffix"
    # Monkeypatch a span covering exactly the leak, then assert it is suppressed.
    original = guard._permitted_spans
    start = line.index(leak)
    guard._permitted_spans = lambda _l: [(start, start + len(leak))]
    try:
        assert guard.scan_text(line, rx) == [], (
            "a hit lying entirely inside a permitted span was still reported — the allowlist "
            "has become inert, which is the opposite failure to amnesty")
        # ...and a hit only PARTLY covered is still reported.
        guard._permitted_spans = lambda _l: [(start, start + len(leak) - 1)]
        assert guard.scan_text(line, rx), (
            "a hit that merely TOUCHES a permitted span was suppressed — containment must be "
            "total, or a span can mask a leak by overlapping it")
    finally:
        guard._permitted_spans = original


# =============================================================================================
# HOLE 1 — the AMNESTY bypass (delete-then-match + an unbounded leading-label allow-span).
#
# Measured on this guard BEFORE the fix: 6 of 6 dotted shapes walked straight through, because
# appending `.example.com` to a leak made the allow-span match the LEAK TOO, and the
# delete-then-match pass then erased it. `AGENT=<rfc1918-addr>.example.com` scanned CLEAN and
# exited 0. Every test below fails on that code and passes on this.
# =============================================================================================


def _run_guard(repo: Path, *extra: str) -> subprocess.CompletedProcess:
    """The real CLI, against a real repository. Bounded: a push-path guard may not hang."""
    return subprocess.run(
        [sys.executable, str(_SCRIPT), "--repo", str(repo), *extra],
        capture_output=True, text=True, timeout=300)


# ⚠️ ASSEMBLED AT RUNTIME. This file IS scanned by the guard — only the guard's own source is
# exempt — so a deny case spelled out whole would make the guard fail on its own test suite.
# Neither fragment matches alone. Every value is synthetic (RFC1918/CGNAT documentation shapes,
# `.invalid` hosts, an invented account name).
_LEAK_TOKENS: list[tuple[str, str]] = [
    ("private IPv4 (RFC1918)", "192.168." + "77.77"),
    ("cgnat address", "100.127." + "255.254"),
    ("tailnet name", "host-a.tailnet-example." + "ts" + ".net"),
    ("private lan domain", "nas-a." + "lan"),
    ("unraid pool path", "/mnt/" + "user"),
    ("personal mail address", "someone@" + "gmail" + ".invalid"),
    ("uuid (access policy / tenant id)", "11111111-2222-3333-" + "4444-555555555555"),
    ("windows profile path", "C:\\Users\\" + "operator" + "\\AppData"),
]

# The documented placeholder forms — every one of these is PERMITTED and none of them trips a
# pattern, which is why they can be written out whole here.
_PERMITTED_TOKENS = ("example.com", "example.org", "example.net", "your-domain.example",
                     ".env.example", ".env.local", "192.0.2.5", "198.51.100.5", "203.0.113.9")


def test_every_denylist_pattern_has_a_bare_leak_token_here() -> None:
    """`_LEAK_TOKENS` must cover the whole denylist, or the amnesty tests below have a blind spot.

    The recurring failure this closes is the one the canon names: a round names a defect CLASS and
    only the listed EXAMPLES get pinned, so the next round rediscovers the class one member over.
    The amnesty bypass is a class over PATTERNS, so the enumeration is asserted, not assumed.
    """
    assert {label for label, _ in _LEAK_TOKENS} == {label for label, _ in guard.PATTERNS}, (
        "a pattern has no bare leak token, so no amnesty case exercises it")


@pytest.mark.parametrize("want_label,token", _LEAK_TOKENS)
def test_each_bare_leak_token_is_actually_caught_on_its_own(want_label: str, token: str) -> None:
    """The precondition for every amnesty test: without it they could all pass vacuously.

    If a token did not trip its pattern in isolation, "it is still caught when a permitted token
    is appended" would be true of a guard that catches NOTHING.
    """
    labels = {label for _, label, _ in guard.scan_text(token, COMPILED)}
    assert want_label in labels, (
        f"{token!r} does not trip {want_label!r} on its own, so the amnesty cases built from it "
        f"prove nothing")


@pytest.mark.parametrize("want_label,sample", guard._MUST_FAIL_ADJACENT)
def test_the_allowlist_cannot_grant_amnesty_to_an_adjacent_leak(want_label: str,
                                                                sample: str) -> None:
    """⭐ THE BYPASS ITSELF, one curated case per shape.

    A permitted token written FLUSH AGAINST a leak must not hide it. Curated per label rather
    than generated, because concatenation is not meaning-preserving for every pattern: appending
    `.example.com` to a `.lan` host makes it a host UNDER example.com and genuinely not a `.lan`
    host any more, which is the documented right-bound behaviour and not a miss. The guard's own
    `_MUST_FAIL_ADJACENT` records which combinations are real and why the absent ones are absent.
    """
    labels = {label for _, label, _ in guard.scan_text(sample, COMPILED)}
    assert want_label in labels, (
        f"AMNESTY BYPASS: a permitted token flush against a leak hid it. Wanted {want_label!r}, "
        f"got {sorted(labels)} on {sample!r}")


@pytest.mark.parametrize("want_label,leak", _LEAK_TOKENS)
@pytest.mark.parametrize("permitted", _PERMITTED_TOKENS)
def test_a_permitted_token_elsewhere_on_the_line_never_excuses_a_leak(
    want_label: str, leak: str, permitted: str,
) -> None:
    """The universal half of the class: 8 shapes x 9 permitted tokens x 3 layouts.

    Unlike flush concatenation this IS meaning-preserving for every pattern — a permitted token
    somewhere else on the line cannot change what the leak is — so it can be swept exhaustively
    rather than curated. This is the direction `ALLOW_SPANS` neutralising the LINE would break.
    """
    for line in (f"{permitted} {leak}", f"{leak} {permitted}",
                 f"# see {permitted} -- real value is {leak}"):
        labels = {label for _, label, _ in guard.scan_text(line, COMPILED)}
        assert want_label in labels, (
            f"a permitted token on the same line hid a real leak. Wanted {want_label!r}, got "
            f"{sorted(labels)} on {line!r}")


def test_no_permitted_span_overlaps_the_leak_in_any_curated_amnesty_case() -> None:
    """⭐ THE INVARIANT THAT TERMINATES THE CLASS, rather than one more example of it.

    "No span may consume anything to its left" is the actual property; the individual bypasses
    were all symptoms of a span growing over its neighbours. Asserting the extent directly means
    a future widening of `ALLOW_SPANS` fails HERE, at the cause, instead of being rediscovered as
    yet another shape that slipped through.
    """
    for want_label, sample in guard._MUST_FAIL_ADJACENT:
        spans = guard._permitted_spans(sample)
        for _, label, match in guard.scan_text(sample, COMPILED):
            if label != want_label:
                continue
            start = sample.index(match)
            end = start + len(match)
            for s, e in spans:
                assert e <= start or s >= end, (
                    f"the permitted span {sample[s:e]!r} OVERLAPS the leak {match!r} in "
                    f"{sample!r} — a span has grown over its neighbour again, which is exactly "
                    f"how the delete-then-match design failed open")


def test_a_permitted_span_may_only_start_mid_word_if_it_cannot_contain_a_leak() -> None:
    """⭐⭐ THE INVARIANT THAT WOULD HAVE CAUGHT THE `.env...local` BYPASS, stated generally.

    A permitted span is safe if EITHER of two things is true:
      (a) it cannot begin immediately after a word character, so it can never grow leftward out
          of the token it was written for; or
      (b) nothing it matches can contain a deny match, so even if it does grow, it has no leak to
          grant amnesty to.

    `\\.example` relies on (b) — it is a bare suffix with no left bound, and deliberately so, but
    `.example` contains no leak shape, so it can suppress nothing. `.env[.<qual>].local` relies on
    (a), because it DOES contain a `private lan domain` match by construction — and it shipped
    without a left bound, which is exactly how a `<host>.env.<qualifier>` LAN name scanned clean.

    Checking the condition rather than enumerating bypasses is what terminates the class: a new
    ALLOW_SPANS entry that satisfies neither arm fails HERE, at the cause, instead of being
    rediscovered later as one more shape that slipped through.
    """
    wordy = ("nas-a", "host-b", "operator", "svc1", "x")
    for token in _PERMITTED_TOKENS:
        can_contain_a_leak = any(rx.search(token) for _, rx in COMPILED)
        for prefix in wordy:
            line = f"{prefix}{token}"
            grew_left = [(s, e) for s, e in guard._permitted_spans(line)
                         if s > 0 and re.match(r"[\w-]", line[s - 1])]
            if grew_left and can_contain_a_leak:
                pytest.fail(
                    f"AMNESTY VECTOR: the permitted span {line[grew_left[0][0]:grew_left[0][1]]!r}"
                    f" begins immediately after a word character in {line!r}, AND the token "
                    f"{token!r} can contain a deny match. That span can be appended to a real "
                    f"leak to hide it — left-bound it with (?<![\\w-]).")


def test_the_untouchable_lan_local_pattern_is_exactly_as_decided() -> None:
    """⛔ DO NOT 'FIX' THE TRAILING-DOT GAP. It was repaired once and REVERTED.

    `(?![\\w-]|\\.[\\w-])` does catch `host-a.lan.` at a sentence end — and false-fires on
    `config.local.${ENV}`, `settings.local.*` and `.gitignore` globs, which are ordinary clean
    lines. `<label>.local.` and `<label>.lan.` at a sentence end are the same string shape and no
    regex separates them, so the gap is taken deliberately and declared in KNOWN LIMITS.

    ⚠️ THIS PIN EXISTS BECAUSE NOTHING ELSE CATCHES THE REVERT. The forbidden repair was
    re-applied experimentally and the ENTIRE suite stayed green, selftest included: `_MUST_PASS`
    happens to carry only the three `.local` FILENAME forms the bad repair also passes. Pinning
    the decision is the only thing that makes undoing it loud, so this asserts the regex source.
    """
    assert dict(guard.PATTERNS)["private lan domain"] == r"(?<![\w-])[\w-]+\.(?:lan|local)(?![\w.-])", (
        "the `private lan domain` pattern changed. If this is the trailing-dot 'repair', it was "
        "tried before and reverted for false-firing on config.local.${ENV} and .gitignore globs "
        "— see KNOWN LIMITS. Do not re-apply it.")


@pytest.mark.parametrize("sample", [
    # The exact shapes that made the trailing-dot repair unacceptable. `_MUST_PASS` pinned only
    # the three plain filename forms, all of which the BAD repair also passes — so none of them
    # would have caught the revert.
    "load_config('config.local.${ENV}')",
    "compose.local.$(uname).yaml",
    "the override file is settings.local.",
])
def test_the_false_positives_that_forced_the_trailing_dot_revert_stay_clean(sample: str) -> None:
    hits = guard.scan_text(sample, COMPILED)
    assert not hits, (
        f"{sample!r} now trips {[h[1] for h in hits]} — this is the false-positive class the "
        f"trailing-dot repair was reverted for")


def test_a_trailing_glob_IS_a_known_false_positive_and_is_recorded_as_one() -> None:
    """⚠️ AN HONEST PIN OF A REAL, PRE-EXISTING FALSE POSITIVE — not a claim that it is fine.

    A `.gitignore` glob of the form `*<name>.local*` trips `private lan domain` TODAY: the glob's
    trailing `*` is not in `[\\w.-]`, so the right bound is satisfied and the pattern reads it as
    a hostname. A repo carrying that line would redden CI while leaking nothing.

    It is pinned rather than fixed because the fix is a change to this exact pattern, which is
    frozen by decision (see `test_the_untouchable_lan_local_pattern_is_exactly_as_decided`) — and
    because a gap that is asserted is a gap somebody can find, whereas one mentioned in a comment
    is not. Filed as unraid-templates#32. If that issue is resolved, this test flips to the
    must-pass list above; until then it documents the true behaviour.
    """
    glob = "gitignore glob: *config." + "local*"     # fragmented: this file is scanned
    hits = guard.scan_text(glob, COMPILED)
    assert [h[1] for h in hits] == ["private lan domain"], (
        "the trailing-glob false positive changed behaviour. If it was FIXED, move this sample "
        "into test_the_false_positives_that_forced_the_trailing_dot_revert_stay_clean and close "
        "unraid-templates#32.")


def test_the_delete_then_match_pass_is_gone_and_must_not_come_back() -> None:
    """`_neutralize` WAS the bug: deletion is what let a permitted token consume its neighbours.

    Pinned as an absence because the sibling repo kept the function alive after the rewrite as
    "so the allowlist can be inspected directly" — nothing called it, nothing tested it, and it
    sat in a safety-critical file still carrying the shape of the defect.
    """
    assert not hasattr(guard, "_neutralize"), (
        "the delete-then-match pass is back. A span must SUPPRESS a hit it contains, never "
        "rewrite the line — see scan_text.")


# =============================================================================================
# HOLE 2 — a tracked file that is STAGED-BUT-DELETED. Its content is in the index and goes into
# the commit; the tree scan used to `continue` past it in silence and print "no internal info
# found". Submodules are the reason that branch was written as a skip, so both are tested here.
# =============================================================================================


@pytest.mark.timeout(300)
def test_a_staged_then_deleted_file_is_REPORTED_not_silently_skipped(tmp_path: Path) -> None:
    """⭐ RED BEFORE / GREEN AFTER. On the previous guard this repo scanned clean and exited 0.

    `git add <leak>` then removing it from the worktree leaves the leak in the INDEX — which is
    what the commit will contain. `read_text` raises FileNotFoundError, and the old branch
    treated that as "nothing to see" rather than "I cannot vouch for this".
    """
    repo = tmp_path / "staged"
    _init(repo)
    leak = repo / "staged.txt"
    leak.write_text(f"AGENT_URL=http://{_HOST}:9999/mcp\n", encoding="utf-8")
    _git(repo, "add", "staged.txt")
    leak.unlink()

    assert _HOST in _git(repo, "show", ":staged.txt"), "precondition: the index still has it"
    proc = _run_guard(repo)
    assert proc.returncode == 1, (
        f"a staged-but-deleted leak scanned CLEAN: rc={proc.returncode} {proc.stdout}")
    # ⭐ IDENTIFIED, not merely "unreadable". The guard reads the staged BLOB, so it names the
    # file, the line and the pattern — an operator can act on that, where "I could not vouch for
    # this path" sent them looking by hand.
    assert "staged.txt:1" in proc.stdout, proc.stdout
    assert "private lan domain" in proc.stdout, proc.stdout


@pytest.mark.timeout(300)
def test_an_UNSTAGED_deletion_of_a_clean_file_does_NOT_block_the_commit(tmp_path: Path) -> None:
    """⭐ THE FALSE-RED THE HOLE-2 FIX NEARLY SHIPPED, and the reason it reads the staged blob.

    `rm <tracked-file>` without staging the deletion is ordinary mid-edit behaviour. The index
    still holds the file, so a blanket "tracked but absent -> cannot vouch for it" reddened a tree
    that publishes nothing internal — and told the operator to "re-stage it", which is the wrong
    instruction when the whole point was to delete it. A guard that reddens correct work is one
    that gets switched off, so this direction matters as much as the catching one.
    """
    repo = tmp_path / "unstaged"
    _init(repo)
    (repo / "keep.txt").write_text("nothing internal here\n", encoding="utf-8")
    (repo / "doomed.txt").write_text("also perfectly clean\n", encoding="utf-8")
    _git(repo, "add", "keep.txt", "doomed.txt")
    _git(repo, "commit", "-q", "-m", "base")
    (repo / "doomed.txt").unlink()          # deleted, deletion NOT staged

    proc = _run_guard(repo)
    assert proc.returncode == 0, (
        f"an unstaged deletion of a CLEAN tracked file reddened the tree: {proc.stdout}")


@pytest.mark.timeout(300)
def test_staged_content_that_is_not_UTF8_is_still_reported_as_not_cleared(tmp_path: Path) -> None:
    """The fallback still fails closed. Reading the blob answers the question when it CAN be
    decoded; when it cannot, the honest answer is unchanged — not scanned, so not cleared."""
    repo = tmp_path / "stagedbin"
    _init(repo)
    blob = repo / "wide.txt"
    blob.write_bytes(f"AGENT={_HOST}\n".encode("utf-16"))
    _git(repo, "add", "wide.txt")
    blob.unlink()

    proc = _run_guard(repo)
    assert proc.returncode == 1, f"undecodable staged content was cleared: {proc.stdout}"
    assert "wide.txt" in proc.stdout and "not UTF-8" in proc.stdout, proc.stdout


@pytest.mark.timeout(300)
def test_a_submodule_does_not_redden_an_otherwise_clean_repo(tmp_path: Path) -> None:
    """⭐ THE REGRESSION THE FIX ABOVE WOULD OTHERWISE SHIP, and the WP's acceptance criterion.

    A gitlink and a staged-but-deleted file are indistinguishable to `read_text`: checked out a
    gitlink is a DIRECTORY, and in a clone without `--recurse-submodules` it does not exist at
    all. Reporting either would make any repo containing a submodule permanently RED — a
    false-fail on a clean tree, which costs more than the gap it closes. Asked of git
    (`ls-files -s`, mode 160000) instead of inferred from the filesystem. Both states exercised.
    """
    repo = tmp_path / "withsub"
    _init(repo)
    (repo / "ok.txt").write_text("nothing to see\n", encoding="utf-8")
    _git(repo, "add", "ok.txt")

    # A real inner repository, staged as a gitlink without needing a network remote.
    sub = repo / "vendor"
    sub.mkdir()
    _init(sub)
    (sub / "readme.md").write_text("vendored\n", encoding="utf-8")
    _git(sub, "add", "readme.md")
    _git(sub, "commit", "-q", "-m", "sub")
    sub_head = _git(sub, "rev-parse", "HEAD").strip()
    _git(repo, "update-index", "--add", "--cacheinfo", f"160000,{sub_head},vendor")

    assert "vendor" in guard.gitlinks(repo), "precondition: the gitlink was not recognised"
    present = _run_guard(repo)
    assert present.returncode == 0, (
        f"a CHECKED-OUT submodule reddened a clean repo: {present.stdout}{present.stderr}")

    # ...and the NOT-checked-out state, which raises FileNotFoundError — the very branch that
    # now reports a staged-but-deleted file. Staged directly rather than by deleting the tree:
    # git marks its object files read-only, so removing a submodule on Windows is a chmod dance
    # that tests nothing.
    _git(repo, "update-index", "--add", "--cacheinfo",
         "160000,0123456789abcdef0123456789abcdef01234567,absent-vendor")
    assert "absent-vendor" in guard.gitlinks(repo)
    absent = _run_guard(repo)
    assert absent.returncode == 0, (
        f"a submodule that is NOT checked out reddened a clean repo: "
        f"{absent.stdout}{absent.stderr}")


@pytest.mark.timeout(300)
def test_a_gitlink_MODE_alone_cannot_exclude_a_real_file_from_the_scan(tmp_path: Path) -> None:
    """⭐ THE SPOOF THE SUBMODULE SKIP OPENS — the rejecting half of the gitlink logic.

    `git update-index --cacheinfo 160000,<sha>,<path>` marks ANY tracked path as a gitlink with
    no real submodule and no `.gitmodules` entry, while the file goes on sitting in the worktree,
    readable and published. Trusting the index MODE would let a planted leak scan clean, so the
    skip is conditional on "not a readable file" and a spoofed entry falls through to be scanned.
    """
    repo = tmp_path / "spoof"
    _init(repo)
    planted = repo / "vendored"
    planted.mkdir()
    (planted / "leak.txt").write_text(f"AGENT_URL=http://{_ADDR}:9999/mcp\n", encoding="utf-8")
    _git(repo, "add", "vendored/leak.txt")
    sha = _git(repo, "hash-object", "vendored/leak.txt").strip()
    _git(repo, "rm", "--cached", "-q", "vendored/leak.txt")
    _git(repo, "update-index", "--add", "--cacheinfo", f"160000,{sha},vendored/leak.txt")

    assert "vendored/leak.txt" in guard.gitlinks(repo), "precondition: spoofed mode not set"
    assert (planted / "leak.txt").is_file(), "precondition: the leak must still be on disk"
    proc = _run_guard(repo)
    assert proc.returncode == 1, (
        f"a real file marked as a gitlink escaped the scan entirely: rc={proc.returncode} "
        f"{proc.stdout}{proc.stderr}")
    assert "vendored/leak.txt" in proc.stdout, proc.stdout


# =============================================================================================
# The COMMIT'S OWN identity. Author/committer name and email are published on every push and no
# guard in the fleet looked at them — a repo whose files are spotless still ships a personal
# address on every commit page if `user.email` was wrong, and only a history rewrite removes it.
# =============================================================================================


@pytest.mark.timeout(300)
def test_a_commit_authored_from_a_personal_address_FAILS_the_range_scan(tmp_path: Path) -> None:
    """⭐ RED BEFORE / GREEN AFTER — nothing scanned commit metadata at all.

    The diff here is deliberately CLEAN, so the only thing that can fail the scan is the identity.
    """
    repo = tmp_path / "authors"
    _init(repo)
    (repo / "ok.txt").write_text("nothing to see here\n", encoding="utf-8")
    _git(repo, "add", "ok.txt")
    bad = "someone@" + "gmail" + ".invalid"
    _git(repo, "-c", f"user.email={bad}", "commit", "-q", "-m", "clean diff, leaky author")

    assert _tree_findings(repo) == [], "precondition: the FILES are clean, only the author is not"
    proc = _run_guard(repo, "--range", "HEAD")
    assert proc.returncode == 1, (
        f"a commit authored from a personal address scanned clean: rc={proc.returncode} "
        f"{proc.stdout}{proc.stderr}")
    assert "author email" in proc.stdout, proc.stdout
    assert "personal mail address" in proc.stdout, proc.stdout


@pytest.mark.timeout(300)
def test_an_ordinary_noreply_author_does_NOT_redden_the_range_scan(tmp_path: Path) -> None:
    """The negative direction. Without it, "the identity scan fires" is equally true of one that
    can ONLY fire — and a guard that reddens every commit is one that gets switched off.

    The address here is the shape the fleet actually commits under.
    """
    repo = tmp_path / "goodauthor"
    _init(repo)
    (repo / "ok.txt").write_text("nothing to see here\n", encoding="utf-8")
    _git(repo, "add", "ok.txt")
    _git(repo, "-c", "user.email=1234567+someone@users.noreply.github.com",
         "-c", "user.name=someone", "commit", "-q", "-m", "clean")

    proc = _run_guard(repo, "--range", "HEAD")
    assert proc.returncode == 0, (
        f"an ordinary noreply author reddened a clean commit: {proc.stdout}{proc.stderr}")


def test_the_identity_scan_reads_every_field_not_just_the_author_email() -> None:
    """`commit_identity` returns four fields; a scan that only looked at one would still pass the
    test above. Pinned on the pure function so it does not need four crafted repositories."""
    assert guard._IDENT_FIELDS == (
        "author name", "author email", "committer name", "committer email")
    for field in guard._IDENT_FIELDS:
        leak = "someone@" + "gmail" + ".invalid"
        found = guard.scan_identity("abc1234567", [(field, leak)], COMPILED)
        assert found and field in found[0], f"{field} is not scanned: {found}"


# =============================================================================================
# The remaining gambit refinements, each pinned by the behaviour it changes.
# =============================================================================================


@pytest.mark.timeout(300)
def test_the_self_exemption_follows_the_FILE_not_a_hardcoded_path(tmp_path: Path) -> None:
    """`SELF_PATH` is a constant, so the exemption used to land on whatever sits at that path.

    Copy the guard to a different path and run it: it scanned ITSELF (every synthetic deny case
    became a finding) while exempting an unrelated file at `scripts/…` — the exemption on the one
    file that does not need it, and gone from the one that does.
    """
    repo = tmp_path / "moved"
    _init(repo)
    tools = repo / "tools"
    tools.mkdir()
    copied = tools / "check_no_internal_info.py"
    copied.write_bytes(_SCRIPT.read_bytes())
    _git(repo, "add", "tools/check_no_internal_info.py")

    proc = subprocess.run([sys.executable, str(copied), "--repo", str(repo)],
                          capture_output=True, text=True, timeout=300)
    assert proc.returncode == 0, (
        f"the guard reported its OWN synthetic deny cases as findings when run from a path "
        f"other than {guard.SELF_PATH!r}: {proc.stdout}{proc.stderr}")

    # ⭐ THE OTHER HALF, and the half that actually catches a regression. The docstring names a
    # TWO-sided bug — "the exemption on the one file that does not need it, AND GONE FROM THE ONE
    # THAT DOES" — and only the second half was asserted. A decoy at the hardcoded SELF_PATH must
    # be SCANNED, because it is not this file. Asserting the clean direction alone is equally
    # true of an exemption that has stopped working entirely.
    scripts = repo / "scripts"
    scripts.mkdir()
    decoy = scripts / "check_no_internal_info.py"
    decoy.write_text(f"AGENT_URL=http://{_HOST}:9999/mcp\n", encoding="utf-8")
    _git(repo, "add", "scripts/check_no_internal_info.py")

    proc = subprocess.run([sys.executable, str(copied), "--repo", str(repo)],
                          capture_output=True, text=True, timeout=300)
    assert proc.returncode == 1, (
        f"an unrelated file sitting at the hardcoded {guard.SELF_PATH!r} was exempted — the "
        f"self-exemption is landing on a PATH rather than on the guard: {proc.stdout}")
    assert "scripts/check_no_internal_info.py" in proc.stdout, proc.stdout


@pytest.mark.timeout(300)
def test_the_RANGE_scan_resolves_the_self_path_the_same_way_the_tree_scan_does(
    tmp_path: Path,
) -> None:
    """⭐ THE TWO SCANS MUST AGREE, and one call site was missed.

    `added_lines` filtered its unscannable list with `_skipped(p)` — no `root` — so it fell back
    to the SELF_PATH CONSTANT while the tree scan resolved the real file from `__file__`. The
    consequence was not a cosmetic mismatch: a path wrongly judged "skipped" drops out of
    `pending`, and an empty `pending` returns early DISCARDING the unscannable list, so an
    unreadable blob was reported CLEAN by the range scan on the push path.

    Reproduced the way it actually bites: guard relocated to `tools/`, an undecodable file parked
    at the hardcoded `scripts/check_no_internal_info.py`.
    """
    repo = tmp_path / "twoscans"
    _init(repo)
    tools = repo / "tools"
    tools.mkdir()
    copied = tools / "check_no_internal_info.py"
    copied.write_bytes(_SCRIPT.read_bytes())
    scripts = repo / "scripts"
    scripts.mkdir()
    (scripts / "check_no_internal_info.py").write_bytes(
        f"AGENT=http://{_HOST}/\n".encode("utf-16"))
    _git(repo, "add", "tools/check_no_internal_info.py", "scripts/check_no_internal_info.py")
    _git(repo, "commit", "-q", "-m", "decoy at the hardcoded path")

    proc = subprocess.run([sys.executable, str(copied), "--repo", str(repo), "--range", "HEAD"],
                          capture_output=True, text=True, timeout=300)
    assert proc.returncode == 1, (
        f"the RANGE scan cleared a blob it never read, because it resolved the self-path "
        f"differently from the tree scan: rc={proc.returncode} {proc.stdout}{proc.stderr}")


def test_compile_patterns_is_the_single_definition_and_it_is_case_insensitive() -> None:
    """⛔ The drift this closes: `main` inlined `re.compile(rx, re.IGNORECASE)` and the test
    module inlined the identical line, so the tests carried their OWN correct copy of the flags.
    Dropping IGNORECASE from the shipped scan would have left the suite and CI fully green while
    an uppercase LAN host or a mixed-case freemail address scanned clean and exited 0.

    Asserted on BEHAVIOUR (an uppercase leak is caught through the shipped helper), not on the
    flag value — a flags comparison is satisfied by a helper nothing calls.
    """
    compiled = guard.compile_patterns()
    assert {label for label, _ in compiled} == {label for label, _ in guard.PATTERNS}
    upper = ("nas-a." + "lan").upper()
    labels = {label for _, label, _ in guard.scan_text(upper, compiled)}
    assert "private lan domain" in labels, (
        f"an UPPERCASE leak was not caught: {upper!r} — compile_patterns has lost IGNORECASE")


@pytest.mark.parametrize("sample", [
    # The array mounts the plural `disks` did not cover.
    "/mnt/" + "disk1" + "/appdata/svc",
    "/mnt/" + "disk17" + "/appdata/svc",
    # Provider domains the old alternation NAMED and still let through.
    "someone@" + "protonmail" + ".invalid",
    "someone@" + "live" + ".invalid",
    "someone@" + "googlemail" + ".invalid",
    # `_` is a word character, so `\b` did not hold and `<KEY>_<uuid>` walked past the bound.
    "app_id_" + "11111111-2222-3333-" + "4444-555555555555",
])
def test_the_shapes_the_old_bounds_let_through_are_now_caught(sample: str) -> None:
    """Each of these matched a pattern that was written FOR it and missed it on a bound."""
    assert guard.scan_text(sample, COMPILED), f"{sample!r} still walks through"


@pytest.mark.parametrize("sample", [
    r"clone it to C:\dev\unraid-templates",
    r"gh lives at C:\Program Files\GitHub CLI\gh.exe",
    r"export to D:\data\report.csv",
    r"put it in C:\Users\<you>\AppData\Local\app",
    r"set CACHE=C:\Users\%USERNAME%\AppData\Local\app",
    r"shared drop: C:\Users\Public\Documents\shared.csv",
])
def test_ordinary_windows_paths_do_NOT_fire(sample: str) -> None:
    """⭐ THE FALSE-POSITIVE HALF, which for a guard matters as much as the catching half.

    `[A-Za-z]:\\…` on its own fires on every ordinary Windows instruction — including the ones
    this repo's own README gives. A guard that reddens on the command it is telling you to run is
    a guard someone switches off, so the pattern is anchored to a `Users` segment and the two
    placeholder spellings fail structurally rather than by exception.
    """
    hits = guard.scan_text(sample, COMPILED)
    assert not hits, f"false positive on an ordinary Windows path: {sample!r} -> {hits}"


@pytest.mark.parametrize("sample", [
    # ⭐ THE SAME PATH IN ITS OTHER SPELLINGS. Only the `C:\` form was matched at first; each of
    # these is the identical leak on the identical machine, written the way that tool writes it.
    "cache = " + "/mnt/c/Users/" + "operator" + "/AppData/Local/svc",          # WSL view
    "set CACHE=" + "%SystemDrive%\\Users\\" + "operator" + "\\AppData",        # env-var prefix
    "path: " + "C:\\\\\\Users\\\\\\" + "operator",                            # 3+ escapes
])
def test_the_other_spellings_of_a_windows_profile_path_are_caught(sample: str) -> None:
    labels = {label for _, label, _ in guard.scan_text(sample, COMPILED)}
    assert "windows profile path" in labels, f"{sample!r} walks through -> {labels}"


def test_svg_and_other_text_formats_are_NEVER_skipped() -> None:
    """The leak an earlier batch removed was literally an icon URL inside an SVG.

    `SKIP_SUFFIXES` is the one list that can make the guard look away from a whole file, and
    nothing asserted that a TEXT-bearing format had not drifted into it. Adding `.svg` would have
    been silently green.
    """
    for suffix in (".svg", ".xml", ".md", ".json", ".yml", ".yaml", ".py", ".sh", ".txt"):
        assert suffix not in guard.SKIP_SUFFIXES, (
            f"{suffix} is a TEXT format and has been added to SKIP_SUFFIXES — an SVG is XML and "
            f"carries <title>/<desc>/href, which is where an icon-URL leak lived once")
    # ...and the exemption still works for what it is actually for.
    assert guard._skipped("icons/logo.png") and guard._skipped("a/b/FONT.WOFF2")


@pytest.mark.parametrize("label,rx", [(label, rx) for label, rx in guard.compile_patterns()])
def test_no_single_denylist_pattern_backtracks_quadratically(label: str, rx) -> None:
    """⭐ A HANG IS THE FAILURE MODE A PUSH-PATH GUARD CANNOT HAVE, and only the ALLOW-SPANS had
    a linearity test — the measured claims on `tailnet name` and `personal mail address` (the
    lookbehinds that once made a real `git push` take 2m06s) were comment-only. Dropping either
    bound left the suite green.

    Bounded rather than timed precisely: the point is the ORDER of growth, and a tight wall-clock
    assertion on a shared runner is its own flake. The inputs are the character runs each pattern
    is built from, which is what makes a missing left bound quadratic.
    """
    import time

    for filler in ("z" * 32_000, "a-b-" * 8_000, "0123456789abcdef-" * 2_000, "x.y." * 8_000):
        start = time.perf_counter()
        rx.search(filler)
        elapsed = time.perf_counter() - start
        assert elapsed < 2.0, (
            f"{label!r} took {elapsed:.1f}s on a {len(filler)}-char line — it is backtracking "
            f"quadratically; check its left bound (?<![...]) is present")


def test_the_SUPPRESSION_path_is_linear_too() -> None:
    """The containment check runs once per match per pattern. Done as a linear scan over the
    permitted spans it is O(matches x spans), and a 176 KB minified line dense with permitted
    tokens took 31 SECONDS — on the push path. `_containment_index` makes each query O(log n).

    A line of many `.env.local` tokens is the shape that reaches it: each one is a permitted span
    AND contains a suppressible deny match, which is the worst case by construction.
    """
    import time

    line = "var e=" + '"'.join([".env.local"] * 8_000) + ";"
    start = time.perf_counter()
    guard.scan_text(line, COMPILED)
    elapsed = time.perf_counter() - start
    assert elapsed < 5.0, (
        f"scanning one {len(line) // 1024} KB line of permitted tokens took {elapsed:.1f}s — the "
        f"containment check has gone quadratic again; it must stay indexed, not a linear scan")


@pytest.mark.timeout(300)
def test_a_leaky_COMMITTER_is_caught_even_when_the_author_is_clean(tmp_path: Path) -> None:
    """`commit_identity` reads four fields; the end-to-end tests only ever set the AUTHOR.

    Truncating `_IDENT_FIELDS` to the author pair left the whole suite green, so nothing pinned
    the committer half — and a committer address is set by exactly the same kind of stray
    `-c user.email` override the identity scan exists to catch.
    """
    repo = tmp_path / "committer"
    _init(repo)
    (repo / "ok.txt").write_text("nothing to see here\n", encoding="utf-8")
    _git(repo, "add", "ok.txt")
    bad = "someone@" + "yahoo" + ".invalid"
    _git(repo, "-c", "user.name=clean", "-c", "user.email=1234+clean@users.noreply.github.com",
         "-c", f"committer.email={bad}", "commit", "-q", "-m", "clean author, leaky committer",
         "--author", "clean <1234+clean@users.noreply.github.com>")

    proc = _run_guard(repo, "--range", "HEAD")
    assert proc.returncode == 1, (
        f"a leaky COMMITTER address scanned clean: {proc.stdout}{proc.stderr}")
    assert "committer email" in proc.stdout, proc.stdout


def test_a_short_identity_response_is_an_ERROR_not_a_silent_partial_scan() -> None:
    """`zip` stops at the shorter side, so a malformed git response would have quietly scanned
    only the fields that arrived and reported the commit clean on the rest — a guard reporting on
    less than it claims. Unverified must fail closed like everything else here."""
    original = guard._git
    guard._git = lambda *a, **k: "only-one-field"          # a response of the wrong shape
    try:
        with pytest.raises(ValueError, match="identity fields"):
            guard.commit_identity(Path("."), "abc1234567")
    finally:
        guard._git = original

    # ...and the well-formed response still parses into all four fields.
    guard._git = lambda *a, **k: "n\x00n@example.com\x00c\x00c@example.com\n"
    try:
        assert [f for f, _ in guard.commit_identity(Path("."), "abc")] == list(
            guard._IDENT_FIELDS)
    finally:
        guard._git = original


@pytest.mark.timeout(300)
def test_a_windows_profile_path_in_a_real_repo_fails_the_actual_tree_scan(tmp_path: Path) -> None:
    """The pattern proven end-to-end through the CLI, not just through `scan_text`."""
    repo = tmp_path / "winpath"
    _init(repo)
    leak = "C:\\Users\\" + "operator" + "\\AppData\\Local\\svc"
    (repo / "notes.md").write_text(f"cache lives in {leak}\n", encoding="utf-8")
    _git(repo, "add", "notes.md")

    proc = _run_guard(repo)
    assert proc.returncode == 1, f"a Windows profile path scanned clean: {proc.stdout}"
    assert "windows profile path" in proc.stdout, proc.stdout
