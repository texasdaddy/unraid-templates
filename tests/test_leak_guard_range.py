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

    The denied tokens themselves come from `guard`'s decoded table rather than from split-string
    fragments in this file — see the comment above `_POOL`. `test_guard_source_carries_no_
    plaintext_token` closes the loop by asserting that the guard's own source, the file the tree
    scan is structurally unable to clear, carries no decoded token as a literal either.
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

COMPILED = [(label, re.compile(rx, re.IGNORECASE)) for label, rx in guard.PATTERNS]

# ⚠️ TAKEN FROM THE GUARD'S DECODED TABLE, NOT WRITTEN OUT. See the module docstring. These used
# to be split-string fragments (`"rein" + "lie"`), which defeats a grep for the whole token but
# still ships each half in plaintext and drifts silently if the guard's denylist ever changes.
# Reading them back from the module under test fixes both: nothing is spelled here, and a token
# that stopped being denied would break these tests instead of quietly un-testing them.
# Matches "unraid pool path": `/mnt/` alone does not match, the pattern needs a pool name after
# it, so neither fragment is a finding on its own.
_POOL = "/mnt/" + guard._POOL[0]
_LEAK = f"{_POOL}/appdata/example/data"
# Matches "infra domain". `.invalid` guarantees it resolves nowhere.
_HOST = f"host-a.{guard._DOMAIN}.invalid"
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
        if guard._skipped(rel):
            continue
        try:
            text = p.read_text(encoding="utf-8")
        except (FileNotFoundError, UnicodeDecodeError):
            continue
        out += [f"{rel}:{n}: {label}" for n, label, _ in guard.scan_text(text, COMPILED)]
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
    assert "infra domain" in labels, f"the hostname was not caught: {result.findings}"
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
    assert "infra domain" in ranged.stdout


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
    assert _hits("abc", [(guard.SELF_RELPATH, 5, _LEAK)]) == [], (
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

    broken = _cli(repo, "--range", "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef..HEAD")
    assert broken.returncode == 1, (
        "AN UNRESOLVABLE RANGE MUST NOT REPORT CLEAN: " + broken.stdout)
    assert "could not scan" in broken.stdout

    assert _cli(repo, "--range").returncode == 2, "a missing argument is a usage error"


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


def test_guard_source_carries_no_plaintext_token():
    """The guard's own source must not spell out any token it denies.

    THIS IS THE ONE CHECK NOTHING ELSE CAN MAKE. `SELF_RELPATH` exempts
    `scripts/check_no_internal_info.py` from the tree scan by exact path, and it has to: the
    file necessarily contains the denylist, so scanning it would fail on every run. The cost of
    that exemption is that the guard is structurally blind to itself — a codename retyped into a
    new deny case, a pool name pasted into a comment, and every scan still prints "no internal
    info found" while the value sits in a public repo forever. That is not hypothetical: the
    denylist WAS plaintext here until the history reset, which is exactly why it is base64 now.

    So the assertion is made from outside: decode each token and require that it does not appear
    as a literal in the source. Encoded forms and interpolations (`{_DOMAIN}`) are invisible to
    this by construction, which is the point — they are the supported way to reference a token.

    The GitHub account name is deliberately NOT checked. It is in the repo's clone URL and in
    every icon URL the templates serve, so it is public by construction; ALLOW_LITERALS depends
    on it being written plainly, and encoding it would break image pulls for no gain.
    """
    src = _SCRIPT.read_text(encoding="utf-8")
    # ⚠️ POOL NAMES ARE CHECKED ONLY IN `/mnt/<pool>` FORM, and that is not a loophole.
    # Three of the five are ordinary technical English that this file legitimately contains:
    # `__pycache__` in the SELF_RELPATH comment, `--not --remotes` in `commits_in_range`, `user`
    # in half a dozen places. Matching them bare made this test fail on prose that republishes
    # nothing, and a test that cries wolf gets deleted. What identifies the estate is the PATH —
    # which is exactly what the "unraid pool path" pattern itself denies, `/mnt/` prefix and all.
    # The other four tokens are distinctive enough to check bare, so they are.
    tokens = {
        "host codename": guard._CODENAME,
        "unraid pool path": [f"/mnt/{p}" for p in guard._POOL],
        "infra domain": [guard._DOMAIN],
        "personal name": [guard._PERSON],
        "cloudflare access app": [guard._CFAPP],
    }
    leaked = [
        f"{label}: {tok[:2]}... ({len(tok)} chars) appears verbatim in {guard.SELF_RELPATH}"
        for label, toks in tokens.items()
        for tok in toks
        # casefold: the deny patterns are IGNORECASE, so any casing republishes the value
        if tok.casefold() in src.casefold()
    ]
    assert not leaked, (
        "a denied token is written out in the guard's own source, which is the ONE file the "
        "tree scan skips — so nothing else would ever report it:\n  " + "\n  ".join(leaked)
        + "\n\nReference it as an interpolation of the decoded table (_CODENAMES/_DOMAIN/"
          "_POOLS/_PERSON/_CFAPP) instead of retyping it."
    )
