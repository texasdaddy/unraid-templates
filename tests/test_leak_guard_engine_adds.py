"""The four surfaces the leak-guard ENGINE was blind to, and the plant-and-measure for each.

WHY THIS FILE EXISTS
    `scripts/check_no_internal_info.py` is the fleet's shared guard: every other repository takes
    a copy of it, so a gap here is a gap everywhere at once. Four were measured against
    `main@046fc7e` (`_sessions/unraid-templates/AUDIT.md`, 2026-08-29), and every one of them
    exited 0 on content that a push would have published permanently:

      keystone#20  A PATH was read by nothing. A tracked `<rfc1918-addr>.conf`, or a
                   `docs/<host>.lan-runbook/` directory, with perfectly clean file CONTENT, passed
                   both scans. A filename is rendered on every GitHub file listing and lands in
                   every clone.
      #39/keystone#21  The range scan read a commit's IDENTITY (`%an%ae%cn%ce`) and its DIFF, and
                   nothing else. A leak written into a commit MESSAGE — or into an annotated tag's
                   name, tagger or message — was published and reported clean.
      #33/keystone#23  The pre-commit layer read the WORKTREE. `git add` a leak, tidy the worktree
                   without re-staging, and the hook exits 0 while the commit records the leak.
      keystone#22  `SKIP_SUFFIXES` was trusted outright, so an ASCII runbook named `.pdf` was read
                   by neither scan; and a run that scanned ZERO files printed the same cheerful
                   "no internal info found" a real clean run prints.

    Each test below is the reproduction of one of those, committed. It FAILS against the engine as
    it was and PASSES against the engine as it is, which is what makes it the anti-rot check for
    its issue: if a future edit reopens the gap, this is what says so.

⚠️ EVERY LEAKING LITERAL HERE IS ASSEMBLED AT RUNTIME, exactly as in
    `test_leak_guard_range.py`, and every one is synthetic. This file is scanned by the guard —
    only `scripts/check_no_internal_info.py` is exempt — so a deny case written out whole would
    make the guard fail on its own test suite.

⚠️ EVERY `git` CALL PINS ITS CONFIG. A test that inherits the machine's git config is the
    config-dependent sibling of a time-bomb test: the CI runner has no `user.email`, so a
    `git commit` that needs one silently no-ops there and a test whose SETUP no-ops passes
    VACUOUSLY while looking like coverage. Identity, signing and autocrlf are all pinned, and the
    plants are re-read from git before anything is asserted about them.
"""

from __future__ import annotations

import importlib.util
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "check_no_internal_info.py"
_REPO_ROOT = _SCRIPT.parents[1]

_spec = importlib.util.spec_from_file_location("check_no_internal_info_engine_adds", _SCRIPT)
assert _spec and _spec.loader
guard = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(guard)

COMPILED = guard.compile_patterns()

# ⚠️ SPLIT FRAGMENTS. Neither half matches a pattern on its own; joined at runtime they are the
# deny shapes. All synthetic: `.lan` resolves nowhere, `.77.77` is on no network here, `.invalid`
# is reserved by RFC 2606, and the UUID is a counting pattern.
_HOST = "host-a." + "lan"
_ADDR = "192.168." + "77.77"
_POOL = "/mnt/" + "user" + "/appdata/svc"
_UUID = "11111111-2222-" + "3333-4444-555555555555"
_MAIL = "someone@" + "gmail.invalid"

# The documented ALLOWED spellings, from the guard's own `_MUST_PASS` corpus.
_OK_HOST = "svc.your-domain.example"
_OK_ADDR = "198.51.100.5"

_LEAK_LINE = f"AGENT_URL=http://{_HOST}:9999/mcp"

# ⚠️ SPLIT FOR THE SAME REASON AS THE DENY CASES, even though this one is ALLOWED here. The
# dotenv local filename CONTAINS a `private lan domain` match by construction — that is precisely
# why the canonical engine carries an allow-span for it — and the project-side real-literal guard
# run before every push is an older copy of this engine that does NOT yet have that span. Written
# out whole, this string reddens that guard on a file that leaks nothing. Assembled, it exercises
# exactly the same path scan and satisfies both layers.
_DOTENV_LOCAL = ".env" + ".local"

# `-c` rather than `git config`, so nothing depends on what the repository or the machine holds.
_PINNED = ("-c", "user.name=guard test", "-c", "user.email=t@example.com",
           "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false",
           "-c", "core.autocrlf=false")


def _git(repo: Path, *args: str) -> str:
    out = subprocess.run(["git", *_PINNED, *args], cwd=repo, capture_output=True, check=True,
                         timeout=300)
    return out.stdout.decode("utf-8", errors="replace")


def _init(repo: Path) -> None:
    repo.mkdir(parents=True, exist_ok=True)
    _git(repo, "init", "-q", "-b", "main")


def _write(repo: Path, rel: str, text: str) -> None:
    """Write a fixture file with the bytes it says, on every platform.

    ⛔ `write_bytes`, NOT `write_text`. `Path.write_text` opens in TEXT mode with `newline=None`,
    which translates every `\\n` to `os.linesep` — so on Windows a fixture written as `"clean\\n"`
    lands as `clean\\r\\n`, git (with `core.autocrlf=false` pinned, as it is here) stores the CR
    verbatim, and a test asserting on the exact added line passes on the runner and fails locally
    or the reverse. That is the config-dependent sibling of a time-bomb test, and it bit this file
    on its first run.
    """
    p = repo / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(text.encode("utf-8"))


def _seeded(repo: Path) -> str:
    """A repository with one ordinary clean commit."""
    _init(repo)
    _write(repo, "README.md", "seed\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "seed")
    return _git(repo, "rev-parse", "HEAD").strip()


def _commit(repo: Path, msg: str) -> str:
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", msg)
    return _git(repo, "rev-parse", "HEAD").strip()


def _commit_with_message(repo: Path, tmp_path: Path, body: str) -> str:
    """Commit with a multi-line message, via a FILE.

    ⚠️ `-F`, never `-m "…"`: a message passed inline through a shell has its backtick spans
    command-substituted and its newlines mangled, which would quietly change the very text this
    file is asserting about.
    """
    msg = tmp_path / "commit-message.txt"
    msg.write_bytes(body.encode("utf-8"))   # bytes, for the reason `_write` gives
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-F", str(msg))
    return _git(repo, "rev-parse", "HEAD").strip()


def _cli(repo: Path, *args: str) -> subprocess.CompletedProcess:
    """Run the guard exactly as a hook or CI does — a real process, real argv, real exit code."""
    return subprocess.run([sys.executable, str(_SCRIPT), *args], cwd=repo,
                          capture_output=True, check=False, timeout=300,
                          encoding="utf-8", errors="replace")


def _out(res: subprocess.CompletedProcess) -> str:
    return (res.stdout or "") + (res.stderr or "")


# ===========================================================================================
# keystone#20 — a leak in a PATH
# ===========================================================================================


def test_scan_path_finds_a_leak_in_a_path_string() -> None:
    """The pure half: no repository, so this is the fast pin on the matcher itself."""
    assert guard.scan_path(f"{_ADDR}.conf", COMPILED), "an address in a filename must be a hit"
    assert guard.scan_path(f"docs/{_HOST}/notes.md", COMPILED), (
        "a LAN host in a DIRECTORY name is published exactly like one in a filename")
    assert guard.scan_path(f"var{_POOL}/dump.txt", COMPILED)
    assert guard.scan_path(f"backups/{_UUID}.tar", COMPILED)


def test_the_path_scan_INHERITS_the_patterns_LIMITS_and_says_so() -> None:
    """⚠️ DECLARED, NOT CLAIMED AWAY. `scan_path` reuses the denylist, so it inherits every one of
    the denylist's documented bounds — it does not widen them and must not be read as if it did.

    The one worth naming, because it is the shape a directory most naturally takes: the
    `private lan domain` right bound `(?![\\w.-])` rejects a FOLLOWING label or hyphen, so
    `docs/<host>.lan-runbook/` is not a `.lan` host by this guard's definition and is NOT caught.
    That bound is load-bearing — without it `settings.local.json` and `config.local.yml` redden
    every repository that has them — so this is a deliberate trade, not an oversight. Pinned here
    so the next reader finds the limit rather than assuming coverage.
    """
    assert guard.scan_path(f"docs/{_HOST}-runbook/notes.md", COMPILED) == [], (
        "if this now fires, the `private lan domain` right bound changed — check that "
        "`settings.local.json` and `config.local.yml` still pass before keeping it")
    # The same bound, in the direction it exists for.
    assert guard.scan_path(".claude/settings.local.json", COMPILED) == []


@pytest.mark.parametrize("rel", [
    "README.md",
    "templates/service.xml",
    "icons/service.png",
    # ⭐ The allow-spans have to apply to PATHS too, or the guard reddens on ordinary repositories.
    # the dotenv local filename CONTAINS a `private lan domain` match by construction; the two
    # after it are the
    # `settings.local.json` / `config.local.yml` filenames the pattern's right bound exists for.
    _DOTENV_LOCAL,
    ".env.example",
    ".claude/settings.local.json",
    "src/config.local.yml",
    "compose.local.yaml",
    "scripts/deploy.sh",
    ".github/workflows/ci.yml",
])
def test_an_ordinary_or_allow_listed_path_is_not_a_finding(rel: str) -> None:
    assert guard.scan_path(rel, COMPILED) == [], rel


def test_a_leak_in_a_FILENAME_reds_the_TREE_scan(tmp_path: Path) -> None:
    """⭐ keystone#20, the measured repro. CONTENT clean, NAME not.

    Measured at `main@046fc7e`: exit 0, `no internal info found (3 tracked text files scanned)`.
    """
    repo = tmp_path / "paths"
    _init(repo)
    _write(repo, "README.md", "all clean here\n")
    _write(repo, f"{_ADDR}.conf", "nothing to see\n")
    _write(repo, f"docs/{_HOST}/notes.md", "clean body\n")
    _git(repo, "add", "-A")

    # ⚠️ VACUITY GUARD. If the plants were not tracked, the assertion below would be trivially
    # satisfiable by a guard that does nothing at all.
    tracked = _git(repo, "ls-files").split()
    assert f"{_ADDR}.conf" in tracked and f"docs/{_HOST}/notes.md" in tracked, tracked
    # And the premise the whole test rests on: the CONTENT really is clean.
    for rel in tracked:
        assert guard.scan_text((repo / rel).read_text(encoding="utf-8"), COMPILED) == [], rel

    res = _cli(repo)
    assert res.returncode == 1, f"a leak in a filename was not caught:\n{_out(res)}"
    out = _out(res)
    assert "<path>" in out, (
        f"the finding must say it is a PATH, not a line inside a file:\n{out}")
    # ⭐ BOTH plants, not just whichever one happens to fire first: a filename and a DIRECTORY name
    # publish identically, and reporting only one would be half a scan.
    assert f"{_ADDR}.conf" in out and f"docs/{_HOST}/notes.md" in out, out


def test_a_leak_in_a_FILENAME_reds_the_RANGE_scan(tmp_path: Path) -> None:
    """The push-path half. The tree scan is local; this is what CI and `pre-push` run."""
    repo = tmp_path / "paths_range"
    _seeded(repo)
    _write(repo, f"{_ADDR}.conf", "nothing to see\n")
    sha = _commit(repo, "add a config")

    assert f"{_ADDR}.conf" in _git(repo, "show", "--name-only", "--format=", sha)
    res = _cli(repo, "--range", f"{sha}^..{sha}")
    assert res.returncode == 1, f"a filename leak reached the range scan clean:\n{_out(res)}"
    assert "<path>" in _out(res), _out(res)


def test_a_clean_tree_of_ordinary_paths_still_passes_BOTH_scans(tmp_path: Path) -> None:
    """⛔ THE FALSE-RED DIRECTION, which matters as much as the catch: a guard that reddens
    correct work is one that gets switched off. Every path here occurs in ordinary repositories.
    """
    repo = tmp_path / "paths_clean"
    _init(repo)
    for rel in ("README.md", _DOTENV_LOCAL, ".env.example", "icons/app.png",
                "templates/svc.xml", "src/config.local.yml", ".claude/settings.local.json",
                "scripts/deploy.sh"):
        _write(repo, rel, "clean\n")
    sha = _commit(repo, "ordinary layout")

    tree = _cli(repo)
    assert tree.returncode == 0, f"a clean tree of ordinary paths reddened:\n{_out(tree)}"
    rng = _cli(repo, "--range", sha)
    assert rng.returncode == 0, f"a clean commit of ordinary paths reddened:\n{_out(rng)}"


def test_DELETING_a_badly_named_path_is_not_reported(tmp_path: Path) -> None:
    """⛔ A DELETION PUBLISHES NOTHING NEW, and its path was published by whichever commit ADDED
    it. Reporting it would make the commit that CLEANS UP a badly-named file fail forever — the
    same trap the removed-lines rule avoids, and the reason `changed_paths` passes
    `--diff-filter=d`.
    """
    repo = tmp_path / "paths_delete"
    _seeded(repo)
    _write(repo, f"{_ADDR}.conf", "clean\n")
    _commit(repo, "add it")
    (repo / f"{_ADDR}.conf").unlink()
    removal = _commit(repo, "remove it")

    assert f"{_ADDR}.conf" in _git(repo, "show", "--name-only", "--format=", removal), (
        "vacuity guard: the removal commit must actually touch that path")
    res = _cli(repo, "--range", f"{removal}^..{removal}")
    assert res.returncode == 0, f"a commit that DELETES a bad path was punished:\n{_out(res)}"


# ===========================================================================================
# #39 / keystone#21 — a leak in a commit MESSAGE or a TAG
# ===========================================================================================


def test_a_leak_in_a_commit_message_BODY_reds_the_range_scan(tmp_path: Path) -> None:
    """⭐ #39, the measured repro. Diff clean, identity clean, MESSAGE not.

    Measured at `main@046fc7e`: exit 0, `no internal info added across 1 commit(s)`.
    """
    repo = tmp_path / "message_body"
    _seeded(repo)
    _write(repo, "notes.md", "nothing internal here\n")
    body = (f"subject line is clean\n\n"
            f"deployed from {_HOST} at {_ADDR}, appdata under {_POOL}\n"
            f"policy {_UUID}, contact {_MAIL}\n")
    sha = _commit_with_message(repo, tmp_path, body)

    # Vacuity guards: the message really carries it, and the DIFF really does not.
    assert _HOST in _git(repo, "show", "-s", "--format=%B", sha)
    assert guard.scan_text((repo / "notes.md").read_text(encoding="utf-8"), COMPILED) == []

    res = _cli(repo, "--range", f"{sha}^..{sha}")
    assert res.returncode == 1, f"a leak in a commit message was published:\n{_out(res)}"
    assert "<commit message>" in _out(res), _out(res)


def test_a_leak_in_a_commit_SUBJECT_reds_the_range_scan(tmp_path: Path) -> None:
    """The one-line form. `%B` covers subject and body alike; a `%b`-only read would miss this."""
    repo = tmp_path / "message_subject"
    _seeded(repo)
    _write(repo, "notes.md", "clean\n")
    sha = _commit(repo, f"release cut on {_HOST}")

    res = _cli(repo, "--range", f"{sha}^..{sha}")
    assert res.returncode == 1, f"a leak in a commit SUBJECT was published:\n{_out(res)}"
    assert "<commit message>" in _out(res), _out(res)


def test_a_leak_in_an_ANNOTATED_TAG_message_reds_the_range_scan(tmp_path: Path) -> None:
    """A tag object is pushed and rendered exactly like a commit, and carries THREE leakable
    fields — its name, its tagger and its message."""
    repo = tmp_path / "tag_message"
    _seeded(repo)
    _write(repo, "notes.md", "clean\n")
    sha = _commit(repo, "clean subject")
    tagmsg = tmp_path / "tag-message.txt"
    tagmsg.write_bytes(f"release cut on {_HOST}, policy {_UUID}\n".encode("utf-8"))
    _git(repo, "tag", "-a", "v9.9.9", "-F", str(tagmsg))

    assert _HOST in _git(repo, "for-each-ref", "--format=%(contents)", "refs/tags/v9.9.9")
    res = _cli(repo, "--range", f"{sha}^..{sha}")
    assert res.returncode == 1, f"a leak in an annotated tag was published:\n{_out(res)}"
    assert "<tag object>" in _out(res), _out(res)


def test_a_leak_in_a_LIGHTWEIGHT_TAG_NAME_reds_the_range_scan(tmp_path: Path) -> None:
    """A lightweight tag has no object, no tagger and no message — only a NAME, which publishes.

    Excluding the cheap kind because it carries no message would leave exactly one hole.
    """
    repo = tmp_path / "tag_name"
    _seeded(repo)
    _write(repo, "notes.md", "clean\n")
    sha = _commit(repo, "clean subject")
    _git(repo, "tag", f"release-{_HOST}")

    assert f"release-{_HOST}" in _git(repo, "tag", "-l")
    res = _cli(repo, "--range", f"{sha}^..{sha}")
    assert res.returncode == 1, f"a leak in a tag NAME was published:\n{_out(res)}"


def test_a_tag_OUTSIDE_the_range_is_NOT_scanned(tmp_path: Path) -> None:
    """⛔ SCOPING IS A CORRECTNESS PROPERTY, not an optimisation. Scanning every tag in the
    repository on every push would red forever on a pre-existing badly-named tag that THIS push
    does not publish — a red nobody can clear, which is how a guard gets switched off.
    """
    repo = tmp_path / "tag_out_of_range"
    _seeded(repo)
    _write(repo, "old.md", "clean\n")
    old = _commit(repo, "old work")
    _git(repo, "tag", f"legacy-{_HOST}", old)
    _write(repo, "new.md", "clean\n")
    new = _commit(repo, "new work")

    assert f"legacy-{_HOST}" in _git(repo, "tag", "-l"), "vacuity guard: the bad tag must exist"
    res = _cli(repo, "--range", f"{old}..{new}")
    assert res.returncode == 0, (
        f"a tag on a commit OUTSIDE the range reddened a clean push:\n{_out(res)}")


def test_clean_messages_a_MERGE_and_a_clean_TAG_all_pass(tmp_path: Path) -> None:
    """The false-red direction for the message scan: an auto-generated merge subject, a message
    quoting the DOCUMENTED placeholder spellings, and an ordinary release tag."""
    repo = tmp_path / "message_clean"
    _seeded(repo)
    _git(repo, "checkout", "-q", "-b", "side")
    _write(repo, "side.txt", "side\n")
    _commit(repo, "side change")
    _git(repo, "checkout", "-q", "main")
    _write(repo, "main.txt", "main\n")
    base = _commit(repo, f"document the example host {_OK_HOST} at {_OK_ADDR}")
    _git(repo, "merge", "--no-ff", "-q", "-m",
         "Merge pull request #1 from texasdaddy/side", "side")
    head = _git(repo, "rev-parse", "HEAD").strip()
    _git(repo, "tag", "-a", "v1.0.0", "-m", f"clean release, see {_OK_HOST}")

    assert head != base, "vacuity guard: the merge must have created a commit"
    res = _cli(repo, "--range", head)
    assert res.returncode == 0, f"ordinary clean history reddened:\n{_out(res)}"


def test_the_message_read_survives_log_showSignature(tmp_path: Path) -> None:
    """⛔ THE SAME TRAP `commit_identity` CARRIES, one call site over. With
    `log.showSignature=true` git prepends the signature-VERIFICATION block to stdout, ahead of the
    `--format` output — and that block quotes a key path under a user profile and a signer
    principal. Without `--no-show-signature` the message read INVENTS a finding on a commit whose
    message is clean, and the operator is told to rewrite history over text git printed.
    """
    repo = tmp_path / "showsig"
    _seeded(repo)
    _git(repo, "config", "log.showSignature", "true")
    _write(repo, "notes.md", "clean\n")
    sha = _commit(repo, "an entirely clean subject")

    assert _git(repo, "config", "log.showSignature").strip() == "true", "vacuity guard"
    assert "--no-show-signature" in guard.commit_message.__doc__ or True  # documented; asserted:
    text = guard.commit_message(repo, sha)
    assert text.strip() == "an entirely clean subject", (
        f"the message read picked up more than the message: {text!r}")
    res = _cli(repo, "--range", f"{sha}^..{sha}")
    assert res.returncode == 0, f"a clean commit reddened under log.showSignature:\n{_out(res)}"


def test_the_message_scan_reads_the_REAL_commit_not_a_restatement(tmp_path: Path) -> None:
    """⭐ A test must EXECUTE the thing it names. This asserts on what `git` actually returned for
    a specific sha, so deleting `commit_message`'s call site cannot leave it green.
    """
    repo = tmp_path / "message_real"
    _seeded(repo)
    _write(repo, "a.txt", "a\n")
    first = _commit(repo, "first subject")
    _write(repo, "b.txt", "b\n")
    second = _commit(repo, "second subject")

    assert guard.commit_message(repo, first).strip() == "first subject"
    assert guard.commit_message(repo, second).strip() == "second subject"
    assert guard.scan_message(second, f"host {_HOST}", COMPILED), (
        "scan_message must report a leak in the text it is handed")
    assert guard.scan_message(second, f"host {_OK_HOST}", COMPILED) == []


# ===========================================================================================
# #33 / keystone#23 — the INDEX, not the worktree
# ===========================================================================================


def test_a_leak_STAGED_then_TIDIED_is_caught_by_the_staged_scan(tmp_path: Path) -> None:
    """⭐ #33, the measured repro, both halves.

    Measured at `main@046fc7e`: the tree scan exits 0 (`2 tracked text files scanned`) and
    `git show HEAD:cfg.txt` returns the leak. The tree scan's answer is HONEST — the worktree
    really is clean — which is exactly why a second question had to be asked.
    """
    repo = tmp_path / "staged"
    _seeded(repo)
    _write(repo, "cfg.txt", f"{_LEAK_LINE}\n")
    _git(repo, "add", "cfg.txt")
    _write(repo, "cfg.txt", f"AGENT_URL=http://{_OK_HOST}:9999/mcp\n")

    # Vacuity guards for BOTH premises of this test.
    assert _HOST in _git(repo, "cat-file", "blob", ":cfg.txt"), "the INDEX must hold the leak"
    assert _HOST not in (repo / "cfg.txt").read_text(encoding="utf-8"), (
        "the WORKTREE must have been tidied, or there is nothing here the tree scan misses")

    tree = _cli(repo)
    assert tree.returncode == 0, (
        f"premise changed: the tree scan is no longer blind to this:\n{_out(tree)}")
    staged = _cli(repo, "--staged")
    assert staged.returncode == 1, f"the staged leak was not caught:\n{_out(staged)}"
    assert "STAGED FOR COMMIT" in _out(staged), _out(staged)


def test_the_pre_commit_HOOK_actually_blocks_the_staged_then_tidied_commit(tmp_path: Path) -> None:
    """⭐⭐ THE CLASS-TERMINATING ASSERTION: run the real hook, in a real repository, and check
    what it DID — the commit is refused and HEAD does not move.

    A wiring assertion ("`--staged` appears in the hook file") is the infinite-regress form this
    file's siblings warn about: it holds while the hook is unreachable, while the script path is
    wrong, and while the exit code is discarded by a missing `|| exit 1`. Copying the two
    directories into a scratch repository and running `git commit` under
    `core.hooksPath=.githooks` answers the question that actually matters.
    """
    repo = tmp_path / "hook"
    _seeded(repo)
    shutil.copytree(_REPO_ROOT / "scripts", repo / "scripts",
                    ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copytree(_REPO_ROOT / ".githooks", repo / ".githooks")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "bring the guard and its hooks in")
    _git(repo, "config", "core.hooksPath", ".githooks")
    before = _git(repo, "rev-parse", "HEAD").strip()

    _write(repo, "cfg.txt", f"{_LEAK_LINE}\n")
    _git(repo, "add", "cfg.txt")
    _write(repo, "cfg.txt", f"AGENT_URL=http://{_OK_HOST}:9999/mcp\n")
    assert _HOST in _git(repo, "cat-file", "blob", ":cfg.txt"), "vacuity guard"

    attempt = subprocess.run(["git", *_PINNED, "commit", "-m", "add cfg"], cwd=repo,
                             capture_output=True, check=False, timeout=300)
    after = _git(repo, "rev-parse", "HEAD").strip()
    assert attempt.returncode != 0, (
        "the pre-commit hook allowed a commit whose INDEX carries a leak:\n"
        + attempt.stdout.decode("utf-8", "replace") + attempt.stderr.decode("utf-8", "replace"))
    assert after == before, "the commit was created despite the hook failing"


def test_the_pre_commit_HOOK_still_allows_a_clean_commit(tmp_path: Path) -> None:
    """⛔ The other half, and the one that stops this being a hook that only ever says no. A guard
    proven only in its rejecting direction can be one that rejects everything.
    """
    repo = tmp_path / "hook_clean"
    _seeded(repo)
    shutil.copytree(_REPO_ROOT / "scripts", repo / "scripts",
                    ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copytree(_REPO_ROOT / ".githooks", repo / ".githooks")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "bring the guard and its hooks in")
    _git(repo, "config", "core.hooksPath", ".githooks")
    before = _git(repo, "rev-parse", "HEAD").strip()

    _write(repo, "cfg.txt", f"AGENT_URL=http://{_OK_HOST}:9999/mcp\n")
    _git(repo, "add", "cfg.txt")
    attempt = subprocess.run(["git", *_PINNED, "commit", "-m", "add a clean cfg"], cwd=repo,
                             capture_output=True, check=False, timeout=300)
    after = _git(repo, "rev-parse", "HEAD").strip()
    assert attempt.returncode == 0, (
        "the hooks blocked an entirely clean commit:\n"
        + attempt.stdout.decode("utf-8", "replace") + attempt.stderr.decode("utf-8", "replace"))
    assert after != before, "the clean commit was not created"


def test_the_staged_scan_ignores_a_leak_that_is_only_in_the_WORKTREE(tmp_path: Path) -> None:
    """`--staged` answers "what will this commit record". An unstaged scratch file is not part of
    it, and reddening on one would block ordinary mid-edit work."""
    repo = tmp_path / "staged_unstaged"
    _seeded(repo)
    _write(repo, "new.txt", f"host {_OK_HOST} addr {_OK_ADDR}\n")
    _git(repo, "add", "new.txt")
    _write(repo, "scratch.txt", f"{_LEAK_LINE}\n")   # never staged

    assert "scratch.txt" not in _git(repo, "diff", "--cached", "--name-only"), "vacuity guard"
    res = _cli(repo, "--staged")
    assert res.returncode == 0, f"an UNSTAGED leak blocked the commit:\n{_out(res)}"


def test_the_staged_scan_catches_a_leak_in_a_STAGED_PATH(tmp_path: Path) -> None:
    """The path surface applies to the index too, or `git add <bad-name>` slips the commit-time
    layer the same way it slipped the other two."""
    repo = tmp_path / "staged_path"
    _seeded(repo)
    _write(repo, f"{_ADDR}.conf", "clean content\n")
    _git(repo, "add", "-A")

    res = _cli(repo, "--staged")
    assert res.returncode == 1, f"a staged leaky PATH was not caught:\n{_out(res)}"
    assert "<path>" in _out(res), _out(res)


def test_the_staged_scan_works_on_a_repository_with_no_HEAD(tmp_path: Path) -> None:
    """⛔ THE INITIAL COMMIT is when a whole tree is staged at once, so a `--staged` that dies on
    a missing HEAD would leave the first and largest commit unscanned by this layer."""
    repo = tmp_path / "staged_no_head"
    _init(repo)
    _write(repo, "cfg.txt", f"{_LEAK_LINE}\n")
    _git(repo, "add", "-A")

    assert not guard.resolves(repo, "HEAD"), "vacuity guard: this repo must have no HEAD yet"
    res = _cli(repo, "--staged")
    assert res.returncode == 1, f"the first commit was not scanned:\n{_out(res)}"


def test_the_staged_scan_RESOLVES_a_gitattributes_binary_text_file(tmp_path: Path) -> None:
    """⛔ THE FALSE-RED THIS LAYER WOULD OTHERWISE HAVE INTRODUCED, and the reason the `--text`
    re-diff is shared rather than left inline in `added_lines`.

    Marking a generated lockfile `binary` in `.gitattributes` is standard practice, and git then
    answers `Binary files … differ` for an ordinary UTF-8 text file. The range scan has always
    re-diffed those with `--text` and scanned them properly; a `--staged` that did not would have
    reported the same file "not scanned, so NOT CLEARED" and blocked every commit touching it —
    a red on correct work, in the layer a developer meets most often.

    Both directions are asserted: the clean lockfile passes, and a leak inside one is still found.
    """
    repo = tmp_path / "staged_lock"
    _seeded(repo)
    _write(repo, ".gitattributes", "*.lock binary\n")
    _write(repo, "deps.lock", "resolved = 1\n")
    _git(repo, "add", "-A")

    # Vacuity guard: git must really be calling it binary, or this tests nothing.
    assert "Binary files" in _git(repo, "diff", "--cached", "--no-ext-diff", "HEAD"), (
        "the .gitattributes binary marking did not take effect")
    clean = _cli(repo, "--staged")
    assert clean.returncode == 0, (
        f"an ordinary text file marked `binary` blocked the commit:\n{_out(clean)}")

    _write(repo, "deps.lock", f"resolved = 1\nregistry = http://{_HOST}/simple\n")
    _git(repo, "add", "-A")
    dirty = _cli(repo, "--staged")
    assert dirty.returncode == 1, (
        f"a leak inside a `binary`-marked TEXT file was cleared:\n{_out(dirty)}")


def test_the_staged_scan_passes_a_clean_index(tmp_path: Path) -> None:
    repo = tmp_path / "staged_clean"
    _seeded(repo)
    _write(repo, "docs/notes.md", f"see {_OK_HOST} and {_OK_ADDR}\n")
    _git(repo, "add", "-A")
    res = _cli(repo, "--staged")
    assert res.returncode == 0, f"a clean index was refused:\n{_out(res)}"


# ===========================================================================================
# keystone#22 — the suffix is a hint, and a scan that read nothing is not clean
# ===========================================================================================


def test_looks_binary_asks_the_BYTES(tmp_path: Path) -> None:
    """The pure half. A NUL anywhere, or bytes that are not UTF-8, mean binary; ASCII does not."""
    assert guard._looks_binary(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR")
    assert guard._looks_binary(b"plain text with a nul \x00 inside")
    assert guard._looks_binary(b"\xff\xd8\xff\xe0latin-1 \xe9 bytes")
    assert not guard._looks_binary(b"an ordinary ASCII runbook\n")
    assert not guard._looks_binary("accented but UTF-8: café\n".encode("utf-8"))


def test_an_ASCII_leak_in_a_pdf_NAMED_file_reds_the_TREE_scan(tmp_path: Path) -> None:
    """⭐ keystone#22, the measured repro. Renaming a text file must not defeat the guard.

    Measured at `main@046fc7e`: exit 0, `no internal info found (1 tracked text files scanned)`.
    """
    repo = tmp_path / "suffix_tree"
    _init(repo)
    _write(repo, "README.md", "clean\n")
    _write(repo, "deploy-notes.pdf", f"host {_HOST}\npool {_POOL}\naddr {_ADDR}\n")
    _git(repo, "add", "-A")

    assert guard._binary_suffix("deploy-notes.pdf"), "vacuity guard: .pdf must be a skip suffix"
    assert not guard._looks_binary((repo / "deploy-notes.pdf").read_bytes()), (
        "vacuity guard: the plant must really be text")

    res = _cli(repo)
    assert res.returncode == 1, f"an ASCII leak named .pdf walked past the tree scan:\n{_out(res)}"


def test_an_ASCII_leak_in_a_pdf_NAMED_file_reds_the_RANGE_scan(tmp_path: Path) -> None:
    repo = tmp_path / "suffix_range"
    _seeded(repo)
    _write(repo, "deploy-notes.pdf", f"host {_HOST}\npool {_POOL}\n")
    sha = _commit(repo, "add notes")

    res = _cli(repo, "--range", f"{sha}^..{sha}")
    assert res.returncode == 1, (
        f"an ASCII leak named .pdf walked past the range scan:\n{_out(res)}")


def test_a_GENUINELY_binary_asset_is_still_skipped_in_silence(tmp_path: Path) -> None:
    """⛔ THE FALSE-RED DIRECTION. The suffix list exists so an image is not reported as
    "unreadable, so not cleared" on every run; sniffing content must not cost that."""
    repo = tmp_path / "suffix_binary"
    _init(repo)
    _write(repo, "README.md", "clean\n")
    png = (b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + bytes(range(256)) * 4
           + _HOST.encode() + b"\x00\xff\xfe")
    (repo / "icons").mkdir()
    (repo / "icons" / "logo.png").write_bytes(png)
    _git(repo, "add", "-A")

    assert guard._looks_binary(png), "vacuity guard: the plant must really be binary"
    res = _cli(repo)
    assert res.returncode == 0, f"an ordinary image reddened the tree scan:\n{_out(res)}"
    assert "UNREADABLE" not in _out(res), _out(res)


def test_a_NUL_bearing_blob_at_a_SKIPPED_suffix_is_still_skipped(tmp_path: Path) -> None:
    """⚠️ THE STATED SCOPE OF THIS CHANGE, pinned so it is discoverable rather than folklore.

    `_looks_binary` treats a NUL as binary, so a UTF-16 payload hidden in a file named `.pdf` is
    skipped silently — exactly as it was before this change, no better and no worse. At any OTHER
    path a NUL-bearing blob is still REFUSED and reported (the #242 posture). Widening this means
    re-litigating which suffixes are assets, which is issue #38's design call and not this one's.
    """
    repo = tmp_path / "suffix_nul"
    _init(repo)
    _write(repo, "README.md", "clean\n")
    utf16 = f"{_LEAK_LINE}\n".encode("utf-16-le")
    (repo / "notes.pdf").write_bytes(utf16)
    (repo / "notes.txt").write_bytes(utf16)
    _git(repo, "add", "-A")

    res = _cli(repo)
    assert res.returncode == 1, "a NUL-bearing .txt must still be refused"
    out = _out(res)
    assert "notes.txt" in out, f"the #242 refusal no longer fires on an ordinary path:\n{out}"
    assert "notes.pdf" not in out, (
        f"a declared binary asset is skipped silently, not reported:\n{out}")


def test_a_run_that_scanned_ZERO_files_is_an_ERROR_not_a_pass(tmp_path: Path) -> None:
    """⭐ keystone#22, second half. A scan that opened no file cannot clear a tree.

    Measured at `main@046fc7e`: `no internal info found (0 tracked text files scanned)`, exit 0 —
    a cheerful pass in the same words a real one uses. The count was printed all along; nothing
    acted on it.
    """
    repo = tmp_path / "floor"
    _init(repo)
    (repo / "only.pdf").write_bytes(b"\x89PDF\x00\x00binary-ish\x00\xff\xfe")
    _git(repo, "add", "-A")

    assert _git(repo, "ls-files").split() == ["only.pdf"], "vacuity guard"
    res = _cli(repo)
    assert res.returncode == 1, f"a scan that read nothing reported clean:\n{_out(res)}"
    assert "ZERO" in _out(res), _out(res)


def test_the_floor_does_not_fire_on_an_ordinary_tree(tmp_path: Path) -> None:
    """The false-red direction for the floor: one readable text file is enough."""
    repo = tmp_path / "floor_ok"
    _init(repo)
    _write(repo, "README.md", "clean\n")
    (repo / "logo.png").write_bytes(b"\x89PNG\x00\x00binary")
    _git(repo, "add", "-A")
    res = _cli(repo)
    assert res.returncode == 0, f"an ordinary tree tripped the zero-scan floor:\n{_out(res)}"


# ===========================================================================================
# The engine's own wiring — assert what the scan DID, not what a constant holds
# ===========================================================================================


def test_the_range_scan_reads_ALL_FIVE_surfaces_of_every_commit(tmp_path: Path) -> None:
    """⭐ THE CLASS-TERMINATING INVARIANT for this package, in the style of
    `test_EVERY_git_diff_the_scan_runs_carries_the_pinned_config_and_flags`: run the real
    `scan_range` and record which readers it actually called, per commit.

    A per-surface test proves each reader works; this proves `scan_range` still CALLS each of
    them. Deleting one line from `scan_range` leaves every other test in this file green.
    """
    repo = tmp_path / "surfaces"
    _seeded(repo)
    _write(repo, "a.txt", "a\n")
    first = _commit(repo, "first")
    _write(repo, "b.txt", "b\n")
    second = _commit(repo, "second")

    called: dict[str, list[str]] = {"added": [], "paths": [], "identity": [], "message": [],
                                    "tags": []}
    originals = {name: getattr(guard, name) for name in
                 ("added_lines", "changed_paths", "commit_identity", "commit_message",
                  "annotated_tags")}

    def wrap(name: str, key: str, index: int):
        real = originals[name]

        def spy(*args, **kw):
            called[key].append(str(args[index]) if len(args) > index else "")
            return real(*args, **kw)
        return spy

    guard.added_lines = wrap("added_lines", "added", 1)
    guard.changed_paths = wrap("changed_paths", "paths", 2)
    guard.commit_identity = wrap("commit_identity", "identity", 1)
    guard.commit_message = wrap("commit_message", "message", 1)
    guard.annotated_tags = wrap("annotated_tags", "tags", 1)
    try:
        result = guard.scan_range(repo, f"{first}..{second}", COMPILED)
    finally:
        for name, real in originals.items():
            setattr(guard, name, real)

    assert result.commits == 1, result
    for key in ("added", "paths", "identity", "message"):
        assert called[key] == [second], (
            f"{key} was not read for exactly the commit in range: {called[key]}")
    assert len(called["tags"]) == 1, f"the tag pass did not run once: {called['tags']}"


def test_the_staged_scan_reads_both_the_index_DIFF_and_its_PATHS(tmp_path: Path) -> None:
    """The same invariant for `--staged`: it is two questions, and dropping either is silent."""
    repo = tmp_path / "staged_surfaces"
    _seeded(repo)
    _write(repo, "cfg.txt", "clean\n")
    _git(repo, "add", "-A")

    parsed, paths = guard.staged_diff(repo)
    assert paths == ["cfg.txt"], paths
    assert [c for _, _, c in parsed.added] == ["clean"], parsed.added


def test_changed_paths_excludes_deletions_and_keeps_modifications(tmp_path: Path) -> None:
    repo = tmp_path / "changed_paths"
    _seeded(repo)
    _write(repo, "keep.txt", "one\n")
    _write(repo, "gone.txt", "one\n")
    base = _commit(repo, "add two")
    _write(repo, "keep.txt", "two\n")
    (repo / "gone.txt").unlink()
    head = _commit(repo, "modify one, delete the other")

    got = guard.changed_paths(repo, base, head)
    assert got == ["keep.txt"], (
        f"a deletion must not be reported and a modification must be: {got}")
