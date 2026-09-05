"""The cheap, measured leak-guard defects the 2026-09 audit closed, each pinned by planting.

Every test here is the issue's own repro, re-run against the engine: the forbidden thing is
planted in a throwaway repository and the guard must CATCH it (or, for the false-red and
usability issues, must give a VERDICT rather than a traceback). Each carries the issue it
closes, so a future edit that reopens the gap fails a test named for it.

  #42  under `--repo`, the self-exemption fell back to the SELF_PATH constant and exempted
       whatever the AUDITED repository kept at `scripts/check_no_internal_info.py`.
  #46  the tree scan followed a symlink and scanned the target's CONTENT, while the blob git
       publishes for a mode-120000 entry is the target PATH — the two scans disagreed.
  #47  `.githooks/pre-push` excluded commits on ANY remote-tracking ref, so a push to a second
       remote skipped a leak that remote had never seen.
  #48  `--repo` at a file or a missing path died with a traceback instead of a verdict.
  #50  `repo_root` decoded git's output with the locale codec, so a non-ASCII repository path
       crashed every commit and push through the hooks.
  #44  (partial) `first_parent` was computed twice per commit.

And three gaps the same audit found in the SUITE rather than the engine — guards asserted only
in the clean direction:
  - `--selftest` had never been shown to FAIL, so a selftest gutted to `return 0` was invisible;
  - the message surface ran two patterns (cgnat, tailnet) with no deny case, and the selftest's
    completeness floor asked only the content corpus;
  - the shallow-clone refusal and the strict argument parser had no test at all.

⚠️ EVERY LEAKING LITERAL IS ASSEMBLED AT RUNTIME and every one is synthetic (the guard's own
`_MUST_FAIL` shapes). This file is scanned by the guard.

⚠️ EVERY `git` CALL PINS ITS CONFIG: no global or system config, identity injected — the CI
runner has none, and a commit that silently no-ops there makes a plant-and-measure vacuous.
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "check_no_internal_info.py"
_HOOKS = _SCRIPT.parents[1] / ".githooks"

_spec = importlib.util.spec_from_file_location("check_no_internal_info_audit_fixes", _SCRIPT)
assert _spec and _spec.loader
guard = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(guard)

_HOST = "host-a." + "lan"
_ADDR = "192.168." + "77.77"
_POOL = "/mnt/" + "user" + "/appdata/svc"
_LEAK_LINE = f"AGENT_URL=http://{_HOST}:9999/mcp"

_ENV = {
    **os.environ,
    "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull,
    "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com",
    "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.com",
    "PYTHONDONTWRITEBYTECODE": "1", "PYTHONIOENCODING": "utf-8",
}


def _git(cwd: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=cwd, env=_ENV, capture_output=True,
                          encoding="utf-8", errors="replace", check=check, timeout=120)


def _guard(cwd: Path, *args: str, env: dict | None = None) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(_SCRIPT), *args], cwd=cwd, env=env or _ENV,
                          capture_output=True, encoding="utf-8", errors="replace", timeout=300)


# A locale whose codec cannot spell an accented path, forced on the child so that the #50
# trap reproduces on the UTF-8 CI runner and not only on a cp1252 Windows workstation: with
# coercion off, a C locale makes `text=True` decode git's UTF-8 bytes as ASCII and die.
_C_LOCALE = {**_ENV, "LC_ALL": "C", "LANG": "C", "LANGUAGE": "C",
             "PYTHONUTF8": "0", "PYTHONCOERCECLOCALE": "0"}


def _init(repo: Path) -> Path:
    repo.mkdir(parents=True, exist_ok=True)
    _git(repo, "init", "-q", "-b", "main")
    return repo


def _commit(repo: Path, msg: str = "c") -> str:
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", msg)
    return _git(repo, "rev-parse", "HEAD").stdout.strip()


def _clean(out: subprocess.CompletedProcess) -> str:
    return out.stdout + out.stderr


# ------------------------------------------------------------------------------------- #42


@pytest.mark.timeout(300)
def test_under_repo_a_decoy_at_the_guards_own_path_is_NOT_exempt(tmp_path: Path):
    """#42. The audited tree keeps three deny shapes in a file at `scripts/check_no_internal_info.py`.
    The guard is run from OUTSIDE that tree, so `__file__` does not resolve under it. Both scans
    must report the decoy; before the fix both exited 0."""
    repo = _init(tmp_path / "decoy")
    (repo / "ok.txt").write_text("clean\n", encoding="utf-8")
    (repo / "scripts").mkdir()
    (repo / "scripts" / "check_no_internal_info.py").write_text(
        f"AGENT={_ADDR} host {_HOST} pool {_POOL}\n", encoding="utf-8")
    _commit(repo, "decoy")

    tree = _guard(tmp_path, "--repo", str(repo))
    assert tree.returncode == 1, _clean(tree)
    assert "scripts/check_no_internal_info.py:1: private IPv4" in tree.stdout, tree.stdout
    rng = _guard(tmp_path, "--repo", str(repo), "--range", "HEAD")
    assert rng.returncode == 1, _clean(rng)
    assert "scripts/check_no_internal_info.py:1:" in rng.stdout, rng.stdout


def test_the_self_exemption_still_lands_on_THIS_file_when_run_in_its_own_tree():
    """The other direction: run from inside its own repository, the guard must still exempt
    itself (it carries every deny shape as a corpus). `_self_rel_path` with the real root."""
    guard._self_rel_path.cache_clear()
    assert guard._is_self("scripts/check_no_internal_info.py", _SCRIPT.parents[1])
    assert guard._self_rel_path(_SCRIPT.parents[1]) == guard.SELF_PATH


def test_outside_its_tree_the_exemption_names_no_file_at_all(tmp_path: Path):
    guard._self_rel_path.cache_clear()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    assert guard._self_rel_path(elsewhere) == guard._NOT_IN_THIS_TREE
    assert not guard._is_self("scripts/check_no_internal_info.py", elsewhere)
    assert not guard._is_self("", elsewhere)
    # `root=None` keeps the constant: that arm serves the project-side guard, not a scan.
    assert guard._self_rel_path(None) == guard.SELF_PATH


# ------------------------------------------------------------------------------------- #50


@pytest.mark.timeout(300)
def test_a_non_ascii_repository_path_gets_a_verdict_not_a_traceback(tmp_path: Path):
    """#50. The hooks run the guard with NO `--repo`, from inside the repository, so the path
    git prints is the only thing `repo_root` has. With `text=True` it came back as mojibake
    under a cp1252 locale and every later `cwd=root` died. The child also runs under a C locale
    here (see `_C_LOCALE`) so that a regression to `text=True` is expected to fire on a UTF-8
    runner too — `os.fsdecode` survives a C locale through surrogateescape, `text=True` does
    not. STATED LIMIT: the regression was measured only under cp1252 (Windows ignores LC_ALL
    for this), so the C-locale leg is an intent the CI run has not yet been seen to prove."""
    repo = _init(tmp_path / "café-日本")
    (repo / "README.md").write_text("clean\n", encoding="utf-8")
    _commit(repo)
    for env in (_ENV, _C_LOCALE):
        out = _guard(repo, env=env)
        assert "Traceback" not in _clean(out), _clean(out)
        assert out.returncode == 0, _clean(out)
        assert "1 tracked text files scanned" in out.stdout
    # and the plant still bites through that path: a leak there is a real finding, not a crash
    (repo / "cfg.txt").write_text(_LEAK_LINE + "\n", encoding="utf-8")
    _commit(repo, "leak")
    for env in (_ENV, _C_LOCALE):
        out = _guard(repo, "--range", "HEAD", env=env)
        assert out.returncode == 1 and _HOST in out.stdout, _clean(out)


def test_repo_root_decodes_gits_output_as_a_filesystem_path_not_the_locale(tmp_path: Path):
    repo = _init(tmp_path / "é")
    (repo / "x").write_text("x", encoding="utf-8")
    _commit(repo)
    got = guard.repo_root(str(repo))
    assert got.resolve() == repo.resolve()


# ------------------------------------------------------------------------------------- #48


@pytest.mark.timeout(300)
def test_repo_at_a_file_a_missing_path_or_a_non_repository_is_a_usage_error(tmp_path: Path):
    """#48. Three bad `--repo` inputs, each a VERDICT (exit 2, the usage-error code) naming the
    path — never a traceback. A directory that is not a repository is the third: git itself
    refuses it and that refusal is now reported the same way."""
    somefile = tmp_path / "somefile"
    somefile.write_text("not a directory\n", encoding="utf-8")
    plain = tmp_path / "plain-directory"
    plain.mkdir()
    for target, expect in (
        (somefile, "is not a directory this can run git in"),
        (tmp_path / "does-not-exist", "is not a directory this can run git in"),
        (plain, "is not inside a git repository"),
    ):
        out = _guard(tmp_path, "--repo", str(target))
        combined = _clean(out)
        assert "Traceback" not in combined, combined
        assert out.returncode == 2, combined
        assert expect in combined and str(target) in combined, combined
        assert "usage:" in combined, "the usage text accompanies a usage error"


# ------------------------------------------------------------------------------------- #46


def _can_symlink(where: Path) -> bool:
    try:
        target = where / "probe-target"
        target.write_text("x", encoding="utf-8")
        os.symlink("probe-target", where / "probe-link")
        return True
    except (OSError, NotImplementedError):
        return False


@pytest.mark.timeout(300)
def test_a_symlink_is_scanned_as_the_path_it_points_at_by_every_scan(tmp_path: Path):
    """#46. The blob git stores for a symlink IS its target path string, and that is what a push
    publishes. The tree scan used to follow the link and scan the target's content instead:
    a link named after a clean file but pointing at `<leak>/...` vouched for a file it never
    read, while the range scan (reading the blob) reported the leak — two scans, two answers.
    Now all three read the link. The target here is gitignored so the PATH surface cannot be
    what catches it, and it is CLEAN so following the link would report nothing."""
    if not _can_symlink(tmp_path):
        pytest.skip("this platform or account cannot create a symlink")
    repo = _init(tmp_path / "links")
    _git(repo, "config", "core.symlinks", "true")
    (repo / ".gitignore").write_text(".cache/\n", encoding="utf-8")
    hidden = repo / ".cache" / _HOST
    hidden.mkdir(parents=True)
    (hidden / "cfg.txt").write_text("clean content\n", encoding="utf-8")
    os.symlink(f".cache/{_HOST}/cfg.txt", repo / "link.txt")
    (repo / "README.md").write_text("clean\n", encoding="utf-8")
    sha = _commit(repo, "link")
    mode = _git(repo, "ls-files", "-s", "link.txt").stdout.split()[0]
    if mode != "120000":
        pytest.skip(f"git stored the link as mode {mode}, not a symlink, on this platform")

    tree = _guard(repo)
    assert tree.returncode == 1, _clean(tree)
    assert f"link.txt:1: private lan domain: '{_HOST}'" in tree.stdout, tree.stdout
    assert "unreadable" not in tree.stdout.lower(), "a readable link must not be reported unreadable"
    rng = _guard(repo, "--range", sha)
    assert rng.returncode == 1 and f"link.txt:1: private lan domain: '{_HOST}'" in rng.stdout, _clean(rng)
    # the third scan, on a second link that is STAGED and not yet committed
    os.symlink(f".cache/{_HOST}/other.txt", repo / "link2.txt")
    _git(repo, "add", "link2.txt")
    staged = _guard(repo, "--staged")
    assert staged.returncode == 1 and f"link2.txt:1: private lan domain: '{_HOST}'" in staged.stdout, _clean(staged)


@pytest.mark.timeout(300)
def test_a_clean_symlink_does_not_red_the_tree_scan(tmp_path: Path):
    """The false-red half: links to clean things are an ordinary tree and must pass — a link to
    a sibling file, a DANGLING link (which the absent-file branch already resolved through the
    index and never reddened), and a link to a DIRECTORY, which `read_bytes` refused with
    IsADirectoryError (PermissionError on Windows) and reported as unreadable: that was the
    false red. All are scanned as their target strings and counted."""
    if not _can_symlink(tmp_path):
        pytest.skip("this platform or account cannot create a symlink")
    repo = _init(tmp_path / "clean-links")
    _git(repo, "config", "core.symlinks", "true")
    (repo / "real.txt").write_text("clean\n", encoding="utf-8")
    (repo / "d").mkdir()
    (repo / "d" / "inner.txt").write_text("clean\n", encoding="utf-8")
    os.symlink("real.txt", repo / "alias.txt")
    os.symlink("gone.txt", repo / "dangling.txt")
    os.symlink("d", repo / "dirlink", target_is_directory=True)
    _commit(repo)
    modes = {p: _git(repo, "ls-files", "-s", p).stdout.split()[0] for p in ("alias.txt", "dirlink")}
    if set(modes.values()) != {"120000"}:
        pytest.skip(f"git did not store the links as symlinks on this platform: {modes}")
    out = _guard(repo)
    assert out.returncode == 0, _clean(out)
    assert "unreadable" not in out.stdout.lower(), out.stdout
    assert "5 tracked text files scanned" in out.stdout, out.stdout


# ------------------------------------------------------------------------------------- #47


def _repo_with_hook(root: Path) -> Path:
    repo = _init(root)
    (repo / "scripts").mkdir()
    shutil.copy(_SCRIPT, repo / "scripts" / "check_no_internal_info.py")
    (repo / ".githooks").mkdir()
    shutil.copy(_HOOKS / "pre-push", repo / ".githooks" / "pre-push")
    (repo / "README.md").write_text("clean\n", encoding="utf-8")
    _commit(repo, "clean")
    return repo


def _bare(path: Path) -> Path:
    subprocess.run(["git", "init", "-q", "--bare", str(path)], env=_ENV, check=True,
                   capture_output=True, timeout=120)
    return path


@pytest.mark.timeout(600)
def test_pre_push_scans_what_the_TARGET_remote_lacks_not_what_any_remote_has(tmp_path: Path):
    """#47, both directions through the REAL hook against two bare remotes.

    A leak already on `private` is pushed to `public`, which has never seen it: the hook
    must scan it and block the push (it used to exclude it as "already on a remote"). Then a
    NEW branch at that same history is pushed to `private` — which already holds every commit
    on it — and must NOT re-scan and re-red what that remote already has: exit 0, "0 commit(s)".
    Both are the brand-new-ref form, so both go through the narrowed `--remotes=<name>`."""
    private = _bare(tmp_path / "private.git")
    public = _bare(tmp_path / "public.git")
    repo = _repo_with_hook(tmp_path / "work")
    (repo / "cfg.txt").write_text(_LEAK_LINE + "\n", encoding="utf-8")
    _commit(repo, "leak")
    _git(repo, "remote", "add", "private", str(private))
    _git(repo, "remote", "add", "public", str(public))
    _git(repo, "push", "-q", "private", "main")        # hook not yet enabled: seeds private/main
    _git(repo, "config", "core.hooksPath", ".githooks")

    blocked = _git(repo, "push", "public", "main", check=False)
    assert blocked.returncode != 0, "the leak reached a remote that had never seen it:\n" + _clean(blocked)
    assert "--not --remotes=public" in _clean(blocked), _clean(blocked)
    assert f"private lan domain: '{_HOST}'" in _clean(blocked), _clean(blocked)
    assert _git(tmp_path, "ls-remote", "--heads", str(public)).stdout.strip() == "", "nothing landed"

    _git(repo, "branch", "feature", "main")
    again = _git(repo, "push", "private", "feature", check=False)
    assert again.returncode == 0, "a push to the remote that already holds the history was reddened:\n" + _clean(again)
    assert "--not --remotes=private" in _clean(again), _clean(again)
    assert "0 commit(s)" in _clean(again), "nothing new for private: its own refs exclude the history"
    # and the ordinary existing-branch push is untouched: a clean new commit scans as one commit
    (repo / "more.txt").write_text("clean\n", encoding="utf-8")
    _commit(repo, "more")
    routine = _git(repo, "push", "private", "main", check=False)
    assert routine.returncode == 0 and "1 commit(s)" in _clean(routine), _clean(routine)


def test_the_hook_narrows_the_exclusion_only_for_a_remote_NAME():
    """A push that names a URL directly has no remote name to narrow to: the wide form stays,
    because the alternative — no exclusion at all — would re-scan a whole history."""
    src = (_HOOKS / "pre-push").read_text(encoding="utf-8")
    assert 'remote_name="${1:-}"' in src
    assert "--not --remotes=$remote_name" in src
    assert src.count("$not_pushed") == 2, "BOTH range forms (tag and branch) use the narrowed form"
    assert "--not --remotes\"" in src or "--not --remotes\" ;;" in src, "the URL/empty arm keeps the wide form"


# ------------------------------------------------------------------------------------- #44


@pytest.mark.timeout(300)
def test_one_commit_costs_one_first_parent_lookup(tmp_path: Path, monkeypatch):
    """#44, the free part. `scan_range` resolved each commit's parent and `added_lines` resolved
    it again — two `rev-parse --verify <sha>^` per commit for one answer."""
    repo = _init(tmp_path / "parents")
    (repo / "README.md").write_text("clean\n", encoding="utf-8")
    _commit(repo, "root")
    for i in range(3):
        (repo / f"f{i}.txt").write_text(f"{i}\n", encoding="utf-8")
        _commit(repo, f"c{i}")
    calls: list[list[str]] = []
    real = guard.subprocess.run

    def spy(args, *a, **kw):
        calls.append(list(args))
        return real(args, *a, **kw)

    monkeypatch.setattr(guard.subprocess, "run", spy)
    result = guard.scan_range(repo, "HEAD~3..HEAD", guard.compile_patterns())
    assert result.commits == 3 and result.findings == []
    parent_lookups = [c for c in calls if "rev-parse" in c and "--verify" in c and any(x.endswith("^") for x in c)]
    assert len(parent_lookups) == 3, f"expected one parent lookup per commit, got {len(parent_lookups)}"


def test_added_lines_still_resolves_the_parent_itself_when_not_given(tmp_path: Path):
    repo = _init(tmp_path / "solo")
    (repo / "a.txt").write_text(_LEAK_LINE + "\n", encoding="utf-8")
    sha = _commit(repo, "root")
    parsed = guard.added_lines(repo, sha)          # root commit: parent is the empty tree
    assert any(_HOST in line for _, _, line in parsed.added)


# ------------------------------------------------------------ the SUITE gaps: negative direction


def test_the_selftest_FAILS_when_a_pattern_is_gutted(capsys):
    """`--selftest` had only ever been shown to pass. A selftest that can only say "ok" proves
    nothing; this proves it reds when a live pattern stops matching."""
    compiled = guard.compile_patterns()
    gutted = [(label, guard.re.compile(r"(?!)") if label == "private lan domain" else rx)
              for label, rx in compiled]
    assert guard.selftest(gutted) == 1
    out = capsys.readouterr().out
    assert "SELFTEST FAILED" in out and "SHOULD have been caught (private lan domain)" in out


def test_the_selftest_FAILS_when_a_corpus_loses_a_pattern_a_surface_runs(monkeypatch, capsys):
    """The completeness floor now covers the PATH and MESSAGE surfaces: a pattern those surfaces
    run with no deny case in their corpus is reported, which is exactly what let cgnat and
    tailnet run unproven on messages until this audit."""
    trimmed = [(label, s) for label, s in guard._MUST_FAIL_MESSAGES if label != "cgnat address"]
    monkeypatch.setattr(guard, "_MUST_FAIL_MESSAGES", trimmed)
    assert guard.selftest(guard.compile_patterns()) == 1
    out = capsys.readouterr().out
    assert "MESSAGE surface runs with no deny case there" in out and "cgnat address" in out, out
    monkeypatch.undo()
    trimmed_paths = [(label, s) for label, s in guard._MUST_FAIL_PATHS if label != "tailnet name"]
    monkeypatch.setattr(guard, "_MUST_FAIL_PATHS", trimmed_paths)
    assert guard.selftest(guard.compile_patterns()) == 1
    assert "PATH surface runs with no deny case there" in capsys.readouterr().out


def test_every_pattern_each_surface_runs_has_a_deny_case_in_that_surfaces_corpus():
    for corpus, running in ((guard._MUST_FAIL_PATHS, guard.path_patterns()),
                            (guard._MUST_FAIL_MESSAGES, guard.message_patterns())):
        assert {l for l, _ in running} <= {l for l, _ in corpus}
    assert guard.selftest(guard.compile_patterns()) == 0


@pytest.mark.timeout(300)
def test_a_shallow_clone_is_REFUSED_by_the_range_scan(tmp_path: Path):
    """The guard's own comment says the refusal 'has to exist rather than be asserted'; nothing
    asserted it. A depth-1 clone of a history that carries a leak two commits back would scan
    one commit and print clean; the refusal is what stops that."""
    origin = _init(tmp_path / "origin")
    (origin / "cfg.txt").write_text(_LEAK_LINE + "\n", encoding="utf-8")
    _commit(origin, "leak")
    (origin / "a.txt").write_text("a\n", encoding="utf-8")
    _commit(origin, "a")
    (origin / "b.txt").write_text("b\n", encoding="utf-8")
    _commit(origin, "b")
    shallow = tmp_path / "shallow"
    subprocess.run(["git", "clone", "-q", "--depth", "1", origin.as_uri(), str(shallow)],
                   env=_ENV, check=True, capture_output=True, timeout=120)
    assert guard.is_shallow(shallow)
    out = _guard(shallow, "--range", "HEAD")
    assert out.returncode == 1 and "REFUSING to scan a SHALLOW clone" in out.stdout, _clean(out)
    full = _guard(origin, "--range", "HEAD~3..HEAD")
    assert full.returncode == 1 and _HOST in full.stdout, "the control: the full history reds on the leak"


@pytest.mark.parametrize("argv", [
    ["origin/main..HEAD"],                 # a bare range with no flag
    ["--range", "--selftest"],             # a flag swallowed as a value
    ["--range=-x"],                        # a joined value that is itself a flag
    ["--selftest", "--staged"],            # two exclusive modes
    ["--range", "a..b", "--staged"],       # two exclusive modes, the other pair
    ["--frobnicate"],                      # an unknown flag
    ["--repo"],                            # a flag with no value
])
def test_the_strict_argument_parser_rejects_what_its_docstring_says_it_rejects(argv):
    with pytest.raises(guard.UsageError):
        guard.parse_args(argv)
    assert guard.main(argv) == 2


def test_the_argument_parser_accepts_the_documented_forms():
    assert guard.parse_args(["--selftest"]).selftest
    assert guard.parse_args(["--range", "a..b"]).rev_range == "a..b"
    assert guard.parse_args(["--range=a..b"]).rev_range == "a..b"
    assert guard.parse_args(["--staged"]).staged
    assert guard.parse_args(["--repo", "x", "--range", "a..b"]).repo == "x"
    assert guard.parse_args(["-h"]).help and guard.parse_args(["--help"]).help
