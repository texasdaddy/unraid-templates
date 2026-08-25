"""`sync-templates.py`: what it must write, what it must NOT write, and what it must SAY.

Two bugs in one week made this file necessary, and they are the same shape twice over —
`merge()` computed the right answer and `update_instance` threw part of it away because the
gate on the write asked the wrong question.

1. The gate was ``st["added"] or st["deleted"] or st["kept_flag"]``, so a template edit that
   changed only a field's Description, Default, Display or Required was discarded. Every
   operator-facing instruction in this repo lives in a `Description`, so the one edit the
   templates exist to deliver was the one edit that could not arrive.
2. Comparing content instead fixed that and broke the drift alarm: a variable the template
   no longer defines but which still holds a value is copied *verbatim* into `merged`, so the
   trees compare equal while `kept_flag` is non-empty. The `!! KEPT` line — which three
   separate documents promise is loud, and which is a migration checklist's only pointer to
   a mapping the operator must delete by hand — went silent on every run after the first.

So the assertions below cover the whole surface, not just the bug of the day: writes,
non-writes, the reported drift, the backup, and delete-as-necessary. Each one was checked by
mutating `sync-templates.py` and confirming it goes red.
"""

import importlib.util
import pathlib
import sys
import xml.etree.ElementTree as ET

import pytest

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "sync-templates.py"

HEAD = (
    '<Container version="2"><Name>widget</Name><Repository>example/widget:1</Repository>'
    '<TemplateURL>https://example.invalid/templates/widget.xml</TemplateURL>'
)
TOKEN = (
    '<Config Name="TOKEN" Target="TOKEN" Default="" Mode="" Description="{desc}" '
    'Type="Variable" Display="always" Required="true" Mask="true"{tail}'
)
# a mapping the template no longer defines, still holding a real value: the drift case
SOCKET = (
    '<Config Name="Docker socket" Target="/var/run/docker.sock" Default="" Mode="rw" '
    'Description="x" Type="Path" Display="always" Required="false" Mask="false">'
    '/var/run/docker.sock</Config>'
)


def template(desc="TEXT"):
    return ET.fromstring(HEAD + TOKEN.format(desc=desc, tail="/>") + "</Container>")


def instance_xml(desc="TEXT", extra=""):
    return HEAD + TOKEN.format(desc=desc, tail=">s3cret</Config>") + extra + "</Container>"


@pytest.fixture()
def sync():
    spec = importlib.util.spec_from_file_location("sync_templates", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    # Pin it. README tells operators to flip DRY_RUN to True for a rehearsal, and under that
    # value four of these tests fail and the no-spurious-write one passes VACUOUSLY, because
    # nothing writes at all. A test suite whose verdict depends on a module constant the docs
    # invite you to change is not a test suite.
    mod.DRY_RUN = False
    return mod


@pytest.fixture()
def inst(tmp_path):
    def _make(xml):
        p = tmp_path / "my-widget.xml"
        p.write_text(xml, encoding="utf-8")
        return p
    return _make


def config_of(path, target="TOKEN"):
    for c in ET.parse(path).getroot().findall("Config"):
        if c.get("Target") == target:
            return c
    return None


# --------------------------------------------------------------------------- bug 1: writes

def test_a_description_only_edit_reaches_the_instance(sync, inst, tmp_path):
    p = inst(instance_xml(desc="OLD TEXT"))
    sync.update_instance(str(p), template(desc="NEW TEXT the operator must act on"), str(tmp_path / "b"))
    assert config_of(p).get("Description") == "NEW TEXT the operator must act on"
    assert config_of(p).text == "s3cret", "the applied value must survive"


@pytest.mark.parametrize("attr,value", [("Display", "advanced"), ("Required", "false"), ("Default", "xyz")])
def test_every_other_metadata_attribute_reaches_the_instance_too(sync, inst, tmp_path, attr, value):
    """The broken gate saw none of the metadata, so pin the class and not just Description."""
    p = inst(instance_xml())
    tpl = template()
    tpl.find("Config").set(attr, value)
    sync.update_instance(str(p), tpl, str(tmp_path / "b"))
    assert config_of(p).get(attr) == value
    assert config_of(p).text == "s3cret"


def test_an_unchanged_template_does_not_rewrite_the_instance(sync, inst, tmp_path):
    """The other direction: an unconditional rewrite would churn a secret-bearing backup."""
    p = inst(instance_xml())
    before = p.read_bytes()
    backups = tmp_path / "b"
    sync.update_instance(str(p), template(), str(backups))
    assert p.read_bytes() == before
    assert not backups.exists() or not list(backups.iterdir())


def test_dry_run_writes_nothing_even_when_there_is_a_real_change(sync, inst, tmp_path):
    p = inst(instance_xml(desc="OLD TEXT"))
    before = p.read_bytes()
    sync.DRY_RUN = True
    sync.update_instance(str(p), template(desc="NEW TEXT"), str(tmp_path / "b"))
    assert p.read_bytes() == before


# ----------------------------------------------------------------- bug 2: the drift alarm

def test_drift_is_reported_even_when_there_is_nothing_to_write(sync, inst, tmp_path, capsys):
    """The regression: merged == operator, so the content gate returned before warning."""
    p = inst(instance_xml(extra=SOCKET))
    sync.update_instance(str(p), template(), str(tmp_path / "b"))
    out = capsys.readouterr().out
    assert "KEPT" in out, "a removed-but-valued Config must still be flagged"
    assert "Docker socket" in out, "the flag must name what drifted"
    assert "nothing to change" not in out, "it is not 'nothing to change' - there is drift"
    assert config_of(p, "/var/run/docker.sock") is not None, "drift is kept, never deleted"


def test_drift_is_reported_on_every_run_not_just_the_first(sync, inst, tmp_path, capsys):
    """After the first sync the trees match, which is precisely when the alarm went silent."""
    p = inst(instance_xml(extra=SOCKET))
    for run in range(3):
        capsys.readouterr()
        sync.update_instance(str(p), template(), str(tmp_path / "b"))
        assert "KEPT" in capsys.readouterr().out, f"drift went unreported on run {run + 1}"


# ------------------------------------------------------------- promises made in the README

def test_a_real_write_is_backed_up_first(sync, inst, tmp_path):
    """README: 'creates/updates/deletes with timestamped backups'. Nothing was pinning it."""
    p = inst(instance_xml(desc="OLD TEXT"))
    backups = tmp_path / "b"
    sync.update_instance(str(p), template(desc="NEW TEXT"), str(backups))
    saved = list(backups.iterdir())
    assert len(saved) == 1, "an overwritten instance must be backed up"
    assert "OLD TEXT" in saved[0].read_text(encoding="utf-8"), "the backup must hold the PRE-write file"


def test_delete_as_necessary_only_deletes_what_is_unused(sync, inst, tmp_path):
    """`if val == "" or val == default` -> `if True` destroys real operator values silently."""
    unused = (
        '<Config Name="Spare" Target="SPARE" Default="d" Mode="" Description="x" '
        'Type="Variable" Display="always" Required="false" Mask="false">d</Config>'
    )
    p = inst(instance_xml(extra=unused + SOCKET))
    sync.update_instance(str(p), template(), str(tmp_path / "b"))
    assert config_of(p, "SPARE") is None, "a value still at its default is unused: delete it"
    assert config_of(p, "/var/run/docker.sock") is not None, "a real value must never be dropped"


# ------------------------------------------------------- mutations that used to survive
# A verification round mutated the script and found these still green. Each one breaks a
# promise the README makes, so each gets the case that proves it bites.


def test_the_no_write_path_really_does_not_write_or_back_up(sync, inst, tmp_path):
    """Drift reporting must not smuggle in a write.

    The drift tests above assert on stdout only. With that alone, making the `unchanged`
    branch write and back up left the suite green — and the cost is a timestamped copy of a
    secret-bearing template churned on EVERY run of a drifted instance, which is exactly the
    accumulation unraid-templates#27 is about.
    """
    p = inst(instance_xml(extra=SOCKET))
    before = p.read_bytes()
    backups = tmp_path / "b"
    sync.update_instance(str(p), template(), str(backups))
    assert p.read_bytes() == before, "the no-write path wrote"
    assert not backups.exists() or not list(backups.iterdir()), "the no-write path took a backup"


def test_an_invalid_merge_result_is_refused_and_the_instance_is_left_alone(sync, inst, tmp_path):
    """README: 'a merged result is validated before it replaces the original.'

    Deleting the `validate(merged)` call left the whole suite green. The guard exists so a
    template that would produce a structurally broken instance cannot overwrite a working
    one — the failure mode being a container Unraid can no longer render or start.
    """
    # merge() bases the result on the OPERATOR's tree, so an invalid merge comes from a
    # damaged instance rather than a damaged template - a truncated my-*.xml, say, or a
    # half-written file from an interrupted Apply. validate() requires a non-empty
    # <Repository>; without the guard the script would happily rewrite that file.
    damaged = instance_xml(desc="OLD TEXT").replace(
        "<Repository>example/widget:1</Repository>", "<Repository></Repository>"
    )
    p = inst(damaged)
    before = p.read_bytes()

    sync.update_instance(str(p), template(desc="NEW TEXT"), str(tmp_path / "b"))

    assert p.read_bytes() == before, "an invalid merge result overwrote the instance"
    assert not (tmp_path / "b").exists() or not list((tmp_path / "b").iterdir()), (
        "a refused merge must not leave a backup either"
    )


def test_dry_run_reports_no_write_rather_than_would_update_when_there_is_nothing_to_write(
    sync, inst, tmp_path, capsys
):
    """Ordering: `if unchanged` must be tested before `elif DRY_RUN`.

    Swapping them made a dry run announce `would UPDATE` for an instance with nothing to
    write — a rehearsal that misreports what the real run will do is worse than no rehearsal.
    """
    p = inst(instance_xml(extra=SOCKET))
    sync.DRY_RUN = True
    sync.update_instance(str(p), template(), str(tmp_path / "b"))
    out = capsys.readouterr().out
    assert "would UPDATE" not in out, "a dry run claimed it would write when there is nothing to write"
    assert "KEPT" in out, "a dry run must still report drift"


def test_metadata_refreshed_is_only_claimed_when_that_is_what_happened(sync, inst, tmp_path, capsys):
    """The line says "no variables added or removed" - so it must not print when some were.

    It used to be computed from added/deleted/kept_flag alone, which left two ways to lie:
    a duplicate-keyed Config, which merge() DROPS (a variable removed), and the no-write
    path, where nothing was refreshed at all.
    """
    # (a) a real metadata-only write: the claim is true and must be made
    p = inst(instance_xml(desc="OLD TEXT"))
    sync.update_instance(str(p), template(desc="NEW TEXT"), str(tmp_path / "b"))
    assert "metadata refreshed" in capsys.readouterr().out

    # (b) nothing written at all: nothing was refreshed, so the claim must not be made
    p2 = inst(instance_xml(extra=SOCKET))
    capsys.readouterr()
    sync.update_instance(str(p2), template(), str(tmp_path / "b2"))
    out = capsys.readouterr().out
    assert "metadata refreshed" not in out, "claimed a refresh on a run that wrote nothing"

    # (c) a duplicate is dropped, which IS a variable removed
    dupe = instance_xml(desc="SAME").replace("</Container>", "") + (
        '<Config Name="TOKEN" Target="TOKEN" Default="" Mode="" Description="SAME" '
        'Type="Variable" Display="always" Required="true" Mask="true">other</Config></Container>'
    )
    p3 = inst(dupe)
    capsys.readouterr()
    sync.update_instance(str(p3), template(desc="SAME"), str(tmp_path / "b3"))
    out = capsys.readouterr().out
    # unconditional: guarding this on "duplicate keys" in out meant deleting the dupes
    # bookkeeping entirely left the whole suite green, with this assertion never running.
    assert "duplicate keys" in out, "a duplicate-keyed Config must be reported"
    assert "no variables added or removed" not in out, (
        "claimed no variables were removed while dropping a duplicate"
    )


# =============================================================================================
# unraid-templates#27 — backups were a byte-for-byte PLAINTEXT copy of every masked value.
#
# `Mask="true"` only tells the Unraid web form to render a password box; the XML on the flash
# drive stores the value in cleartext regardless. So `shutil.copy2` wrote one more cleartext copy
# of every API token and PAT on every write, and nothing ever pruned them. RED before / GREEN
# after: on the previous script `test_a_masked_value_is_REDACTED_in_the_backup` fails outright.
# =============================================================================================

# A masked field with NO value, and an ordinary unmasked one — the two negative directions.
EMPTY_SECRET = (
    '<Config Name="SPARE_KEY" Target="SPARE_KEY" Default="" Mode="" Description="x" '
    'Type="Variable" Display="always" Required="false" Mask="true"></Config>'
)
SECRET = "s3cret"       # the value `instance_xml()` puts in the Mask="true" TOKEN field


def _backups(d):
    return sorted(p for p in d.iterdir() if p.name.endswith(".bak"))


def test_a_masked_value_is_REDACTED_in_the_backup(sync, inst, tmp_path):
    """⭐ THE ISSUE. The backup must not be a cleartext copy of the operator's PAT."""
    p = inst(instance_xml(desc="OLD TEXT"))
    backups = tmp_path / "b"
    assert SECRET in p.read_text(encoding="utf-8"), "precondition: the instance holds a secret"

    sync.update_instance(str(p), template(desc="NEW TEXT"), str(backups))

    saved = _backups(backups)
    assert len(saved) == 1, "an overwritten instance must still be backed up"
    text = saved[0].read_text(encoding="utf-8")
    assert SECRET not in text, (
        "the backup still holds the masked value in PLAINTEXT — this is unraid-templates#27")
    assert sync.REDACTED in text, "the masked field should be marked as redacted, not dropped"


def test_the_LIVE_instance_keeps_its_secret(sync, inst, tmp_path):
    """⛔ THE REGRESSION REDACTION COULD EASILY SHIP: redacting the file being backed UP.

    `backup()` parses its own tree, so the live instance must be untouched. Redacting it would
    destroy the running container's credentials on the next sync — far worse than the leak.
    """
    p = inst(instance_xml(desc="OLD TEXT"))
    sync.update_instance(str(p), template(desc="NEW TEXT"), str(tmp_path / "b"))
    assert config_of(p).text == SECRET, (
        "the sync REDACTED the live instance — the operator's real value is gone")


def test_an_unmasked_value_is_preserved_in_the_backup(sync, inst, tmp_path):
    """The negative direction. "Nothing sensitive survives" is equally true of a backup that
    blanks EVERYTHING, and such a backup restores nothing."""
    # A real metadata change, so the write path (and therefore the backup) actually runs.
    p = inst(instance_xml(desc="OLD TEXT", extra=SOCKET))
    backups = tmp_path / "b"
    sync.update_instance(str(p), template(desc="NEW TEXT"), str(backups))
    saved = _backups(backups)
    assert saved, "precondition: a backup was taken"
    text = saved[0].read_text(encoding="utf-8")
    assert "/var/run/docker.sock" in text, "an unmasked value must survive into the backup"
    assert "OLD TEXT" in text, "the backup must still hold the PRE-write metadata"
    assert text.count(sync.REDACTED) == 1, "exactly the one masked field should be redacted"


def test_an_EMPTY_masked_field_is_not_marked_as_holding_a_secret(sync, inst, tmp_path):
    """Redacting an empty field would claim it held a value it never had, which misleads an
    operator reading a backup to see what was configured."""
    root = ET.fromstring(instance_xml(extra=EMPTY_SECRET))
    assert sync.redact_secrets(root) == 1, "only the ONE non-empty masked value is redacted"
    spare = [c for c in root.findall("Config") if c.get("Target") == "SPARE_KEY"][0]
    assert not (spare.text or "").strip(), "an empty masked field must stay empty"


def test_a_file_that_cannot_be_backed_up_safely_is_NOT_overwritten(sync, tmp_path, capsys):
    """⛔ NO BACKUP, NO WRITE — and no falling back to a plaintext copy.

    A fallback that did the unsafe thing whenever the safe one failed would reintroduce #27 on
    exactly the malformed files nobody inspects.
    """
    p = tmp_path / "my-widget.xml"
    p.write_text("<Container><Name>x</Name>", encoding="utf-8")  # truncated: unparseable
    backups = tmp_path / "b"
    with pytest.raises(sync.BackupUnsafe):
        sync.backup(str(p), str(backups))
    assert not backups.exists() or not _backups(backups), "an unsafe backup was written anyway"


def test_the_one_time_clear_out_redacts_backups_previous_versions_already_wrote(sync, tmp_path):
    """⭐ Fixing `backup()` stops NEW cleartext copies and does nothing about the pile already on
    the flash drive, which is where every secret this script has ever seen currently sits."""
    backups = tmp_path / "b"
    backups.mkdir()
    old = backups / "my-widget.xml.20260101-000000.bak"
    old.write_text(instance_xml(), encoding="utf-8")
    assert SECRET in old.read_text(encoding="utf-8"), "precondition: plaintext accumulation"

    files, values, unparseable = sync.redact_existing_backups(str(backups))

    assert (files, values, unparseable) == (1, 1, [])
    assert SECRET not in old.read_text(encoding="utf-8"), "the pre-existing plaintext survived"
    assert sync.REDACTED in old.read_text(encoding="utf-8")


def test_the_clear_out_is_idempotent(sync, tmp_path):
    """A second run must find nothing left to do — otherwise every run reports a clear-out it did
    not perform, and the operator cannot tell when the accumulation is actually gone."""
    backups = tmp_path / "b"
    backups.mkdir()
    (backups / "my-widget.xml.20260101-000000.bak").write_text(instance_xml(), encoding="utf-8")
    sync.redact_existing_backups(str(backups))
    assert sync.redact_existing_backups(str(backups)) == (0, 0, [])


def test_an_unparseable_backup_is_REPORTED_and_never_silently_deleted(sync, tmp_path):
    """It may well hold a secret, and only the operator can say whether it is worth keeping.
    Deleting the operator's data to make a report look clean is the wrong trade."""
    backups = tmp_path / "b"
    backups.mkdir()
    broken = backups / "my-widget.xml.20260101-000000.bak"
    broken.write_text("<Container><Name>x</Name>", encoding="utf-8")

    files, values, unparseable = sync.redact_existing_backups(str(backups))

    assert (files, values) == (0, 0)
    assert len(unparseable) == 1 and "my-widget.xml" in unparseable[0]
    assert broken.exists(), "an unparseable backup was deleted rather than reported"


def test_prune_keeps_the_newest_N_and_never_borrows_from_another_instance(sync, tmp_path):
    """Grouped PER INSTANCE: a container synced often must not evict the only backup another
    container has. The stamp format makes a lexicographic sort chronological."""
    backups = tmp_path / "b"
    backups.mkdir()
    for i in range(sync.KEEP_BACKUPS + 3):
        (backups / f"my-noisy.xml.202601{i + 1:02d}-000000.bak").write_text("<Container/>",
                                                                            encoding="utf-8")
    (backups / "my-quiet.xml.20260101-000000.bak").write_text("<Container/>", encoding="utf-8")

    dropped = sync.prune_backups(str(backups))

    assert len(dropped) == 3, f"expected the 3 oldest noisy backups to go, got {dropped}"
    assert all(d.startswith("my-noisy") for d in dropped), dropped
    kept = {p.name for p in _backups(backups)}
    assert "my-quiet.xml.20260101-000000.bak" in kept, "the quiet instance lost its only backup"
    assert len([k for k in kept if k.startswith("my-noisy")]) == sync.KEEP_BACKUPS
    # The OLDEST are the ones dropped, not an arbitrary three.
    assert "my-noisy.xml.20260101-000000.bak" in dropped
    assert "my-noisy.xml.20260113-000000.bak" in kept


def test_dry_run_neither_rewrites_nor_deletes_a_backup(sync, tmp_path):
    """The DRY_RUN contract is 'writes NOTHING'. It covers the backup dir too — and this is the
    run an operator uses to decide whether to trust the clear-out at all."""
    backups = tmp_path / "b"
    backups.mkdir()
    plain = backups / "my-widget.xml.20260101-000000.bak"
    plain.write_text(instance_xml(), encoding="utf-8")
    for i in range(sync.KEEP_BACKUPS + 2):
        (backups / f"my-noisy.xml.202601{i + 1:02d}-000000.bak").write_text("<Container/>",
                                                                            encoding="utf-8")
    before = {p.name: p.read_bytes() for p in _backups(backups)}

    sync.DRY_RUN = True
    try:
        files, values, _ = sync.redact_existing_backups(str(backups))
        dropped = sync.prune_backups(str(backups))
    finally:
        sync.DRY_RUN = False

    assert (files, values) == (1, 1), "dry-run must still REPORT what it would redact"
    assert len(dropped) == 2, "dry-run must still report what it would prune"
    assert {p.name: p.read_bytes() for p in _backups(backups)} == before, (
        "DRY_RUN wrote to or deleted from the backup directory")
