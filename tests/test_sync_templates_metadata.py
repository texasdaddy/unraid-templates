"""sync-templates.py must propagate a DESCRIPTION-ONLY template edit.

This is the regression test for the bug the templates in this repo were silently built on
top of. `update_instance` used to decide whether to write by asking whether the variable SET
had changed:

    changed = st["added"] or st["deleted"] or st["kept_flag"]

`merge()` computed the new metadata correctly and `update_instance` then discarded it, so an
edit that only changed a field's Description, Default, Display or Required never reached the
instance. Every operator-facing instruction in this repo lives in a `Description`, so the one
edit the templates exist to deliver was the one edit that could not arrive.

The two directions both matter, so both are asserted here: a metadata edit MUST be written,
and an identical template MUST NOT be, because a script that rewrites unconditionally churns
a backup file (holding the applied secrets) on every run.
"""

import importlib.util
import pathlib
import sys
import xml.etree.ElementTree as ET

import pytest

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "sync-templates.py"


def load_sync():
    spec = importlib.util.spec_from_file_location("sync_templates", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    saved = sys.argv
    sys.argv = ["sync-templates.py"]          # the module reads argv at import
    try:
        spec.loader.exec_module(mod)
    finally:
        sys.argv = saved
    return mod


TEMPLATE = """<?xml version="1.0"?>
<Container version="2">
  <Name>widget</Name>
  <Repository>example/widget:1</Repository>
  <Network>bridge</Network>
  <TemplateURL>https://example.invalid/templates/widget.xml</TemplateURL>
  <Config Name="TOKEN" Target="TOKEN" Default="" Mode="" Description="{desc}" Type="Variable" Display="always" Required="true" Mask="true"/>
</Container>
"""

INSTANCE = """<?xml version="1.0"?>
<Container version="2">
  <Name>widget</Name>
  <Repository>example/widget:1</Repository>
  <Network>bridge</Network>
  <TemplateURL>https://example.invalid/templates/widget.xml</TemplateURL>
  <Config Name="TOKEN" Target="TOKEN" Default="" Mode="" Description="{desc}" Type="Variable" Display="always" Required="true" Mask="true">s3cret</Config>
</Container>
"""


def _description(path):
    return ET.parse(path).getroot().find("Config").get("Description")


def _value(path):
    return ET.parse(path).getroot().find("Config").text


@pytest.fixture()
def sync():
    return load_sync()


def test_a_description_only_edit_reaches_the_instance(sync, tmp_path):
    """The bug: this used to be silently discarded."""
    inst = tmp_path / "my-widget.xml"
    inst.write_text(INSTANCE.format(desc="OLD TEXT"), encoding="utf-8")
    tpl = ET.fromstring(TEMPLATE.format(desc="NEW TEXT the operator must act on"))

    sync.update_instance(str(inst), tpl, str(tmp_path / "backups"))

    assert _description(inst) == "NEW TEXT the operator must act on", (
        "a Description-only template edit did not reach the instance"
    )
    # the applied value is what must NOT be touched
    assert _value(inst) == "s3cret"


def test_an_unchanged_template_does_not_rewrite_the_instance(sync, tmp_path):
    """The other direction: no spurious write, so no needless secret-bearing backup."""
    inst = tmp_path / "my-widget.xml"
    inst.write_text(INSTANCE.format(desc="SAME TEXT"), encoding="utf-8")
    before = inst.read_bytes()
    tpl = ET.fromstring(TEMPLATE.format(desc="SAME TEXT"))
    backups = tmp_path / "backups"

    sync.update_instance(str(inst), tpl, str(backups))

    assert inst.read_bytes() == before, "an unchanged template rewrote the instance"
    assert not backups.exists() or not list(backups.iterdir()), (
        "an unchanged template took a backup, which copies the applied secret"
    )


@pytest.mark.parametrize("attr,value", [("Display", "advanced"), ("Required", "false"), ("Default", "xyz")])
def test_other_metadata_edits_also_reach_the_instance(sync, tmp_path, attr, value):
    """Description is the one that bit us; the gate covered all metadata, so prove the class."""
    inst = tmp_path / "my-widget.xml"
    inst.write_text(INSTANCE.format(desc="SAME TEXT"), encoding="utf-8")
    tpl = ET.fromstring(TEMPLATE.format(desc="SAME TEXT"))
    tpl.find("Config").set(attr, value)

    sync.update_instance(str(inst), tpl, str(tmp_path / "backups"))

    assert ET.parse(inst).getroot().find("Config").get(attr) == value
    assert _value(inst) == "s3cret"
