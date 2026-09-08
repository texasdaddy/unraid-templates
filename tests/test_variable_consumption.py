"""Guard for UT-N: a template must not carry a Variable the consuming app never reads.

test_template_invariants.py says plainly what it does NOT do: "Nothing here runs a
container, reads an image or checks that an application actually READS a variable. Whether
a field is inert is established against the application's source, by hand, when a template
is written or audited." UT-N did exactly that by hand, once, for every template with a
consumer under `C:\\dev`. This file is what stops the finding from rotting the moment this
package returns.

WHY THIS CANNOT BE A LIVE GREP AGAINST THE CONSUMING REPO, IN THIS REPO'S CI: this repo is
PUBLIC and its CI runs on GitHub-hosted runners only (a public repo never uses the fleet's
self-hosted runners — see _worker-common "A PUBLIC REPO NEVER USES THE SELF-HOSTED RUNNER
FLEET"). Every consuming app (keystone, tape, cef-tracker, reauth-bot, the-desk) is a
SEPARATE, PRIVATE repo — its source is not, and must not be, available to a public repo's
CI job. So the live "does the app actually read this" check cannot run here; it can only
run by hand, by whoever edits a template's Variables, against a checkout of the consumer.

What CAN run here, and does: `tests/consumption.json` is the durable RECORD of that
hand audit — one citation per declared Variable, naming the file:line in the consumer repo
that actually uses it. This file enforces that the record is COMPLETE and never stale:
  * every `Type="Variable"` Config in every template has a citation (a Variable added
    without one fails CI immediately, instead of accreting silently);
  * no citation survives for a Variable a template no longer declares (a stale record is
    exactly the "changelog of dead settings" this package exists to stop, moved one file
    over instead of eliminated);
  * a template flagged `no_local_consumer` carries no per-var citations to go stale, and is
    itself checked against the actual absence of a same-named repo under `C:\\dev` at audit
    time was recorded correctly by a human — this file cannot re-verify that part.
This is a structural gate, not a semantic one: it cannot itself prove a citation is true.
That proof is the one-time job the accompanying RETURN records; ⚠️ re-run the grep behind a
citation before trusting it if the cited consumer file has moved on since.
"""

import json
import pathlib
import xml.etree.ElementTree as ET

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
TEMPLATES = REPO / "templates"
MANIFEST_PATH = REPO / "tests" / "consumption.json"

NAMES = sorted(p.stem for p in TEMPLATES.glob("*.xml"))


def _manifest():
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def _template_vars(name):
    root = ET.parse(TEMPLATES / f"{name}.xml").getroot()
    return {
        (c.get("Target") or c.get("Name") or "").strip()
        for c in root.iter("Config")
        if (c.get("Type") or "Variable").strip().lower() == "variable"
    }


def test_manifest_exists_and_parses():
    assert MANIFEST_PATH.is_file(), f"{MANIFEST_PATH} is missing"
    manifest = _manifest()
    assert isinstance(manifest, dict) and manifest, "consumption.json is empty"


def test_every_template_has_a_manifest_entry():
    manifest = _manifest()
    entries = {k for k in manifest if not k.startswith("_")}
    missing = set(NAMES) - entries
    assert not missing, (
        f"templates/ has templates with no consumption.json entry: {sorted(missing)} — "
        f"a new template ships with either a per-var audit or no_local_consumer recorded"
    )
    stale = entries - set(NAMES)
    assert not stale, f"consumption.json names templates that no longer exist: {sorted(stale)}"


@pytest.mark.parametrize("name", NAMES)
def test_declared_variables_match_the_audited_variables_exactly(name):
    manifest = _manifest()[name]
    if manifest.get("no_local_consumer"):
        assert not manifest.get("vars"), (
            f"{name}: flagged no_local_consumer but still carries per-variable citations — "
            f"either the consumer showed up under C:\\dev (audit it and clear the flag) or "
            f"these citations are stale (delete them)"
        )
        return
    declared = _template_vars(name)
    audited = set(manifest.get("vars") or {})
    missing = declared - audited
    assert not missing, (
        f"{name}: template declares Variable(s) with no consumption.json citation: "
        f"{sorted(missing)} — grep the consuming repo and either cite where it's read, or "
        f"delete the Config block if nothing reads it (per UT-N: a Variable earns its place "
        f"only if the consuming app actually reads it)"
    )
    stale = audited - declared
    assert not stale, (
        f"{name}: consumption.json cites Variable(s) the template no longer declares: "
        f"{sorted(stale)} — remove the stale citation"
    )


@pytest.mark.parametrize("name", NAMES)
def test_every_citation_is_non_trivial(name):
    # A one-word or blank citation ("yes", "-") records nothing a reviewer can re-check —
    # the whole point of the citation is that it names a file/line to go re-grep.
    manifest = _manifest()[name]
    for var, citation in (manifest.get("vars") or {}).items():
        assert isinstance(citation, str) and len(citation.strip()) >= 8, (
            f"{name}: {var}'s citation {citation!r} is too thin to mean anything — "
            f"name the file (and ideally line) that reads it"
        )
