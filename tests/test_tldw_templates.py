"""The tl;dw template set: the properties that make it safe, asserted rather than read.

This set is two templates that must agree with each other, and its point is a security
posture that is invisible in the rendered UI — credential fields that ship blank, an image
reference that cannot move under you, a session-cookie flag whose value is a decision. Each
of those is one attribute in an XML file, and each is silently undone by an edit that looks
like tidying: giving a blank field a "helpful" default, changing a pinned tag to :latest so
updates arrive, copying a value out of upstream's compose file because that is what it says.

None of it is caught by the leak guard (these are not internal values) or by the XML job
(the file still parses). So it is caught here.

Two lessons from a verification round are built into how these assertions are written, and
both are worth keeping when this file is edited:

⚠️ ASSERT ON `Target`, NEVER ON `Name` ALONE. `Name` is the label Unraid draws beside the
field; `Target` is the string that becomes the environment variable. An earlier version of
this file keyed everything on `Name`, and a mutation that left every label and value intact
while re-pointing the server-side API key at the browser-visible variable passed the whole
suite. Every assertion below that means "this variable" checks `Target`.

⚠️ RULES BY SHAPE, NOT BY ROSTER. An earlier version checked a hardcoded list of four
credential fields, so a NEW credential field — including one shipping a real working secret
as its default — was unguarded entirely. The credential rules below are driven by the shape
of the variable name, so a field nobody thought to add to a list is still covered.

Assertions about placeholder credentials deliberately look at VALUES only — the `Default`
attribute and the element text — never at `Description` prose. The descriptions discuss the
placeholders by name in order to explain why they are refused, and an assertion that merely
searched the file for those strings would fire on the file's own documentation.

WHAT THIS FILE DOES NOT CLAIM, stated because a guard that implies coverage it lacks is
worse than one that names its edges:

  * The Overview disclosures are asserted as SUBSTRINGS. An Overview could contain every
    required phrase inside a sentence that negates it. Substring matching raises the floor —
    it makes silent deletion impossible — it does not make the prose true. Read the Overview.
  * The icon rule proves an icon CAN carry transparency, not that any pixel is transparent.
    A palette PNG whose tRNS entries are all opaque would pass. Proving otherwise means
    decompressing and unfiltering the pixel data, which is not worth it for an icon.
  * Nothing here runs a container. Everything below is a property of the XML and the PNG
    header; whether the image behaves as the descriptions say was established by reading
    upstream at the pinned commit, and is recorded in the templates' own comments.
"""

import pathlib
import re
import xml.etree.ElementTree as ET

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
TEMPLATES = REPO / "templates"
ICONS = REPO / "icons"

# The set, in the order it must be started.
TLDW = ("tldw-redis", "tldw-server")

# The exact ordering sentence each Overview must carry. Asserting that both container names
# merely APPEAR would pass an Overview that stated the order backwards, which is worse than
# saying nothing: Unraid has no depends_on, so this prose is the only thing an operator has.
ORDER_PHRASE = "tldw-redis first, then tldw-server"

# A variable whose name ends this way carries a credential. Driving the rule off the name
# shape rather than a list is what makes a newly-added secret field covered on the day it is
# added rather than on the day someone remembers to update a roster. The suffix list is
# deliberately wide: a confirming round walked eight real-world spellings past a narrower
# version of it (_APIKEY, _PASSWD, _KEYS, _CREDENTIALS, _PASSPHRASE, SECRET_KEY_BASE …),
# each shipping a working secret.
CREDENTIAL_SHAPE = re.compile(
    r"(?:_|^)(?:API_?KEYS?|KEYS?|KEY_BASE|SECRETS?|SALT|TOKEN|PASSWORD|PASSWD|PASS|"
    r"PASSPHRASE|CREDENTIALS?|BEARER|PW|PWD)$"
)

# The other half of a shape rule: names that LOOK credential-shaped and are not. Without an
# escape hatch the first person who needs SORT_KEY or SECOND_PASS deletes the rule instead
# of the exception, so the exception lives here, named, and is the cheaper thing to add.
# Keep it SMALL: every name added here is a hole, so a suffix that needs many exceptions
# (as the plural TOKENS and a bare AUTH both did) belongs out of the pattern instead.
NOT_A_CREDENTIAL = frozenset(
    {
        "SORT_KEY",
        "PARTITION_KEY",
        "SECOND_PASS",
    }
)

# Credential variables this set requires the operator to fill in. Everything matching
# CREDENTIAL_SHAPE must be blank and masked; these must additionally be marked required.
REQUIRED_SECRETS = {
    "tldw-server": {"SINGLE_USER_API_KEY", "MCP_JWT_SECRET", "MCP_API_KEY_SALT"},
    "tldw-redis": set(),
}

# Not credential-shaped, but can carry a password inside a URL — upstream's own example of a
# DATABASE_URL is a Postgres URL with the password in it.
MUST_ALSO_BE_MASKED = {("tldw-server", "DATABASE_URL")}

# Values upstream ships as placeholders. Checked against CREDENTIAL-SHAPED fields only:
# "default" and "secret" are perfectly ordinary values for an enum setting, and a rule that
# reddened `PROFILE=default` would be a guard that fails a correct tree.
PLACEHOLDER_CREDENTIALS = frozenset(
    {
        "change-me",
        "changeme",
        "change_me",
        "changed",
        "default",
        "test-key",
        "password",
        "secret",
    }
)

# An image reference is pinned when its tag CANNOT be re-pointed at different content:
# a full semver tag by convention, or a per-commit / digest reference by construction.
# Matching pin SHAPES rather than blacklisting tag NAMES is the point — a denylist of five
# names let `:0.1`, `:master` and `:nightly` through, all of which move. The channel-word
# check on the suffix is the second half of that lesson: `0.0.0-nightly` is semver-shaped
# and moves anyway.
PINNED_TAG = re.compile(r"^(?:\d+\.\d+\.\d+(?:[.\-+][\w.\-]*)?|sha-[0-9a-f]{7,40})$")
CHANNEL_WORDS = ("latest", "main", "master", "dev", "nightly", "edge", "rolling", "stable")

# The image each template must actually pull. A pinned tag proves the reference cannot move;
# it says nothing about WHICH image it names, so the repository half is pinned here too.
EXPECTED_IMAGE = {
    "tldw-server": "ghcr.io/rmusser01/tldw_server",
    "tldw-redis": "redis",
}

# The one reference that does NOT satisfy the pin rule, named here so its exception is a
# visible decision rather than a hole. `redis:7-alpine` is a rolling tag — Docker Hub
# re-points it on every Redis 7.x release — and it is what upstream's own compose file uses.
# What this test therefore guarantees: no reference to the tl;dw application image can move.
# What it does NOT guarantee: that the Redis container stays on one upstream version.
ROLLING_TAG_EXCEPTIONS = {("tldw-redis", "redis:7-alpine")}

# PostArgs is appended after the image name, so it is the container's command line: a shell
# command there can export anything over the values asserted in this file. tldw-redis is the
# one template that legitimately needs it — it is how that image is configured at all.
POSTARGS_MUST_BE_EMPTY = {"tldw-server"}

# The minimum each template must actually declare, so "no rule fired" cannot mean "there was
# nothing left to look at". Gutting tldw-redis to a single placeholder Config previously
# stayed green, because every rule that covers it is conditional and its required-secret set
# is legitimately empty.
MUST_DECLARE = {
    "tldw-server": {("Port", "8000"), ("Path", "/app/Databases")},
    "tldw-redis": {("Port", "6379"), ("Path", "/data")},
}

# Upstream's two compose service names, as they appear in a URL: `redis://redis:6379/0`,
# `http://app:8000`, and the port-less forms of both. The leading lookbehind is what keeps
# an absolute SQLite URL out of it — `sqlite:////app/Databases/users.db` contains "//app"
# and is a perfectly good value, so matching that substring reddened a correct tree.
COMPOSE_HOST = re.compile(r"(?<!/)//(?:app|redis)(?::\d+)?(?:/|$)")

_CACHE = {}


def load(name):
    path = TEMPLATES / (name + ".xml")
    assert path.is_file(), f"{path} is missing"
    return ET.parse(path).getroot()


def template(name):
    if name not in _CACHE:
        _CACHE[name] = load(name)
    return _CACHE[name]


def configs(root):
    # iter(), not findall(): findall sees direct children only, so a Config wrapped in any
    # element at all becomes invisible to every rule below. `scripts/sync-templates.py` made
    # exactly this correction, with the note that missing one IS the bug.
    return list(root.iter("Config"))


def var_name(cfg):
    """The environment variable a Config actually sets.

    `Target` when present, else `Name` — which is not a nicety: `sync-templates.py` keys a
    variable as `Target or Name`, and its own suite has a test named for that fallback arm.
    An earlier version of this file swung from Name-only to Target-only and thereby let a
    Config with no Target at all past every rule here. Stripped, because that script strips
    too, so a padded Target is the same variable in this repo's model.
    """
    return ((cfg.get("Target") or cfg.get("Name") or "")).strip()


def is_variable(cfg):
    # A missing or oddly-cased Type must not be a way out of the variable rules.
    return (cfg.get("Type") or "Variable").strip().lower() == "variable"


def by_target(root, target):
    """Every Config wired to this environment variable — by Target, not by label."""
    return [c for c in configs(root) if is_variable(c) and var_name(c) == target]


def one_by_target(root, target):
    found = by_target(root, target)
    assert len(found) == 1, f"expected exactly one Config with Target={target!r}, got {len(found)}"
    return found[0]


def value_of(cfg):
    """The two places a value can hide: the attribute and the element text."""
    return ((cfg.get("Default") or "").strip(), (cfg.text or "").strip())


def environment_pairs(root):
    """The <Environment> block Unraid writes beside <Config>, as (name, value) pairs.

    Unraid emits both halves for a configured container, and templates are commonly authored
    by exporting one — so a secret, or a contradicting override of a value asserted below,
    can arrive here while every <Config> still reads correctly.
    """
    pairs = []
    for var in root.iter("Variable"):
        name = (var.findtext("Name") or "").strip()
        value = (var.findtext("Value") or "").strip()
        if name:
            pairs.append((name, value))
    return pairs


@pytest.mark.parametrize("name", TLDW)
def test_the_templates_exist_and_name_themselves(name):
    # The vacuity guard for everything below: if a template were missing, or its root were
    # not a Container, or it had no Config elements, the per-field assertions would have
    # nothing to look at and several would pass by finding nothing wrong.
    root = template(name)
    assert root.tag == "Container"
    assert root.findtext("Name") == name
    assert configs(root), f"{name}: no Config elements at all"
    assert name in MUST_DECLARE and name in EXPECTED_IMAGE, (
        f"{name}: added to TLDW without an entry in MUST_DECLARE / EXPECTED_IMAGE, so "
        f"several rules below would have nothing to check for it"
    )
    declared = {((c.get("Type") or "").strip(), (c.get("Target") or "").strip()) for c in configs(root)}
    missing = MUST_DECLARE[name] - declared
    assert not missing, (
        f"{name}: no longer declares {sorted(missing)} — several rules below are conditional, "
        f"so a template stripped of its port and mount would pass them by having nothing to check"
    )


@pytest.mark.parametrize("name", TLDW)
def test_no_two_configs_share_a_name_or_a_target(name):
    # A second Config with the same Name shadows the first for any reader that looks up by
    # label, so a guarded field can read as correct while the container is handed a second,
    # contradictory value for the same variable.
    root = template(name)
    names = [(c.get("Name") or "").strip() for c in configs(root)]
    targets = [var_name(c) for c in configs(root) if is_variable(c)]
    assert len(names) == len(set(names)), f"{name}: duplicate Config Name: {names}"
    assert len(targets) == len(set(targets)), f"{name}: duplicate Variable Target: {targets}"


@pytest.mark.parametrize("name", TLDW)
def test_every_credential_shaped_variable_ships_blank_and_masked(name):
    root = template(name)
    found = set()
    for cfg in configs(root):
        target = var_name(cfg)
        if not is_variable(cfg) or target in NOT_A_CREDENTIAL:
            continue
        if not CREDENTIAL_SHAPE.search(target):
            continue
        found.add(target)
        default, text = value_of(cfg)
        assert default == "", f"{name}: {target} ships a default value"
        assert text == "", f"{name}: {target} ships a value as element text"
        assert cfg.get("Mask") == "true", f"{name}: {target} is not masked"
    # The rule above is only as good as its ability to see the fields it is meant to cover.
    missing = REQUIRED_SECRETS[name] - found
    assert not missing, f"{name}: credential-shape rule did not match {sorted(missing)}"
    # The same rule over the <Environment> block Unraid writes beside <Config>.
    for env_name, env_value in environment_pairs(root):
        if env_name in NOT_A_CREDENTIAL or not CREDENTIAL_SHAPE.search(env_name):
            continue
        assert not env_value, f"{name}: <Environment> ships a value for {env_name}"


@pytest.mark.parametrize("name", TLDW)
def test_the_secrets_the_operator_must_supply_are_marked_required(name):
    # Required is advisory in Unraid — it does not stop a blank container from starting —
    # but it is what renders the field as one the operator is expected to fill, and it is
    # the only signal the template can give on the page itself.
    for target in sorted(REQUIRED_SECRETS[name]):
        cfg = one_by_target(template(name), target)
        assert cfg.get("Required") == "true", f"{name}: {target} is not marked required"


@pytest.mark.parametrize("name,target", sorted(MUST_ALSO_BE_MASKED))
def test_url_variables_that_can_carry_a_password_are_masked(name, target):
    cfg = one_by_target(template(name), target)
    assert cfg.get("Mask") == "true", f"{name}: {target} can carry a password and is not masked"


@pytest.mark.parametrize("name", TLDW)
def test_no_template_ships_a_placeholder_credential_as_a_value(name):
    root = template(name)
    candidates = [
        (var_name(c), v)
        for c in configs(root)
        if is_variable(c) and CREDENTIAL_SHAPE.search(var_name(c))
        for v in value_of(c)
    ] + [(n, v) for n, v in environment_pairs(root) if CREDENTIAL_SHAPE.search(n)]
    for target, value in candidates:
        assert value.lower() not in PLACEHOLDER_CREDENTIALS, (
            f"{name}: {target} ships the placeholder {value!r} as a working value"
        )


@pytest.mark.parametrize("name", TLDW)
def test_every_image_reference_is_pinned(name):
    repository = (template(name).findtext("Repository") or "").strip()
    assert repository, f"{name}: no Repository"
    # A pinned tag says the reference cannot move; it does not say WHICH image it names.
    image = repository.split("@", 1)[0].rsplit(":", 1)[0]
    assert image == EXPECTED_IMAGE[name], (
        f"{name}: pulls {image!r}, expected {EXPECTED_IMAGE[name]!r}"
    )
    if (name, repository) in ROLLING_TAG_EXCEPTIONS:
        # Returned, not skipped: a skip prints no reason in this repo's CI invocation,
        # so the exception would be invisible to anyone reading the run.
        return
    if "@sha256:" in repository:
        return  # a digest reference is immutable by construction
    last = repository.rsplit("/", 1)[-1]
    assert ":" in last, f"{name}: {repository!r} has no tag at all, so it means :latest"
    tag = last.rsplit(":", 1)[-1]
    assert PINNED_TAG.match(tag), (
        f"{name}: {repository!r} uses {tag!r}, which is not a pinned shape — a pinned "
        f"reference is a full semver tag, a sha-<commit> tag, or an @sha256: digest"
    )
    # `0.0.0-nightly` is semver-shaped and moves anyway.
    for word in CHANNEL_WORDS:
        assert word not in tag.lower(), (
            f"{name}: {tag!r} carries the channel word {word!r}, so it moves"
        )


@pytest.mark.parametrize("name", TLDW)
def test_the_wiring_variables_ship_blank_so_the_operator_must_fill_them(name):
    # A default that cannot work is worse than no default: it looks configured. Upstream's
    # compose service names resolve only on a user-defined Docker network, which a template
    # cannot create, so anything of that shape must not be shipped as a value.
    root = template(name)
    pairs = [(var_name(c), v) for c in configs(root) if is_variable(c) for v in value_of(c)]
    pairs += environment_pairs(root)
    for target, value in pairs:
        assert not COMPOSE_HOST.search(value), (
            f"{name}: {target} ships {value!r}, a compose service name that "
            f"does not resolve on the bridge network"
        )
    if name == "tldw-server":
        default, text = value_of(one_by_target(template(name), "REDIS_URL"))
        assert default == "" and text == "", "REDIS_URL must ship blank"


def test_the_session_cookie_is_secure_with_no_operator_action():
    root = template("tldw-server")
    assert value_of(one_by_target(root, "SESSION_COOKIE_SECURE")) == ("1", "1")
    for env_name, env_value in environment_pairs(root):
        if env_name == "SESSION_COOKIE_SECURE":
            assert env_value == "1", "<Environment> contradicts the Config value"


def test_csrf_ships_off_because_the_secure_cookie_makes_it_unusable_over_plain_http():
    # Not an oversight and not a weakening: with SESSION_COOKIE_SECURE=1 and no HTTPS in
    # front, the double-submit cookie this protection relies on is discarded by the browser,
    # so every write it guards fails with a 403 that names CSRF rather than the real cause.
    # Off is also the application's own behaviour in single-user mode.
    root = template("tldw-server")
    assert value_of(one_by_target(root, "CSRF_ENABLED")) == ("0", "0")
    for env_name, env_value in environment_pairs(root):
        if env_name == "CSRF_ENABLED":
            assert env_value == "0", "<Environment> contradicts the Config value"


@pytest.mark.parametrize("name", TLDW)
def test_each_overview_states_the_startup_order_in_order(name):
    overview = template(name).findtext("Overview") or ""
    assert ORDER_PHRASE in overview, (
        f"{name}: its Overview does not state the start order as {ORDER_PHRASE!r} — "
        f"Unraid has no depends_on, so this sentence is the only place it exists"
    )


def test_the_api_overview_carries_the_disclosures_the_operator_needs_up_front():
    # Each of these is something that changes whether someone installs this at all, and the
    # Overview is the only text Unraid shows before the container is created.
    overview = template("tldw-server").findtext("Overview") or ""
    assert re.search(r"\b\d+\.\d+\.\d+ beta\b", overview), (
        "the API Overview no longer names the upstream version it warns about — assert "
        "the shape, not a literal, so an image bump is not a test edit"
    )
    for phrase in (
        "rough edges",      # upstream's own beta warning, quoted
        "yt-dlp",
        "ffmpeg",
        "faster_whisper",
        "egress",           # blocks media URLs pointing at private networks
        "CPU-bound",        # and therefore slow under load
        "GPU support is unverified",
    ):
        assert phrase in overview, f"the API Overview no longer mentions {phrase!r}"


@pytest.mark.parametrize("name", TLDW)
def test_no_gpu_passthrough_fields_were_added_speculatively(name):
    # Deliberately absent: whether ingest always runs Whisper is unverified, and a wrong
    # GPU field is a confusing thing to ship where a later added one is not.
    root = template(name)
    fields = [
        text
        for cfg in configs(root)
        for text in (cfg.get("Name"), cfg.get("Target"))
        if text
    ]
    fields.append(root.findtext("ExtraParams") or "")
    fields.append(root.findtext("PostArgs") or "")
    haystack = " ".join(fields).lower()
    for token in ("nvidia", "cuda", "--gpus", "gpu_uuid"):
        assert token not in haystack, f"{name}: a GPU passthrough field ({token}) was added"


@pytest.mark.parametrize("name", TLDW)
def test_the_privilege_posture_is_minimal(name):
    root = template(name)
    assert (root.findtext("Privileged") or "").strip() == "false", f"{name}: Privileged"
    assert not (root.findtext("ExtraParams") or "").strip(), (
        f"{name}: ExtraParams is non-empty — anything added there is invisible on the "
        f"Edit page's normal fields and bypasses every rule in this file"
    )
    if name in POSTARGS_MUST_BE_EMPTY:
        # Same property as ExtraParams: a shell command here can export whatever it
        # likes over the values asserted elsewhere in this file. tldw-redis is exempt
        # because PostArgs is how that image is given its command line at all.
        assert not (root.findtext("PostArgs") or "").strip(), (
            f"{name}: PostArgs is non-empty and can override any variable asserted here"
        )
    assert (root.findtext("Network") or "").strip() == "bridge", f"{name}: Network"
    for cfg in configs(root):
        kind = (cfg.get("Type") or "").strip().lower()
        assert kind != "device", f"{name}: passes a host device through ({cfg.get('Target')})"
        if kind not in ("path", ""):
            continue
        # BOTH sides: Target is the container path, Default is the HOST path, and it is
        # the host side that decides what the container can reach.
        host = (cfg.get("Default") or "").strip().rstrip("/").lower()
        both = f"{cfg.get('Target') or ''} {cfg.get('Default') or ''}".lower()
        assert "docker.sock" not in both, f"{name}: mounts the docker socket"
        # A blank host path is the intended shipping state — the operator fills it in on
        # import — so only a host path that IS set gets judged.
        if host:
            assert host != "/boot" and not host.startswith("/boot/"), (
                f"{name}: mounts the Unraid flash device ({cfg.get('Default')!r})"
            )
        assert (cfg.get("Default") or "").strip() != "/", f"{name}: mounts the host root"


@pytest.mark.parametrize("name", TLDW)
def test_the_template_url_and_icon_point_at_files_that_exist(name):
    root = template(name)
    template_url = root.findtext("TemplateURL") or ""
    icon_url = root.findtext("Icon") or ""
    assert template_url.endswith(f"/templates/{name}.xml"), (
        f"{name}: TemplateURL is {template_url!r}, which does not name this template — "
        f"sync-templates.py maps an installed container back to its template with it"
    )
    assert icon_url.endswith(f"/icons/{name}.png"), f"{name}: Icon is {icon_url!r}"
    assert (ICONS / f"{name}.png").is_file(), f"{name}: icons/{name}.png does not exist"


@pytest.mark.parametrize("name", TLDW)
def test_every_icon_is_256px_and_can_carry_transparency(name):
    # The repo README states the rule; nothing enforced it until now. The PNG header is read
    # directly rather than through Pillow, which CI does not install.
    #
    # STATED LIMIT: this asserts the image CAN carry transparency, not that any pixel is
    # actually transparent — that would mean decompressing and unfiltering the pixel data.
    # Colour type 3 (palette) is accepted when a tRNS chunk is present, because that is what
    # an ordinary optimiser produces from a transparent RGBA icon, and rejecting it would
    # red a correct tree.
    data = (ICONS / f"{name}.png").read_bytes()
    assert data[:8] == b"\x89PNG\r\n\x1a\n", f"{name}: not a PNG"
    assert data[12:16] == b"IHDR"
    width = int.from_bytes(data[16:20], "big")
    height = int.from_bytes(data[20:24], "big")
    colour_type = data[25]
    assert (width, height) == (256, 256), f"{name}: icon is {width}x{height}, not 256x256"
    if colour_type in (4, 6):
        return  # an alpha channel, the ordinary case
    assert colour_type in (0, 2, 3), f"{name}: unknown PNG colour type {colour_type}"
    # 0, 2 and 3 carry transparency only through a tRNS chunk. Locate it by walking the
    # chunk list rather than scanning the file, so a coincidental match inside compressed
    # pixel data cannot satisfy this.
    offset, kinds = 8, []
    while offset + 8 <= len(data):
        length = int.from_bytes(data[offset:offset + 4], "big")
        kinds.append(data[offset + 4:offset + 8])
        offset += 12 + length
    assert b"tRNS" in kinds, (
        f"{name}: PNG colour type {colour_type} with no tRNS chunk carries no transparency"
    )


@pytest.mark.parametrize("name", TLDW)
def test_the_readme_table_has_a_row_for_the_template_and_its_icon(name):
    # The README makes this a rule about itself ("Every template + icon in this repo must
    # have a row here") and records that it was broken once already. Assert a table ROW, not
    # a substring anywhere in the file — a passing mention in prose is not a row.
    rows = [
        line
        for line in (REPO / "README.md").read_text(encoding="utf-8").splitlines()
        if line.startswith("|") and f"templates/{name}.xml" in line
    ]
    assert rows, f"README has no table row for templates/{name}.xml"
    assert any(f"icons/{name}.png" in row for row in rows), (
        f"no README row for {name} names its icon"
    )
