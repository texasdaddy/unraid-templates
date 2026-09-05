"""Every template in this repo, held to the properties a PUBLIC Unraid template must have.

These rules began life in `test_tldw_templates.py`, written for one two-container set, and
none of them was specific to it: a credential field that ships a working default, an image
reference that moves under an Update, a `Default=` attribute that disagrees with the element
text, an icon the README does not list — each is a defect in ANY template here, and each is
silently undone by an edit that looks like tidying. Issue #57 asked for them to be lifted so
they are enforced by CI over `templates/*.xml` rather than by review. The tl;dw file keeps
only what is genuinely about that set (its start order, its wiring, its cookie posture).

Nothing here is caught by the leak guard (these are not internal values) or by the XML job
(the file still parses either way), which is why it is caught here.

⚠️ ASSERT ON `Target`, NEVER ON `Name` ALONE. `Name` is the label Unraid draws beside the
field; `Target` is the string that becomes the environment variable. Keying on `Name` let a
mutation that re-pointed a server-side key at a browser-visible variable pass a whole suite.

⚠️ RULES BY SHAPE, NOT BY ROSTER. A hardcoded list of credential fields leaves the next one
unguarded on the day it is added. The credential rules are driven by the shape of the
variable name, with a small named exception set for the false positives.

⭐ A `<Config>` CARRIES ITS VALUE TWICE — the `Default="…"` attribute AND the element text.
An edit that updates one and not the other is half a change, and which half Unraid honours
is not something to discover in production. The agreement is asserted on every Config.

WHAT THIS FILE DOES NOT CLAIM, so that a guard implying coverage it lacks does not ship:
  * The icon rule proves an icon CAN carry transparency, not that any pixel is transparent.
  * Nothing here runs a container, reads an image or checks that an application actually
    READS a variable. Whether a field is inert is established against the application's
    source, by hand, when a template is written or audited.
  * The exceptions below (a privileged runner, a rolling database tag, a Redis command line)
    are DECISIONS recorded as data, each with the reason beside it. Adding to one of those
    sets is the cheap way to make this file pass; it is also how a decision gets made
    without being noticed, so every entry carries the why.
"""

import pathlib
import re
import xml.etree.ElementTree as ET

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
TEMPLATES = REPO / "templates"
ICONS = REPO / "icons"
README = REPO / "README.md"
RAW_PREFIX = "https://raw.githubusercontent.com/texasdaddy/unraid-templates/main/"

# Every template, discovered — a new file is covered the day it lands, with no roster to update.
NAMES = sorted(p.stem for p in TEMPLATES.glob("*.xml"))

# A variable whose name ends this way carries a credential. Wide on purpose: a confirming
# round walked eight real-world spellings past a narrower version (_APIKEY, _PASSWD, _KEYS,
# _CREDENTIALS, _PASSPHRASE, SECRET_KEY_BASE …), each shipping a working secret.
CREDENTIAL_SHAPE = re.compile(
    r"(?:_|^)(?:API_?KEYS?|AUTH_?KEYS?|KEYS?|KEY_BASE|SECRETS?|SALT|TOKEN|PAT|PASSWORD|PASSWD|"
    r"PASS|PASSPHRASE|CREDENTIALS?|BEARER|PRIVKEY|PW|PWD)$",
    re.IGNORECASE,   # `db_password` and `Smtp__Password` are the same secret as DB_PASSWORD
)

# Names that LOOK credential-shaped and are not. Keep it SMALL: every entry is a hole.
#   SEL_PASS — reauth-bot's CSS selector for the password FIELD on a login page; a selector,
#              not a secret, and the first false positive this rule met in a shipped template.
#   SORT_KEY, PARTITION_KEY, SECOND_PASS — no template carries these yet; they are the
#              ordinary non-secret spellings a wider version of this rule met, kept so the
#              first template that needs one adds a field rather than deleting the rule.
NOT_A_CREDENTIAL = frozenset({"SORT_KEY", "PARTITION_KEY", "SECOND_PASS", "SEL_PASS"})

# Values upstreams ship as placeholders. Checked against CREDENTIAL-SHAPED fields only —
# "default" and "secret" are ordinary values for an enum setting elsewhere.
PLACEHOLDER_CREDENTIALS = frozenset(
    {"change-me", "changeme", "change_me", "changed", "default", "test-key", "password", "secret"}
)

# Not credential-shaped, but carries a password INSIDE the value: a Postgres URL has the
# password in it. Masked wherever it appears, in any template.
URL_VARIABLES_THAT_CARRY_A_PASSWORD = frozenset({"DATABASE_URL"})

# An image reference is pinned when its tag CANNOT be re-pointed at different content: a
# full semver tag by convention, or a per-commit / digest reference by construction.
PINNED_TAG = re.compile(
    r"^(?:v?\d+\.\d+\.\d+(?:[.\-+][\w.\-]*)?|sha-[0-9a-f]{7,40}|[0-9a-f]{7,40})$")
# Matched as a whole dot/dash/plus-separated COMPONENT of the tag, never as a substring:
# `2.336.0-ubuntu-devel` and `1.2.3-mainline` are fixed variants, `0.0.0-nightly` is not.
CHANNEL_WORDS = ("latest", "main", "master", "dev", "nightly", "edge", "rolling", "stable",
                 "snapshot", "canary", "unstable", "testing", "preview")


def channel_word_in(tag):
    return next((w for w in CHANNEL_WORDS
                 if re.search(rf"(?:^|[.\-+]){w}(?:[.\-+]|$)", tag, re.IGNORECASE)), None)

# Images whose upstream numbers releases MAJOR.MINOR, so a two-component tag names exactly
# one release there (`postgres:16.14` is a release; `postgres:16` is the moving line). On a
# semver project the same two-component tag is a moving minor line, which is why this is an
# allowance per image basename and not a loosening of PINNED_TAG.
TWO_COMPONENT_RELEASE_IMAGES = frozenset({"postgres"})
TWO_COMPONENT_TAG = re.compile(r"^\d+\.\d+(?:[.\-+][\w.\-]*)?$")   # 16.14, 16.14-alpine

# The fleet's OWN images publish a moving release channel BY DESIGN — the deploy model is
# "the container pulls :stable (or :latest, for a repo with no version tags) and an Update
# takes the new release". So for an image under this prefix the template ships the channel
# tag, and a pinned tag there would be the defect: it would freeze a deployment on one
# release for ever. Third-party images get the opposite rule, because nobody here controls
# what a moving tag on Docker Hub will point at tomorrow.
FLEET_IMAGE_PREFIX = "ghcr.io/texasdaddy/"
FLEET_CHANNEL_TAGS = frozenset({"stable", "latest"})

# Third-party references that do NOT satisfy the pin rule, each a visible decision:
#   tldw-redis  redis:7-alpine              — upstream's own compose choice; the blast radius is
#                                             a cache and a queue, stated in the template.
#   tape-db     timescale/timescaledb:latest-pg16 — a ROLLING tag on a STATEFUL database, which
#                                             its own sibling keystone-db deliberately does not
#                                             do (postgres:16.14). Recorded here so it is a
#                                             decision on the record rather than a hole; whether
#                                             to pin it is logged for the PM (see the RETURN
#                                             that introduced this file).
ROLLING_TAG_EXCEPTIONS = frozenset(
    {("tldw-redis", "redis:7-alpine"), ("tape-db", "timescale/timescaledb:latest-pg16")}
)

# The one privileged container, and why: github-runner runs a Docker daemon INSIDE itself
# (Docker-in-Docker), which needs Privileged and is the whole design — the README and the
# template's own field descriptions carry the trust model. Nothing else here may be.
PRIVILEGED_BY_DESIGN = frozenset({"github-runner"})

# PostArgs is appended after the image name: it is the container's COMMAND LINE, and a shell
# command there can export anything over the values asserted in this file. tldw-redis is
# the one template that legitimately needs it — that is how the redis image is configured.
POSTARGS_BY_DESIGN = frozenset({"tldw-redis"})

# The attribute set every Config must carry. `sync-templates.py` keys on Type/Target/Name and
# refreshes the rest from the repo copy; Unraid renders all nine. A Config missing one is
# rendered or merged differently from its neighbours, silently.
CONFIG_ATTRIBUTES = ("Name", "Target", "Default", "Mode", "Description", "Type", "Display",
                     "Required", "Mask")
CONFIG_TYPES = frozenset({"Variable", "Path", "Port", "Device", "Label"})
DISPLAY_VALUES = frozenset({"always", "advanced", "always-hide", "advanced-hide"})
ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
WEBUI_PORT = re.compile(r"\[PORT:(\d+)\]")

_CACHE = {}


def template(name):
    if name not in _CACHE:
        path = TEMPLATES / (name + ".xml")
        assert path.is_file(), f"{path} is missing"
        _CACHE[name] = ET.parse(path).getroot()
    return _CACHE[name]


def configs(root):
    # iter(), not findall(): findall sees direct children only, so a Config wrapped in any
    # element at all would become invisible to every rule below.
    return list(root.iter("Config"))


def var_name(cfg):
    """The environment variable a Config actually sets: `Target`, else `Name` — the same
    fallback `sync-templates.py` uses, so a Config with no Target is the same variable here
    that it is there. Stripped, because that script strips too."""
    return ((cfg.get("Target") or cfg.get("Name") or "")).strip()


def is_variable(cfg):
    # A missing or oddly-cased Type must not be a way out of the variable rules.
    return (cfg.get("Type") or "Variable").strip().lower() == "variable"


def value_of(cfg):
    """The two places a value lives: the attribute and the element text — VERBATIM.

    Not stripped: Unraid's importer (`xmlToVar` in dynamix.docker.manager) hands the container
    exactly the bytes between the tags, with no trim, so `>info </Config>` beside
    `Default="info"` ships `LOG_LEVEL="info "` — the half-change the agreement rule exists for,
    and one a stripping comparison waved through.
    """
    return ((cfg.get("Default") or ""), (cfg.text or ""))


def is_label(cfg):
    return (cfg.get("Type") or "").strip().lower() == "label"


def secret_bearing(cfg):
    """Configs whose VALUE reaches the container or the public: variables and labels."""
    return is_variable(cfg) or is_label(cfg)


def is_credential_name(name):
    return name.upper() not in NOT_A_CREDENTIAL and bool(CREDENTIAL_SHAPE.search(name))


# The v1 template blocks Unraid's importer still reads beside <Config> — `<Data><Volume>` for
# mounts and `<Networking>` for the mode/ports. `sync-templates.py` reconciles <Config> only,
# so a mount declared this way is invisible to every rule here AND to the sync tool; a docker
# socket smuggled in a <Volume> block imported fine and passed the whole file. Forbidden
# outright: this repo declares everything as <Config>.
LEGACY_BLOCKS = ("Data", "Networking")


def environment_pairs(root):
    """The <Environment><Variable> block Unraid writes beside <Config>, as (name, value).
    Templates are commonly authored by exporting a configured container, so a secret can
    arrive through this block while every <Config> still reads correctly."""
    pairs = []
    for var in root.iter("Variable"):
        name = (var.findtext("Name") or "").strip()
        value = (var.findtext("Value") or "").strip()
        if name:
            pairs.append((name, value))
    return pairs


def icon_basename(root):
    icon = (root.findtext("Icon") or "").strip()
    return icon.rsplit("/", 1)[-1]


def test_there_are_templates_to_check():
    # The vacuity guard for every parametrised test below: a glob that finds nothing would
    # make the whole file pass by having nothing to look at.
    assert len(NAMES) >= 2, f"templates/ holds {NAMES!r}"


def test_every_template_is_at_the_top_level_where_the_rules_and_the_sync_tool_look():
    # NAMES is a non-recursive glob because that is what sync-templates.py lists; an XML file
    # in a subdirectory would be fetchable by URL and checked by nothing.
    everything = {p.relative_to(TEMPLATES).as_posix() for p in TEMPLATES.rglob("*") if p.is_file()}
    covered = {f"{n}.xml" for n in NAMES}
    assert everything == covered, (
        f"templates/ holds files the rules do not cover: {sorted(everything - covered)}"
    )


@pytest.mark.parametrize("name", NAMES)
def test_no_legacy_v1_block_declares_anything_beside_the_configs(name):
    root = template(name)
    for tag in LEGACY_BLOCKS:
        assert root.find(tag) is None, (
            f"{name}: carries a <{tag}> block — Unraid imports it, sync-templates.py ignores it, "
            f"and no rule here sees it; declare it as <Config> instead"
        )


@pytest.mark.parametrize("name", NAMES)
def test_the_template_names_itself_and_declares_something(name):
    root = template(name)
    assert root.tag == "Container", f"{name}: root is <{root.tag}>, not <Container>"
    assert (root.findtext("Name") or "").strip() == name, (
        f"{name}: <Name> is {root.findtext('Name')!r} — sync-templates.py seeds my-<Name>.xml "
        f"from it, so it must match the file"
    )
    assert configs(root), f"{name}: no Config elements at all"
    for tag in ("Repository", "Overview", "Description", "Category"):
        assert (root.findtext(tag) or "").strip(), f"{name}: <{tag}> is empty"


@pytest.mark.parametrize("name", NAMES)
def test_every_config_carries_the_full_attribute_set_with_known_values(name):
    for cfg in configs(template(name)):
        label = cfg.get("Name") or cfg.get("Target") or "<unnamed>"
        missing = [a for a in CONFIG_ATTRIBUTES if cfg.get(a) is None]
        assert not missing, f"{name}: Config {label!r} lacks {missing}"
        kind = cfg.get("Type").strip()
        assert kind in CONFIG_TYPES, f"{name}: Config {label!r} has Type={kind!r}"
        assert cfg.get("Display").strip() in DISPLAY_VALUES, (
            f"{name}: Config {label!r} has Display={cfg.get('Display')!r}"
        )
        for flag in ("Required", "Mask"):
            assert cfg.get(flag).strip() in ("true", "false"), (
                f"{name}: Config {label!r} has {flag}={cfg.get(flag)!r}, not true/false"
            )
        if kind == "Port":
            assert cfg.get("Mode").strip() in ("tcp", "udp"), f"{name}: port {label!r} Mode"
            assert cfg.get("Target").strip().isdigit(), f"{name}: port {label!r} Target"
        if kind == "Path":
            assert cfg.get("Mode").strip().startswith(("rw", "ro")), f"{name}: path {label!r} Mode"
            assert cfg.get("Target").strip().startswith("/"), f"{name}: path {label!r} Target"
        if kind == "Variable":
            assert ENV_NAME.match(var_name(cfg)), (
                f"{name}: variable {label!r} sets {var_name(cfg)!r}, not a valid env name"
            )


@pytest.mark.parametrize("name", NAMES)
def test_the_default_attribute_and_the_element_text_agree(name):
    # The value lives twice. A change that updates one is half a change, and which half
    # Unraid honours is not something to discover in production.
    for cfg in configs(template(name)):
        default, text = value_of(cfg)
        assert default == text, (
            f"{name}: Config {cfg.get('Name')!r} has Default={default!r} but element text "
            f"{text!r} — update BOTH"
        )


@pytest.mark.parametrize("name", NAMES)
def test_no_two_configs_share_a_name_or_a_variable_target(name):
    # A second Config with the same Name shadows the first for any reader that looks up by
    # label; a second with the same Target hands the container two values for one variable,
    # and which one wins is an ordering accident.
    root = template(name)
    names = [(c.get("Name") or "").strip() for c in configs(root)]
    targets = [var_name(c) for c in configs(root) if is_variable(c)]
    assert len(names) == len(set(names)), f"{name}: duplicate Config Name in {names}"
    assert len(targets) == len(set(targets)), f"{name}: duplicate variable Target in {targets}"


@pytest.mark.parametrize("name", NAMES)
def test_every_credential_shaped_variable_ships_blank_and_masked(name):
    # Secrets are blank by design — the README says so — and masked so the Edit page renders
    # a password box. Neither is enforced by anything but this.
    root = template(name)
    for cfg in configs(root):
        target = var_name(cfg)
        if not secret_bearing(cfg) or not is_credential_name(target):
            continue
        default, text = value_of(cfg)
        assert default == "", f"{name}: {target} ships a default value"
        assert text == "", f"{name}: {target} ships a value as element text"
        assert cfg.get("Mask") == "true", f"{name}: {target} is not masked"
    for env_name, env_value in environment_pairs(root):
        if is_credential_name(env_name):
            assert not env_value, f"{name}: <Environment> ships a value for {env_name}"


def test_the_classifiers_themselves_bite_on_synthetic_values():
    # Every rule above is asserted only in the CLEAN direction against the shipped templates,
    # so a classifier gutted to never match — PINNED_TAG widened to `.*`, an emptied
    # PLACEHOLDER_CREDENTIALS — would leave this whole file green while guarding nothing.
    # This is the negative direction: synthetic bad values each classifier MUST catch, and
    # good ones it must not, so gutting one fails here on the same run.
    for bad in ("latest", "0.1", "master", "7-alpine", "16", "stable", "nightly", "v1", "g"):
        assert not PINNED_TAG.match(bad), f"PINNED_TAG accepts {bad!r}"
    for good in ("1.2.3", "v1.23.16", "0.1.38", "2.336.0-ubuntu-noble", "sha-abc1234",
                 "a1b2c3d", "1.0.0+build.7"):
        assert PINNED_TAG.match(good), f"PINNED_TAG rejects {good!r}"
    for moving in ("0.0.0-nightly", "2.336.0-SNAPSHOT", "1.2.3-canary", "3.0.0-dev.1"):
        assert channel_word_in(moving), f"channel word missed in {moving!r}"
    for fixed in ("2.337.0-ubuntu-devel", "1.2.3-mainline", "1.2.3-rc.1", "0.1.38"):
        assert not channel_word_in(fixed), f"channel word false-fires on {fixed!r}"
    assert TWO_COMPONENT_TAG.match("16.14") and TWO_COMPONENT_TAG.match("16.14-alpine")
    assert not TWO_COMPONENT_TAG.match("16")
    assert {"change-me", "changeme", "password"} <= PLACEHOLDER_CREDENTIALS
    for spelling in ("DB_PASSWORD", "db_password", "Smtp__Password", "X_API_KEY", "X_APIKEY",
                     "X_KEYS", "X_SECRET", "X_SALT", "X_TOKEN", "X_PASSWD", "X_PASS",
                     "X_PASSPHRASE", "X_CREDENTIALS", "SECRET_KEY_BASE", "X_PW", "X_PWD",
                     "PASSWORD", "TS_AUTHKEY", "GITHUB_PAT", "SSH_PRIVKEY"):
        assert is_credential_name(spelling), f"CREDENTIAL_SHAPE misses {spelling}"
    for benign in ("LOG_LEVEL", "DB_HOST", "TOKEN_URL", "TOKEN_STORE_PATH", "LLM_MAX_TOKENS",
                   "ENABLE_AUTH", "B2_KEY_ID", "REAUTH_MAX_CONSENT_AGE_HOURS", "SEL_PASS",
                   "sort_key"):
        assert not is_credential_name(benign), f"CREDENTIAL_SHAPE fires on {benign}"
    assert "DATABASE_URL" in URL_VARIABLES_THAT_CARRY_A_PASSWORD
    assert WEBUI_PORT.findall("http://[IP]:[PORT:8000]/v1/health") == ["8000"]
    assert not ENV_NAME.match("bad-name") and ENV_NAME.match("GOOD_NAME_1")


def test_the_credential_shape_rule_actually_matches_the_fleets_secret_fields():
    # The rule above is only as good as its ability to see the fields it is meant to cover:
    # a pattern edit that stopped matching `_PASSWORD` would leave every DB password
    # unguarded while the test above kept passing by finding nothing. Every template that
    # carries a secret must contribute at least one match, and the known spellings must hit.
    seen = set()
    for name in NAMES:
        for cfg in configs(template(name)):
            if secret_bearing(cfg) and is_credential_name(var_name(cfg)):
                seen.add(var_name(cfg))
    for spelling in ("DB_PASSWORD", "POSTGRES_PASSWORD", "TAPE_CLIENT_SECRET", "ACCESS_TOKEN",
                     "SCHWAB_PASS", "FRED_API_KEY", "TAPE_API_KEYS", "MCP_API_KEY_SALT"):
        assert spelling in seen, f"the credential-shape rule no longer matches {spelling}"


@pytest.mark.parametrize("name", NAMES)
def test_no_template_ships_a_placeholder_credential_as_a_value(name):
    root = template(name)
    candidates = [
        (var_name(c), v)
        for c in configs(root)
        if secret_bearing(c) and is_credential_name(var_name(c))
        for v in value_of(c)
    ] + [(n, v) for n, v in environment_pairs(root) if is_credential_name(n)]
    for target, value in candidates:
        assert value.lower() not in PLACEHOLDER_CREDENTIALS, (
            f"{name}: {target} ships the placeholder {value!r} as a working value"
        )


@pytest.mark.parametrize("name", NAMES)
def test_url_variables_that_can_carry_a_password_are_masked(name):
    for cfg in configs(template(name)):
        if is_variable(cfg) and var_name(cfg) in URL_VARIABLES_THAT_CARRY_A_PASSWORD:
            assert cfg.get("Mask") == "true", (
                f"{name}: {var_name(cfg)} can carry a password inside the URL and is not masked"
            )


@pytest.mark.parametrize("name", NAMES)
def test_the_image_reference_is_pinned_or_a_declared_fleet_channel(name):
    repository = (template(name).findtext("Repository") or "").strip()
    assert repository, f"{name}: no Repository"
    if repository.startswith(FLEET_IMAGE_PREFIX):
        # The fleet's own release channel, by design — see FLEET_CHANNEL_TAGS. Checked FIRST,
        # before the digest arm: a fleet image frozen on a digest is exactly the defect.
        assert "@sha256:" not in repository, (
            f"{name}: {repository!r} — a fleet image pinned by digest never takes a release"
        )
        last = repository.rsplit("/", 1)[-1]
        tag = last.rsplit(":", 1)[-1] if ":" in last else ""
        assert tag in FLEET_CHANNEL_TAGS, (
            f"{name}: {repository!r} — a fleet image ships one of {sorted(FLEET_CHANNEL_TAGS)}, "
            f"not {tag!r}; a pinned tag here would freeze the deployment on one release"
        )
        return
    if "@sha256:" in repository:
        return  # a digest reference cannot be re-pointed
    last = repository.rsplit("/", 1)[-1]
    assert ":" in last, f"{name}: {repository!r} has no tag at all, so it means :latest"
    tag = last.rsplit(":", 1)[-1]
    if (name, repository) in ROLLING_TAG_EXCEPTIONS:
        return  # returned, not skipped: a skip prints no reason in this repo's CI invocation
    image = repository.rsplit(":", 1)[0].rsplit("/", 1)[-1]
    pinned = PINNED_TAG.match(tag) or (
        image in TWO_COMPONENT_RELEASE_IMAGES and TWO_COMPONENT_TAG.match(tag))
    assert pinned, (
        f"{name}: {repository!r} uses {tag!r}, which is not a pinned shape — a third-party "
        f"reference is a (v-prefixed) semver tag, a sha-<commit> or bare-sha tag, or an "
        f"@sha256: digest, or it is listed in ROLLING_TAG_EXCEPTIONS with the reason"
    )
    word = channel_word_in(tag)
    assert word is None, f"{name}: {tag!r} carries the channel word {word!r}, so it moves"


def test_the_rolling_tag_exceptions_are_all_live():
    # An exception that no longer matches a template is a stale decision, and the next
    # person to hit the rule will add a second entry rather than notice this one.
    live = {(n, (template(n).findtext("Repository") or "").strip()) for n in NAMES}
    stale = ROLLING_TAG_EXCEPTIONS - live
    assert not stale, f"ROLLING_TAG_EXCEPTIONS names references no template carries: {stale}"
    assert PRIVILEGED_BY_DESIGN <= set(NAMES), f"PRIVILEGED_BY_DESIGN names a missing template"
    assert POSTARGS_BY_DESIGN <= set(NAMES), f"POSTARGS_BY_DESIGN names a missing template"


@pytest.mark.parametrize("name", NAMES)
def test_the_privilege_posture_is_minimal(name):
    root = template(name)
    privileged = (root.findtext("Privileged") or "").strip()
    if name in PRIVILEGED_BY_DESIGN:
        assert privileged == "true", f"{name}: listed as privileged by design but is not"
    else:
        assert privileged == "false", f"{name}: Privileged={privileged!r}"
    assert not (root.findtext("ExtraParams") or "").strip(), (
        f"{name}: ExtraParams is non-empty — anything there is invisible on the Edit page's "
        f"normal fields and bypasses every rule in this file"
    )
    if name not in POSTARGS_BY_DESIGN:
        assert not (root.findtext("PostArgs") or "").strip(), (
            f"{name}: PostArgs is non-empty and can override any variable asserted here"
        )
    assert (root.findtext("Network") or "").strip() == "bridge", (
        f"{name}: Network is {root.findtext('Network')!r} — the neutral default is bridge; "
        f"an operator picks br0 and an address in the UI"
    )
    for cfg in configs(root):
        kind = (cfg.get("Type") or "").strip().lower()
        label = cfg.get("Name")
        assert kind != "device", f"{name}: passes a host device through ({cfg.get('Target')})"
        if kind != "path":
            continue
        both = f"{cfg.get('Target') or ''} {cfg.get('Default') or ''}".lower()
        assert "docker.sock" not in both, f"{name}: {label!r} mounts the docker socket"
        # The HOST side decides what the container can reach, and a host path is
        # operator-specific by definition: it ships BLANK and is filled in on import. (The
        # leak guard refuses the real share roots; this refuses any value at all.)
        default, text = value_of(cfg)
        assert default == "" and text == "", (
            f"{name}: {label!r} ships a host path {default!r} — host paths are set at creation"
        )


@pytest.mark.parametrize("name", NAMES)
def test_the_template_url_names_this_file_and_the_icon_exists(name):
    root = template(name)
    template_url = (root.findtext("TemplateURL") or "").strip()
    icon_url = (root.findtext("Icon") or "").strip()
    assert template_url == f"{RAW_PREFIX}templates/{name}.xml", (
        f"{name}: TemplateURL is {template_url!r} — sync-templates.py maps an installed "
        f"container back to its template with it, and Unraid fetches it from main"
    )
    assert icon_url.startswith(f"{RAW_PREFIX}icons/") and icon_url.endswith(".png"), (
        f"{name}: Icon is {icon_url!r}"
    )
    assert (ICONS / icon_basename(root)).is_file(), f"{name}: icons/{icon_basename(root)} missing"


@pytest.mark.parametrize("name", NAMES)
def test_the_icon_is_256px_and_can_carry_transparency(name):
    # The README states the rule. The PNG header is read directly rather than through
    # Pillow, which CI does not install. STATED LIMIT: this proves the image CAN carry
    # transparency, not that any pixel is transparent. Palette PNGs (colour type 3) pass
    # with a tRNS chunk, because that is what an optimiser produces from a transparent icon.
    data = (ICONS / icon_basename(template(name))).read_bytes()
    assert data[:8] == b"\x89PNG\r\n\x1a\n", f"{name}: icon is not a PNG"
    assert data[12:16] == b"IHDR"
    width = int.from_bytes(data[16:20], "big")
    height = int.from_bytes(data[20:24], "big")
    colour_type = data[25]
    assert (width, height) == (256, 256), f"{name}: icon is {width}x{height}, not 256x256"
    if colour_type in (4, 6):
        return  # an alpha channel, the ordinary case
    assert colour_type in (0, 2, 3), f"{name}: unknown PNG colour type {colour_type}"
    offset, kinds = 8, []
    while offset + 8 <= len(data):
        length = int.from_bytes(data[offset:offset + 4], "big")
        kinds.append(data[offset + 4:offset + 8])
        offset += 12 + length
    assert b"tRNS" in kinds, f"{name}: colour type {colour_type} with no tRNS chunk"


def _readme_rows():
    """The rows of the README's icon/template TABLE — the one whose header is
    `| Container | Icon | Template |` — and nothing else. A pipe-shaped line inside a comment
    or a fenced block is not a row; an indented table still is."""
    lines = README.read_text(encoding="utf-8").splitlines()
    rows, in_table = [], False
    for raw in lines:
        line = raw.strip()
        if not in_table:
            if line.startswith("|") and "Container" in line and "Template" in line:
                in_table = True
            continue
        if not line.startswith("|"):
            break
        if set(line) <= set("|-: "):
            continue  # the separator row
        rows.append(line)
    assert rows, "the README's `| Container | Icon | Template |` table was not found"
    return rows


@pytest.mark.parametrize("name", NAMES)
def test_the_readme_table_has_a_row_naming_the_template_and_its_icon(name):
    # The README makes this a rule about itself and records that it was broken once. A table
    # ROW, not a substring anywhere in the file — a passing mention in prose is not a row.
    rows = [r for r in _readme_rows() if f"templates/{name}.xml" in r]
    assert rows, f"README has no table row for templates/{name}.xml"
    icon = icon_basename(template(name))
    assert any(f"icons/{icon}" in r for r in rows), f"no README row for {name} names icons/{icon}"


def test_every_icon_file_is_named_by_a_template_and_listed_in_the_readme():
    # The inverse: an icon nothing references is an orphan the README rule also forbids.
    named = {icon_basename(template(n)) for n in NAMES}
    rows = "\n".join(_readme_rows())
    for icon in sorted(p.name for p in ICONS.iterdir() if p.is_file()):
        assert icon in named, f"icons/{icon} is referenced by no template"
        assert f"icons/{icon}" in rows, f"icons/{icon} has no README row"


@pytest.mark.parametrize("name", NAMES)
def test_a_webui_that_names_a_port_names_one_this_template_declares(name):
    # `[PORT:8000]` is substituted with the HOST port mapped for CONTAINER port 8000. Naming a
    # port no Config declares renders a WebUI link that opens nothing.
    root = template(name)
    webui = (root.findtext("WebUI") or "").strip()
    if not webui:
        return
    declared = {(c.get("Target") or "").strip() for c in configs(root)
                if (c.get("Type") or "").strip().lower() == "port"}
    ports = WEBUI_PORT.findall(webui)
    assert ports, f"{name}: WebUI {webui!r} names no [PORT:n]"
    for port in ports:
        assert port in declared, f"{name}: WebUI names port {port}, which no Config declares"
