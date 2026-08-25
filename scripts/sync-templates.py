#!/usr/bin/env python3
"""
sync-templates — reconcile Unraid dockerMan container templates against the
published `unraid-templates` repo WITHOUT losing your applied values.

SINGLE SCRIPT, ONE BUTTON. No parameters, no wrapper. Running it does
create / update / delete-as-necessary across every managed container template.

  CREATE  — seed my-<name>.xml for any repo template that has no my- file yet,
            so it is ready to pick in Add Container.
  UPDATE  — for EVERY live instance of a template (my-tape.xml AND my-tape-dev.xml,
            my-tape-db-dev.xml, ...): keep each instance's applied values, refresh
            each variable's metadata from the template, and ADD new template vars.
  DELETE  — drop a variable the template removed ONLY when it is genuinely unused
            (blank or still at its default). A removed variable that still holds a
            real, non-default value is KEPT and loudly flagged — that almost always
            means the TEMPLATE is missing it (drift), not that you wanted it gone.
  Container-level settings you set per instance — image tag, network/IP, WebUI,
  Extra Params, ports, the container Name — are ALWAYS preserved. Only <Config>
  elements are reconciled.

------------------------------------------------------------------------------
DRY-RUN vs LIVE  —  the ONLY switch is the DRY_RUN constant below.
  * DRY_RUN = True   prints exactly what it WOULD create/update/delete, writes
                     nothing. This is the version you validate.
  * DRY_RUN = False  performs the changes (each overwritten file is backed up
                     first, timestamped, under templates-user/.template-sync-backups/;
                     writes are atomic; a result is validated before it replaces
                     the original).

BACKUPS AND SECRETS  (unraid-templates#27)
  `Mask="true"` is a UI setting only -- it makes the Unraid web form render a
  password box. The XML on the flash drive holds the value in PLAINTEXT either
  way. So a backup is written with every masked value REDACTED, and the first
  run also redacts the backups previous versions already wrote. Backups are
  pruned to the newest KEEP_BACKUPS per instance.

  What that means for a restore: the structure and every non-secret value come
  back in full; a masked value must be re-entered. It is not a real loss --
  merge() copies applied values across verbatim, so a merge cannot damage a
  secret, and the backup is there for a bad merge.
  Workflow: run the dry-run version -> review -> when it is correct, install the
  version with DRY_RUN = False. Never a parameter, never a second script.
------------------------------------------------------------------------------

INSTANCE -> TEMPLATE MAPPING
  Primary: the instance's <TemplateURL> basename (my-tape-dev.xml -> tape.xml).
  Fallback: longest dash-prefix of the filename (my-tape-db-dev.xml -> tape-db,
  never tape; my-tapeworm.xml -> nothing). Foreign containers are never touched.

REQUIRES  python3 >= 3.9 (stdlib only). Run on the Unraid host via User Scripts.
"""

# =============================================================================
DRY_RUN = False    # LIVE — creates/updates/deletes with timestamped backups. (dev phase used True)
# =============================================================================

import copy
import json
import os
import sys
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime

# ----------------------------------------------------------------------------- config
REPO            = "texasdaddy/unraid-templates"
BRANCH          = "main"
TEMPLATE_SUBDIR = "templates"
TEMPLATES_USER  = "/boot/config/plugins/dockerMan/templates-user"
BACKUP_SUBDIR   = ".template-sync-backups"
UA              = "sync-templates (unraid)"
TIMEOUT         = 30

# ----------------------------------------------------------------------------- secrets
# ⭐ WHAT REPLACES A MASKED VALUE IN A BACKUP (unraid-templates#27).
#
# `Mask="true"` is a UI affordance ONLY — it tells the Unraid web form to render the field as a
# password box. The XML on the flash drive stores the value in PLAINTEXT regardless. So the old
# `shutil.copy2` backup wrote a byte-for-byte cleartext copy of every API token, PAT and password
# in the instance, and did it on EVERY write, and never pruned. A flash drive that anyone with
# physical access can read then accumulated one more cleartext copy of each secret per run.
#
# The backup exists to recover from a bad merge, and the value of a secret is not what it
# recovers: `merge()` copies every applied value across VERBATIM (`new_c.text = op_by_key[k].text`)
# and keeps a template-removed variable verbatim too, so a merge cannot corrupt a secret in the
# first place. What a restore actually needs is the STRUCTURE and the non-secret values, and those
# are preserved in full. A masked value is re-entered from wherever it came from.
REDACTED = "***REDACTED***"

# How many backups to keep per instance file. The old code kept every backup forever, which is
# half of what #27 is about: even redacted, an unbounded pile of timestamped XML on a flash drive
# is just accumulation. The newest are the ones with any recovery value.
KEEP_BACKUPS = 10


# ----------------------------------------------------------------------------- http
def _get(url):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        return r.read()


def list_repo_templates():
    """Enumerate <name> for every .xml under templates/ (via the GitHub API)."""
    url = f"https://api.github.com/repos/{REPO}/contents/{TEMPLATE_SUBDIR}?ref={BRANCH}"
    data = json.loads(_get(url).decode("utf-8"))
    return sorted(
        e["name"][:-4] for e in data
        if e.get("type") == "file" and e.get("name", "").endswith(".xml")
    )


def fetch_template(name):
    url = f"https://raw.githubusercontent.com/{REPO}/{BRANCH}/{TEMPLATE_SUBDIR}/{name}.xml"
    return _get(url)


# ----------------------------------------------------------------------------- xml helpers
def config_key(el):
    """Stable identity of a <Config>: (Type, Target) — fall back to Name if no Target."""
    typ = (el.get("Type") or "").strip()
    tgt = (el.get("Target") or "").strip()
    if not tgt:
        tgt = "name:" + (el.get("Name") or "").strip()
    return (typ, tgt)


def validate(root):
    def nonempty(tag):
        e = root.find(tag)
        return e is not None and (e.text or "").strip() != ""
    if root.tag != "Container":
        return f"root element is <{root.tag}>, expected <Container>"
    if not nonempty("Name"):
        return "missing/empty <Name>"
    if not nonempty("Repository"):
        return "missing/empty <Repository>"
    return None


def map_instance(path, fname, repo_names, naming_fallback):
    """Return the repo template name a my-*.xml instance derives from, or None."""
    try:
        tu = (ET.parse(path).getroot().findtext("TemplateURL") or "").strip()
    except Exception:
        tu = ""
    base = os.path.basename(tu)
    if base.endswith(".xml") and base[:-4] in repo_names:
        return base[:-4]                                   # primary: TemplateURL
    if naming_fallback:
        stem = fname[3:-4]                                 # strip 'my-' and '.xml'
        cands = [n for n in repo_names if stem == n or stem.startswith(n + "-")]
        if cands:
            return max(cands, key=len)                     # longest dash-prefix wins
    return None


def discover_instances(directory, repo_names, naming_fallback):
    """Map every my-*.xml in the dir to its template. Returns (by_template, unmapped)."""
    by_template, unmapped = {}, []
    for fname in sorted(os.listdir(directory)):
        if not (fname.startswith("my-") and fname.endswith(".xml")):
            continue
        path = os.path.join(directory, fname)
        t = map_instance(path, fname, repo_names, naming_fallback)
        if t:
            by_template.setdefault(t, set()).add(path)
        else:
            unmapped.append(fname)
    return by_template, unmapped


def merge(operator_root, template_root):
    """Return (merged_root, stats). Base = operator tree; reconcile <Config> only.
    Delete-as-necessary: a removed var is dropped only if unused (blank/default);
    a removed var with a real value is kept + flagged (template drift)."""
    op_by_key, dup_keys = {}, []
    for c in operator_root.findall("Config"):
        k = config_key(c)
        if k in op_by_key:
            dup_keys.append(k)
        else:
            op_by_key[k] = c

    merged = copy.deepcopy(operator_root)
    for c in merged.findall("Config"):          # strip Configs; container tags stay
        merged.remove(c)

    stats = {"added": [], "retained": 0, "deleted": [], "kept_flag": [], "dupes": dup_keys}
    seen = set()

    for tc in template_root.findall("Config"):  # template order; refresh metadata
        k = config_key(tc)
        seen.add(k)
        new_c = copy.deepcopy(tc)               # template metadata + default value
        if k in op_by_key:
            new_c.text = op_by_key[k].text      # keep the applied value verbatim
            stats["retained"] += 1
        else:
            stats["added"].append(tc.get("Name") or k[1])
        merged.append(new_c)

    for k, c in op_by_key.items():              # vars the template no longer defines
        if k in seen:
            continue
        val = (c.text or "").strip()
        default = (c.get("Default") or "").strip()
        label = c.get("Name") or k[1]
        if val == "" or val == default:
            stats["deleted"].append(label)      # unused -> delete as necessary
        else:
            merged.append(copy.deepcopy(c))     # real value -> keep + flag drift
            stats["kept_flag"].append(label)

    return merged, stats


def canonical(root):
    """Serialise a template tree the way atomic_write would, for content comparison."""
    r = copy.deepcopy(root)
    ET.indent(r, space="  ")
    return ET.tostring(r, encoding="utf-8")


def atomic_write(path, root):
    ET.indent(root, space="  ")
    tmp = path + ".tmp"
    ET.ElementTree(root).write(tmp, encoding="utf-8", xml_declaration=False)
    os.replace(tmp, path)


class BackupUnsafe(Exception):
    """The instance could not be backed up in REDACTED form, so it is not backed up at all.

    Raised rather than falling back to a plaintext copy. A fallback that quietly did the unsafe
    thing when the safe one failed would reintroduce #27 on exactly the malformed files nobody
    looks at, and "it only leaks sometimes" is not a fix.
    """


def redact_secrets(root):
    """Blank every `Mask="true"` value on `root`, IN PLACE. Returns how many were redacted.

    Only a NON-EMPTY value is replaced: marking an empty field would claim it held a secret when
    it did not, and an operator reading a backup to see what was set would be misled.

    `findall("Config")` is direct children only — the same view `merge()` reconciles, so the two
    cannot disagree about which elements exist.
    """
    n = 0
    for c in root.findall("Config"):
        if (c.get("Mask") or "").strip().lower() == "true" and (c.text or "").strip():
            c.text = REDACTED
            n += 1
    return n


def backup(path, backup_dir):
    """Copy `path` aside before it is overwritten, with every masked value REDACTED.

    Returns (dest, n_redacted). Raises BackupUnsafe if the file cannot be parsed — see the class.

    ⚠️ RE-SERIALISED, NOT COPIED. The backup is written through the same indent+serialise path as
    the live file, so it is not byte-identical to the original: it loses any XML declaration and
    is re-indented. That costs nothing to a restore — it is exactly the form `atomic_write` gives
    the live file anyway — and it is what makes redaction possible at all.
    """
    try:
        tree = ET.parse(path)
    except ET.ParseError as e:
        raise BackupUnsafe(f"{os.path.basename(path)}: {e}") from e
    n = redact_secrets(tree.getroot())
    os.makedirs(backup_dir, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    dest = os.path.join(backup_dir, f"{os.path.basename(path)}.{stamp}.bak")
    atomic_write(dest, tree.getroot())
    return dest, n


# ----------------------------------------------------------------------------- backup hygiene
def _backup_files(backup_dir):
    """Every `<instance>.<stamp>.bak` in the backup dir, oldest first."""
    if not os.path.isdir(backup_dir):
        return []
    return sorted(f for f in os.listdir(backup_dir) if f.endswith(".bak"))


def redact_existing_backups(backup_dir):
    """ONE-TIME CLEAR-OUT of the plaintext accumulation already on the flash drive.

    Fixing `backup()` stops NEW cleartext copies; it does nothing about the pile already written,
    which is where every secret this script has ever seen is currently sitting. Each existing
    `.bak` is rewritten in redacted form, ATOMICALLY (tmp + `os.replace`) so an interrupted run
    cannot truncate one.

    Rewritten rather than deleted: a backup is the operator's data and the recoverable part of it
    — the structure and every non-secret value — is exactly what deleting would throw away.

    Returns (n_redacted_files, n_values, unparseable). An unparseable `.bak` is REPORTED, never
    silently deleted and never assumed safe: it may well hold a secret, and only the operator can
    say whether it is worth keeping.

    Idempotent — a second run finds nothing left to redact, because a redacted value no longer
    differs from the marker.
    """
    redacted_files, redacted_values, unparseable = 0, 0, []
    for fname in _backup_files(backup_dir):
        full = os.path.join(backup_dir, fname)
        try:
            tree = ET.parse(full)
        except ET.ParseError as e:
            unparseable.append(f"{fname} ({e})")
            continue
        root = tree.getroot()
        n = sum(1 for c in root.findall("Config")
                if (c.get("Mask") or "").strip().lower() == "true"
                and (c.text or "").strip() not in ("", REDACTED))
        if not n:
            continue
        redacted_files += 1
        redacted_values += n
        if not DRY_RUN:
            redact_secrets(root)
            atomic_write(full, root)
    return redacted_files, redacted_values, unparseable


def prune_backups(backup_dir):
    """Keep the newest KEEP_BACKUPS per instance file; drop the rest. Returns what was dropped.

    Grouped per instance rather than over the directory as a whole, so a container synced often
    cannot evict the only backup another container has. The stamp is `%Y%m%d-%H%M%S`, so a plain
    lexicographic sort IS chronological.
    """
    groups = {}
    for fname in _backup_files(backup_dir):
        # `my-tape.xml.20260824-221030.bak` -> `my-tape.xml`
        groups.setdefault(fname.rsplit(".", 2)[0], []).append(fname)
    dropped = []
    for _, files in sorted(groups.items()):
        for fname in sorted(files)[:-KEEP_BACKUPS] if len(files) > KEEP_BACKUPS else []:
            dropped.append(fname)
            if not DRY_RUN:
                os.remove(os.path.join(backup_dir, fname))
    return dropped


# ----------------------------------------------------------------------------- per-instance
def update_instance(inst_path, tpl_root, backup_dir):
    fname = os.path.basename(inst_path)
    try:
        op_root = ET.parse(inst_path).getroot()
    except ET.ParseError as e:
        print(f"    ! {fname:<22} SKIP — XML parse error: {e}")
        return
    merged, st = merge(op_root, tpl_root)
    err = validate(merged)
    if err:
        print(f"    ! {fname:<22} SKIP — merged result invalid ({err}); left untouched")
        return
    # Compare the SEMANTIC result, not the variable set. Gating on added/deleted/kept meant a
    # template edit that changed only a field's Description, Default, Display or Required was
    # computed correctly by merge() and then thrown away — and a Description is where every
    # operator-facing instruction in this repo lives, so the one edit the templates are
    # written to deliver was the one edit that never arrived. Both sides go through the same
    # indent+serialise path so this compares content, not the file's original formatting.
    # kept_flag is the ONE stat this comparison cannot see. A variable the template no longer
    # defines but which still holds a real value is copied VERBATIM into merged (see merge()),
    # so merged can equal the operator's tree while drift is sitting right there. Returning on
    # content alone therefore silenced the loudest warning this script has - and silenced it on
    # every run after the first, which is exactly when an operator re-runs to check their work.
    # Drift is reported whether or not there is anything to write. dupes rides along in the
    # condition for safety, though for an operator-side duplicate it is redundant: merge()
    # keeps only the first of a duplicate-keyed Config, which changes the merged tree, so
    # `unchanged` is already False.
    unchanged = canonical(merged) == canonical(op_root)
    if unchanged and not (st["kept_flag"] or st["dupes"]):
        print(f"    = {fname:<22} up to date  ({st['retained']} values, nothing to change)")
        return
    # "metadata refreshed ... no variables added or removed" must be true of the run that
    # prints it. dupes belongs in here because merge() DROPS all but the first duplicate,
    # which IS a variable removed. `unchanged` needs no term of its own: when unchanged is
    # true the early return above only falls through if kept_flag or dupes is set, and either
    # of those already zeroes this.
    meta_only = not (st["added"] or st["deleted"] or st["kept_flag"] or st["dupes"])
    if unchanged:
        # nothing to write, but there IS something to say - fall through to the warnings
        print(f"    = {fname:<22} no write needed, but see below")
    elif DRY_RUN:
        print(f"    * {fname:<22} would UPDATE")
    else:
        # ⛔ NO BACKUP, NO WRITE. If the pre-write copy cannot be made SAFELY, the instance is
        # left exactly as it was: the alternative is either overwriting with no way back, or
        # falling back to the plaintext copy that #27 exists to remove.
        try:
            b, masked = backup(inst_path, backup_dir)
        except BackupUnsafe as e:
            print(f"    ! {fname:<22} SKIP — could not back it up safely ({e}); left untouched")
            return
        atomic_write(inst_path, merged)
        note = f", {masked} masked value(s) REDACTED" if masked else ""
        print(f"    * {fname:<22} UPDATED   (backup: {os.path.basename(b)}{note})")
    print(f"        values kept   : {st['retained']}")
    if meta_only:
        print("        metadata refreshed (descriptions/defaults/visibility); no variables added or removed")
    if st["added"]:
        print(f"        added         : {', '.join(st['added'])}")
    if st["deleted"]:
        print(f"        deleted (unused): {', '.join(st['deleted'])}")
    if st["kept_flag"]:
        print(f"        !! KEPT (removed from template but still holds a value — FIX THE "
              f"TEMPLATE, it is probably missing these): {', '.join(st['kept_flag'])}")
    if st["dupes"]:
        print(f"        ! duplicate keys (first kept): {st['dupes']}")


def process_template(name, instances_by_tpl, backup_dir):
    print(f"[{name}]")
    try:
        tpl_root = ET.fromstring(fetch_template(name))
    except Exception as e:
        print(f"    ! could not fetch/parse repo template: {e}")
        return
    err = validate(tpl_root)
    if err:
        print(f"    ! repo template invalid ({err}); skipping")
        return

    base_path = os.path.join(TEMPLATES_USER, f"my-{name}.xml")

    if not os.path.exists(base_path):           # CREATE the base stub if absent
        if DRY_RUN:
            print(f"    + my-{name}.xml         would CREATE  (does not exist yet)")
        else:
            atomic_write(base_path, copy.deepcopy(tpl_root))
            print(f"    + my-{name}.xml         CREATED  (ready for Add Container)")

    targets = set(instances_by_tpl.get(name, set()))   # UPDATE every live instance
    if os.path.exists(base_path):
        targets.add(base_path)
    for inst_path in sorted(targets):
        update_instance(inst_path, tpl_root, backup_dir)
    if not targets:
        print("    (no live instances yet)")


# ----------------------------------------------------------------------------- main
def main():
    if not os.path.isdir(TEMPLATES_USER):
        sys.exit(f"error: templates dir not found: {TEMPLATES_USER}")

    # Report the REASON. This is step 0 of the runner conversion, and an unauthenticated
    # api.github.com is rate-limited to 60 requests/hour per IP — "network/API" alone sends
    # the operator looking at their firewall instead of at a 403 that clears by itself.
    try:
        all_repo = list_repo_templates()
        why = ""
    except Exception as e:
        all_repo, why = [], f" ({e})"
    if not all_repo:
        sys.exit(f"error: could not list repo templates from {REPO}@{BRANCH}"
                 f"{why or ' (empty listing)'}. Nothing changed.")

    banner = "DRY-RUN — writes NOTHING (validate me, then install the DRY_RUN=False version)" \
        if DRY_RUN else "LIVE — will create/update/delete with backups"
    print(f"sync-templates  repo={REPO}@{BRANCH}  dir={TEMPLATES_USER}")
    print(f"mode: {banner}\ntemplates: {', '.join(all_repo)}\n")

    instances_by_tpl, unmapped = discover_instances(TEMPLATES_USER, all_repo, naming_fallback=True)
    backup_dir = os.path.join(TEMPLATES_USER, BACKUP_SUBDIR)

    # BEFORE anything else touches the backup dir. Every `.bak` written before this release is a
    # cleartext copy of whatever secrets that instance held, and this is the run that clears
    # them; doing it first means a crash later still leaves the flash drive better than it was.
    files, values, unparseable = redact_existing_backups(backup_dir)
    if files:
        print(f"{'would redact' if DRY_RUN else 'REDACTED'} {values} masked value(s) across "
              f"{files} pre-existing backup(s) in {BACKUP_SUBDIR}/ (unraid-templates#27: "
              f"`Mask` is a UI setting, so these were stored in PLAINTEXT)")
    if unparseable:
        print(f"! {len(unparseable)} backup(s) could not be parsed, so could NOT be redacted - "
              f"they may still hold secrets in plaintext. Review and delete them by hand:")
        for u in unparseable:
            print("    " + u)
    dropped = prune_backups(backup_dir)
    if dropped:
        print(f"{'would prune' if DRY_RUN else 'pruned'} {len(dropped)} backup(s) beyond the "
              f"newest {KEEP_BACKUPS} per instance")
    if files or unparseable or dropped:
        print()

    for name in all_repo:
        process_template(name, instances_by_tpl, backup_dir)
        print()

    if unmapped:
        print("left untouched (foreign / not from these templates): " + ", ".join(sorted(unmapped)))
    print("done." + ("  (dry-run — nothing changed)" if DRY_RUN else "  (LIVE — changes written)"))


if __name__ == "__main__":
    main()
