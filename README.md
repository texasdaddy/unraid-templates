# unraid-templates

Public Unraid Docker templates + icons for the self-hosted stack
(**Tape**, **CEF Tracker**, **Keystone**, **reauth-bot**). Public so Unraid can fetch icons
anonymously via `raw.githubusercontent.com`; the application source stays in its own
private repos.

## Icons
`icons/` holds 256×256 transparent PNGs. Reference them in a container's **Icon URL**:

```
https://raw.githubusercontent.com/texasdaddy/unraid-templates/main/icons/<name>.png
```

| Container | Icon | Template |
|---|---|---|
| tape (dev+prod) | `icons/tape.png` | `templates/tape.xml` |
| tape-db (dev+prod) | `icons/tape_db.png` | `templates/tape-db.xml` |
| cef-tracker (prod) | `icons/cef-tracker.png` | `templates/cef-tracker.xml` |
| reauth-bot | `icons/reauth_bot.png` | `templates/reauth-bot.xml` |
| keystone | `icons/keystone.png` | `templates/keystone.xml` |
| keystone-db | `icons/keystone_db.png` | `templates/keystone-db.xml` |
| keystone-web (dev+prod) | `icons/keystone-web.png` | `templates/keystone-web.xml` |
| the-desk (prod) | `icons/the-desk.png` | `templates/the-desk.xml` |
| iron-tide | `icons/iron-tide.png` | `templates/iron-tide.xml` |
| tldw-redis (start 1st) | `icons/tldw-redis.png` | `templates/tldw-redis.xml` |
| tldw-server (start 2nd) | `icons/tldw-server.png` | `templates/tldw-server.xml` |

Every template + icon in this repo must have a row here — keep this table in sync when adding either (the reauth-bot icon was added 2026-07-25 but not listed until 2026-07-27). Scripts have their own manifest under [Scripts](#scripts); the same rule applies there.

## Templates
`templates/` holds the Unraid container templates (`<Icon>` pre-set). Secrets are blank
by design — fill them in Unraid on import.

**`sync-templates.py` is the only thing that carries a template change toward a container that already exists — and it carries it as far as that container's *saved template*, not into the container itself.** Stock Unraid never merges a template change into an existing container, and that is deliberate rather than a bug: in `emhttp/plugins/dynamix.docker.manager/include/DockerClient.php`, `updateUserTemplate()` opens with `// Don't update templates, but leave code in place for future reference` and returns — on every release from 6.12 to current. Its sibling `downloadTemplates()` became a no-op only in **7.3.0**; on 6.12.x—7.2.x it is live, so registering this repo in `/boot/config/plugins/dockerMan/template-repos` there really does mirror it into `templates-usb` and refresh the *Default templates* list — but that path only populates the Add Container list (and deletes templates it no longer finds); it never touches an existing `my-*.xml`. Templates from this repo appear under **Docker → Add Container** in the *User templates* group because `sync-templates.py` seeds a `my-<name>.xml` for each; `<TemplateURL>` earns its keep by letting that script map an instance back to its template. **So: edit a template here, run `sync-templates.py`, then open the container's Edit page and press Apply.** The script rewrites `my-<name>.xml`; the container is rebuilt from that file by Apply, and equally by any container **Update** or *force update* — but never on its own. "Check for update" compares the image only.

## Scripts

`scripts/` holds the repo's operational + CI tooling. Every script here must have a row:

| Script | What it is | Where it runs |
|---|---|---|
| `scripts/sync-templates.py` | Reconciles the Unraid host's `my-*.xml` container templates against this repo | Unraid host, via **User Scripts** |
| `scripts/check_no_internal_info.py` | Public-repo guard: fails on internal-looking **shapes** — RFC1918/CGNAT addresses, `.lan`/`.local`/`*.ts.net` hosts, the real Unraid share roots under `/mnt/` (`apps`, `user`, `cache`, `remotes`, `disks`, `disk1`…`diskN` — an arbitrarily-named pool is NOT matched), freemail addresses, bare UUIDs, and `C:\Users\<name>\…` Windows profile paths. It scans **five surfaces**, because a push publishes all five: file **content** (the tracked tree, the lines each commit adds, and the index via `--staged`), file and directory **paths**, each commit's **author/committer name and email**, each commit's **message**, and any annotated **tag** the push names — its whole object, which carries the tag's name, its tagger and its message together. Four of those can only be removed by rewriting history; a tag is a ref and can be deleted. ⚠️ A **lightweight** tag has no object, so a leak that exists only as a ref NAME — a lightweight tag or a branch called after a host — is read by no layer ([#49](https://github.com/texasdaddy/unraid-templates/issues/49)). The path and message surfaces run a slightly **narrower** pattern set than file content does — a machine-local override *filename*, a UUID-named migration, and a commit message that merely mentions one are all ordinary, while the same shapes written *inside* a file are not. It **cannot** see a bare hostname, codename or personal name; those have no shape, and a second guard held outside every repo is what catches them. Both layers are required, and green CI here is not clearance. | CI, on every PR, on push to `main`, and on `v*` tags — required by branch protection, see below. ⚠️ **`--staged` is the exception: it runs only in the opt-in `.githooks/pre-commit` hook** (`git config core.hooksPath .githooks`), because a CI checkout has nothing staged. The push-path range scan still catches a staged leak before it reaches the remote. |

> **The guard is enforcing now** (this was the other half of #4). `main` carries
> branch protection requiring all three checks — `No internal info (public-repo
> guard)`, `Leak-guard tests`, `Templates are well-formed XML` — with
> `enforce_admins` on and `strict` (branches must be up to date) set, so a red run
> cannot be merged, including by the owner.
>
> Two consequences worth knowing. **A job's `name:` is the status-check context**,
> so renaming one of those three jobs does not fail its check — the required
> context simply never reports and every PR sits BLOCKED with green jobs and
> nothing to click. And **green CI still is not clearance**: this guard matches
> shapes only, and a bare hostname, codename or personal name has no shape. That
> is the project-side guard's job, and it is not run by CI.

### `sync-templates.py`

One button, no parameters. Each run does **create / update / delete-as-necessary**
across every managed container template in
`/boot/config/plugins/dockerMan/templates-user`, **keeping each instance's applied
values**:

- **CREATE** — seeds `my-<name>.xml` for any repo template that has no `my-` file yet, so it is ready to pick under *Add Container*.
- **UPDATE** — for **every live instance** of a template (`my-tape.xml` *and* `my-tape-dev.xml`, `my-tape-db-dev.xml`, …): keeps that instance's applied value for each variable, refreshes the variable's metadata (description, defaults, visibility) from the repo template, and adds variables the template has gained.
- **DELETE-as-necessary** — drops a variable the template no longer defines **only when it is genuinely unused** (blank, or still at its default). A removed variable that still holds a real, non-default value is **kept and loudly flagged** (`!! KEPT`), because that almost always means the *template* is missing it — repo drift, not an intentional removal. Treat a `!! KEPT` line as a bug in `templates/` — **except during a deliberate migration**, when it is the script telling you a mapping is still on your container: a `!! KEPT` line naming a variable the migration intentionally dropped means delete that mapping in the Unraid UI, **not** put it back in the template.

Container-level settings you set per instance — image tag, network/IP, WebUI, Extra
Params, ports, the container Name — are **always preserved**; only `<Config>`
elements are reconciled.

Instances map to templates by their `<TemplateURL>` basename, falling back to the
longest dash-prefix of the filename — so `my-tape-db-dev.xml` maps to `tape-db`
and never to `tape`. Containers that came from anywhere else are never touched.

**`DRY_RUN` is the only switch**, a constant at the top of the file — never a
parameter, never a second script:

| | |
|---|---|
| `DRY_RUN = True` | Prints exactly what it *would* create/update/delete. Writes nothing. |
| `DRY_RUN = False` | Performs the changes. Every overwritten file is backed up first (timestamped, under `templates-user/.template-sync-backups/`), writes are atomic, and a merged result is validated before it replaces the original. |

The committed copy is the **live** version (`DRY_RUN = False`). To validate a change
first, flip the constant to `True`, run it, review the output, then flip it back.

> **Backups redact your `Mask="true"` values** (#27). `Mask="true"` is a *UI* setting —
> it makes the Unraid form render a password box, but the XML on the flash drive
> holds the value in **plaintext**. Backups used to be byte-for-byte copies, so
> every run left another cleartext copy of every token and PAT on the drive, and
> nothing pruned them.
>
> Now a backup is written with every masked value replaced by `***REDACTED***`,
> the **first run also redacts the backups earlier versions already wrote**, and
> backups are pruned to the newest `KEEP_BACKUPS` (10) per instance. A `.bak`
> that cannot be parsed is *reported by name and left alone* — it may still hold
> a secret, so review and delete those by hand.
>
> **What this costs a restore:** the structure and every non-secret value come
> back in full; a masked value must be re-entered. That is not much of a loss —
> `merge()` copies applied values across verbatim, so a merge cannot damage a
> secret; the backup is there in case a *merge* goes wrong.
>
> `DRY_RUN = True` covers all of this: it reports what it would redact and prune
> and writes nothing.
>
> **What is redacted, stated exactly** — a `Mask="true"` `<Config>`, and the
> `<Environment><Variable><Value>` mirror dockerMan writes for the same variable.
> A secret passed some other way is **not** covered and never claimed to be: most
> importantly anything you typed into **`<Extra Parameters>`** (e.g.
> `-e TOKEN=...`), which is free text with no `Mask` flag to key on. Keep secrets
> in masked variables, not in Extra Parameters.

**Install as an Unraid User Script:** *Settings → User Utilities → User Scripts → Add New Script*,
name it `sync-templates`, paste the file in as the script body, and run it with
*Run Script* (leave it unscheduled — it is a deliberate, on-demand action, not a
cron job). Requires python3 ≥ 3.9; stdlib only, no dependencies to install.
