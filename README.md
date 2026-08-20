# unraid-templates

Public Unraid Docker templates + icons for the Keystone self-hosted stack
(**Tape**, **CEF Tracker**, and later **Keystone**). Public so Unraid can fetch icons
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
| github-runner (one instance per repo) | `icons/running-icon-free-vector.png` | `templates/github-runner.xml` |

Every template + icon in this repo must have a row here — keep this table in sync when adding either (the reauth-bot icon was added 2026-07-25 but not listed until 2026-07-27). Scripts have their own manifest under [Scripts](#scripts); the same rule applies there.

## Templates
`templates/` holds the Unraid container templates (`<Icon>` pre-set). Secrets are blank
by design — fill them in Unraid on import.

### `github-runner.xml`

The one template here that is not a service: a self-hosted GitHub Actions runner, one
instance per repository (set `RUNNER_NAME` and `LABELS` per instance; nothing in the
template names a repo or a host). Self-hosted minutes do not count against the account's
Actions allowance, which is the whole reason to run one.

Two things in it are easy to get wrong and are documented in the file itself. **Network
mode defaults to `host` deliberately** — a runner on `bridge` starts service containers
on the host and then cannot reach them, because the job's steps run inside the runner's
own network namespace where `localhost` means something else entirely; the failure looks
like a healthy service refusing every connection (keystone#43). And **`RUNNER_NAME` and
`LABELS` appear in public workflow logs**, so neither should name the machine.

**This repo is registered as a template repository on the Unraid host** (`/boot/config/plugins/dockerMan/template-repos`), so Unraid tracks it: the templates appear under **Docker → Add Container** and, because each template carries a `<TemplateURL>` to its raw file, Unraid **merges new `<Config>` variables into an existing container when its Edit page is opened** (no purge/redeploy needed — that's the CA update path; "check for update" only checks the image). GitHub-raw caches ~5 min.

## Scripts

`scripts/` holds the repo's operational + CI tooling. Every script here must have a row:

| Script | What it is | Where it runs |
|---|---|---|
| `scripts/sync-templates.py` | Reconciles the Unraid host's `my-*.xml` container templates against this repo | Unraid host, via **User Scripts** |
| `scripts/check_no_internal_info.py` | Public-repo guard: fails if an operator host, IP, pool path or personal name is committed | CI, on every PR — see the caveat below |

> **The guard is advisory, not enforcing.** It runs on every pull request and
> fails loudly, but `main` has no branch protection and no rulesets, so nothing
> stops a red run from being merged. Read the check before merging; do not treat
> a leak as impossible because CI exists.

### `sync-templates.py`

One button, no parameters. Each run does **create / update / delete-as-necessary**
across every managed container template in
`/boot/config/plugins/dockerMan/templates-user`, **keeping each instance's applied
values**:

- **CREATE** — seeds `my-<name>.xml` for any repo template that has no `my-` file yet, so it is ready to pick under *Add Container*.
- **UPDATE** — for **every live instance** of a template (`my-tape.xml` *and* `my-tape-dev.xml`, `my-tape-db-dev.xml`, …): keeps that instance's applied value for each variable, refreshes the variable's metadata (description, defaults, visibility) from the repo template, and adds variables the template has gained.
- **DELETE-as-necessary** — drops a variable the template no longer defines **only when it is genuinely unused** (blank, or still at its default). A removed variable that still holds a real, non-default value is **kept and loudly flagged** (`!! KEPT`), because that almost always means the *template* is missing it — repo drift, not an intentional removal. Treat every `!! KEPT` line as a bug in `templates/`.

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

**Install as an Unraid User Script:** *Settings → User Scripts → Add New Script*,
name it `sync-templates`, paste the file in as the script body, and run it with
*Run Script* (leave it unscheduled — it is a deliberate, on-demand action, not a
cron job). Requires python3 ≥ 3.9; stdlib only, no dependencies to install.
