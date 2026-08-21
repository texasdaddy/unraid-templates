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
| github-runner (one instance per repo) | `icons/github-runner.png` | `templates/github-runner.xml` |

Every template + icon in this repo must have a row here — keep this table in sync when adding either (the reauth-bot icon was added 2026-07-25 but not listed until 2026-07-27). Scripts have their own manifest under [Scripts](#scripts); the same rule applies there.

## Templates
`templates/` holds the Unraid container templates (`<Icon>` pre-set). Secrets are blank
by design — fill them in Unraid on import.

**This repo is registered as a template repository on the Unraid host** (`/boot/config/plugins/dockerMan/template-repos`), so Unraid tracks it: the templates appear under **Docker → Add Container** and, because each template carries a `<TemplateURL>` to its raw file, Unraid **merges new `<Config>` variables into an existing container when its Edit page is opened** (no purge/redeploy needed — that's the CA update path; "check for update" only checks the image). GitHub-raw caches ~5 min.

### `github-runner.xml`

The one template here that is not a service: a self-hosted GitHub Actions runner, **one
instance per repository**. Nothing in it names a repository or a host — `ACCESS_TOKEN`,
`REPO_URL`, `RUNNER_NAME` and `LABELS` are set per instance. Use it on a **private**
repository, where its minutes do not count against the account's Actions allowance; that is
the usual reason to run one, since GitHub's *standard* hosted runners are already free for
public repos.

It runs **its own Docker daemon inside itself** (Docker-in-Docker): `Privileged` on,
`START_DOCKER_SERVICE=true`, `Network` on Bridge, and *no* host socket mounted. That is the
whole design, and it replaced an earlier host-socket + host-networking version.

Everything an operator has to act on is in the template's own `<Config Description>`
fields, which is deliberate: Unraid never renders XML comments, and `sync-templates.py`
reconciles `<Config>` elements only — so for a container that already exists, edits to
`<Overview>` never arrive, and a field description is the one place *prose* reaches both new
and existing instances. What follows is orientation, not the reference.

- **Why Docker-in-Docker.** Under the socket model the runner asked the *host's* daemon for
  a workflow's `services:` container, so the published port landed in the **host's** network
  namespace while the job's steps ran in the runner's own — `localhost:5432` found nothing.
  Measured on a real cutover, where the daemon had genuinely published the port
  (`-p 5432:5432`, read out of the command the runner issued) and the steps still could not
  reach it, so the usual "the port was never published" explanation did not apply. Host
  networking fixes that for *one* runner and still occupies a host port, so any second
  runner running the same workflow collides. An in-container daemon makes the service a
  sibling on a private daemon: `localhost` resolves, nothing is published on the host, and
  N runners never collide.
- **Three settings have no field of their own**, because Unraid does not express them as
  `<Config>` entries, so nothing carries an inline description for them: **Network** must be
  `Bridge`, **Privileged** must be on (both on the container's Edit page, Advanced View),
  and the container **Name** should match `RUNNER_NAME`. For a container that already
  exists, *none* of the three is updated by `sync-templates.py` or by Unraid's template
  merge — set them by hand. This is the step most easily missed when converting an
  existing host-socket runner, and getting it wrong is silent.
- **`Privileged` and `START_DOCKER_SERVICE` are one setting in two places.** Both are
  required, and `START_DOCKER_SERVICE` must be the *exact string* `true` — the entrypoint
  string-compares it and defaults it to `false`, so `True`/`yes`/`1` all mean off. Note this
  is the opposite of `EPHEMERAL`, which any non-empty value enables, including `false`.
  Set only one of the pair and nothing complains: the entrypoint never checks that the
  daemon started, so the runner registers, goes Idle, accepts a job, and *then* every Docker
  step fails against a runner the UI shows as healthy.
- **Do not point this runner at a public repository.** A job on it is root in a privileged
  container, and on a public repo anyone can open a fork pull request. If outside
  contributions are in play at all, set Settings → Actions → General → *Fork pull request
  workflows from outside collaborators* to **Require approval for all external
  contributors**; the first-time-contributors default is not enough here.
- **`RUNNER_NAME` is printed in every job log**, so never name it for the machine. Labels
  are *not* printed there — what publishes them is the `runs-on:` line in the workflow file,
  world-readable on a public repo. Same conclusion, different mechanism.
- **Known limit, measured:** a container the in-container daemon starts on a bridge network
  may have no return path to the network — on the runner this was measured on, attached to a
  *custom* Unraid network, the outbound SYN was forwarded and source-NATed out correctly and
  no reply ever came back, so a build failed with a DNS error that was not a DNS problem.
  Workaround: `docker build --network=host` (inside the runner that means the *runner
  container's* namespace, not the Unraid host's — provided the runner is on Bridge).
  `services:` containers are unaffected. The template ships the plain bridge network, which
  is the configuration that was *not* tested.

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
- **DELETE-as-necessary** — drops a variable the template no longer defines **only when it is genuinely unused** (blank, or still at its default). A removed variable that still holds a real, non-default value is **kept and loudly flagged** (`!! KEPT`), because that almost always means the *template* is missing it — repo drift, not an intentional removal. Treat a `!! KEPT` line as a bug in `templates/` — **except during a deliberate migration**, when it is the script telling you a mapping is still on your container. Converting a `github-runner` off the host-socket design is the case that exists today: a `!! KEPT` line naming the Docker socket or the old work directory means delete that mapping in the Unraid UI, **not** put it back in the template.

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
