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
| tape (prod) | `icons/tape.png` | `templates/tape.xml` |
| tape-dev | `icons/tape_dev.png` | `templates/tape-dev.xml` |
| tape-db (prod) | `icons/tape_db.png` | `templates/tape-db.xml` |
| tape-db-dev | `icons/tape_db_dev.png` | `templates/tape-db-dev.xml` |
| cef-tracker (prod) | `icons/cef-tracker.png` | `templates/cef-tracker.xml` |
| reauth-bot | `icons/reauth_bot.png` | `templates/reauth-bot.xml` |
| keystone | `icons/keystone.png` | `templates/keystone.xml` |
| keystone-db | `icons/keystone_db.png` | `templates/keystone-db.xml` |

Every template + icon in this repo must have a row here — keep this table in sync when adding either (the reauth-bot icon was added 2026-07-25 but not listed until 2026-07-27).

## Templates
`templates/` holds the Unraid container templates (`<Icon>` pre-set). Secrets are blank
by design — fill them in Unraid on import.

**This repo is registered as a template repository on the Unraid host** (`/boot/config/plugins/dockerMan/template-repos`), so Unraid tracks it: the templates appear under **Docker → Add Container** and, because each template carries a `<TemplateURL>` to its raw file, Unraid **merges new `<Config>` variables into an existing container when its Edit page is opened** (no purge/redeploy needed — that's the CA update path; "check for update" only checks the image). GitHub-raw caches ~5 min.
