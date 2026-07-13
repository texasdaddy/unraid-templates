# unraid-templates

Public Unraid Docker templates + icons for the Reinlie self-hosted stack
(**Tape**, and later **Keystone**). Public so Unraid can fetch icons anonymously
via `raw.githubusercontent.com`; the application source stays in its own private repos.

## Icons
`icons/` holds 256×256 transparent PNGs. Reference them in a container's **Icon URL**:

```
https://raw.githubusercontent.com/texasdaddy/unraid-templates/main/icons/<name>.png
```

| Container | Icon |
|---|---|
| tape (prod) | `icons/tape.png` |
| tape-dev | `icons/tape_dev.png` |
| tape-db (prod) | `icons/tape_db.png` |
| tape-db-dev | `icons/tape_db_dev.png` |

## Templates
`templates/` holds the Unraid container templates (`<Icon>` pre-set). Secrets are blank
by design — fill them in Unraid on import. Import by copying the XML to
`/boot/config/plugins/dockerMan/templates-user/` (or via the Docker → Add Container
template dropdown), then set IP/secrets and Apply.
