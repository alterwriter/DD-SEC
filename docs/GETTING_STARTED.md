# Getting started

> `dd-sec` is in **beta**. Writes are dry-run by default; verify important
> results in the Datadog UI.

## 1. Requirements

- `bash` 3.2 or newer (the stock macOS bash is fine)
- `curl`
- `jq`

```bash
# macOS
brew install jq
# Debian / Ubuntu
sudo apt install jq
# Windows
scoop install jq      # or run under WSL
```

That's the whole dependency list. `dd-sec` is a single script — there is no build
step and nothing to install but the file itself.

## 2. Put it on your PATH (optional)

```bash
chmod +x dd-sec
# optional: make it available everywhere
sudo install -m 0755 dd-sec /usr/local/bin/dd-sec
```

If you don't install it, just run `./dd-sec` from the repo directory.

## 3. First run

```bash
dd-sec start
```

`start` opens an arrow-key menu:

- **↑ / ↓** (or `k` / `j`) to move
- **Enter** to choose
- **1–9** to jump to an item
- **q** or **Esc** to cancel / go back

The first time you pick an action that needs the API, `dd-sec` logs you in
*inline* — there is no separate login step to run first. Choose **Browser** and it
opens Datadog's API Keys and Application Keys pages; create one of each, paste
them back, and the tool detects your Datadog site automatically.

Credentials are stored in your OS keystore (macOS Keychain or libsecret on Linux),
falling back to a `chmod 600` file under `~/.config/dd-sec/`. The session is
valid for 12 hours, after which the keys are silently re-validated.

## 4. A first real task

```bash
# See the open critical/high findings
dd-sec findings list --query '@status:open @severity:(critical OR high)'
```

The list is **numbered and cached**. To act on the third row you refer to `#3`,
never to its long ID:

```bash
dd-sec findings show 3          # full detail, including the ID if you want it
```

Every change is a dry-run until you add `--apply`, and every change needs a
reason:

```bash
# dry-run first (prints what would change, by name)
dd-sec recast pick --select 3 --to low --reason 'accepted risk, ticket SEC-123'
# then for real
dd-sec recast pick --select 3 --to low --reason 'accepted risk, ticket SEC-123' --apply
```

## 5. Generate a report

```bash
dd-sec report --format html --out posture.html
open posture.html        # macOS; use xdg-open on Linux
```

See [REPORTS.md](REPORTS.md) for all options.

## Scripting / CI

Every menu action has a direct command form, so the same tool works in a
pipeline. Set credentials via environment variables to skip the interactive
login entirely:

```bash
export DD_API_KEY=...        # your API key
export DD_APP_KEY=...        # your Application key
export DD_SITE=datadoghq.com # optional; auto-detected if omitted
dd-sec report --format json --out posture.json
```

In env mode the credentials are **not** written to disk.

## Environment variables

| Variable | Purpose |
|---|---|
| `DD_API_KEY` / `DD_APP_KEY` | credentials (env mode; not persisted) |
| `DD_SITE` | Datadog site; auto-detected if unset |
| `DD_CASES_PROJECT_ID` | default Work Management project |
| `DD_SEC_HOME` | override the config directory |
| `DD_SEC_KEYSTORE` | `auto` \| `keychain` \| `secret` \| `file` |
| `DD_SEC_NO_TUI` | set to anything to use numbered prompts instead of the arrow-key menu |
| `SAST_QUERY_LIMIT` | default 5000 (see the SAST note in [COMMANDS.md](COMMANDS.md)) |
| `SAST_LOOKBACK_DAYS` | default 30 |
| `NO_COLOR` | disable ANSI colour |
