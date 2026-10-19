# Authentication

> Beta. This describes how `dd-sec` authenticates and stores credentials today;
> details may change between beta releases.

## Lazy by design

`dd-sec` never asks for a key up front. An action calls for authentication only
when it actually needs it, and when it does, the login runs inline and the action
continues. There is no "log in first" step to remember — `dd-sec start` and then
picking any API-backed action is enough.

Once you've logged in, the session lasts 12 hours. After that the stored keys are
silently re-validated on the next action.

## Why API key + Application key, and not a browser session

This is a deliberate design decision, not a limitation.

Datadog has no OAuth device-authorization flow. Its OAuth2 is meant for
Marketplace integrations — confidential clients with a client secret — and Datadog
does not recommend initiating authorization outside the integration tile.

Reading your existing **browser session** instead would mean:

- decrypting the browser's cookie jar (Keychain-wrapped AES on macOS, DPAPI on
  Windows),
- scraping a CSRF token out of the page HTML, and
- tracking an internal web-UI version header across Datadog deploys.

That is fragile — and, more importantly, **a script that decrypts browser cookies
is indistinguishable from an infostealer.** `dd-sec` refuses to do it.

API keys + Application keys are the right tool instead: they are **revocable**,
**scopable**, and **attributable** in the Datadog audit log. So that's what the
tool uses.

## Logging in

`auth login` offers three modes:

| Mode | What it does |
|---|---|
| **Browser** | Opens the API Keys and Application Keys pages; you create one of each and paste them back. |
| **Manual** | You paste an API key and Application key you already have. |
| **Env** | Uses `DD_API_KEY` / `DD_APP_KEY` from the environment; credentials are **not** written to disk. |

The Datadog **site** is detected automatically against `/api/v1/validate` (one
cheap request per candidate site), or you can set it with `--site` /
`DD_SITE`.

After login, the tool probes whether per-finding severity recast is available in
your org (`direct`) or whether you must use severity-modifier rules (`rule`). This
probe sends an empty findings list, so nothing is mutated.

## Where credentials are stored

Resolved in this order (override with `DD_SEC_KEYSTORE`):

1. **macOS Keychain** (`security`)
2. **libsecret** (`secret-tool`) on Linux
3. **File** fallback: `~/.config/dd-sec/credentials`, created `chmod 600` inside a
   `chmod 700` directory

The config directory can be relocated with `DD_SEC_HOME`.

## Logging out

```bash
dd-sec auth logout
```

This removes the local credentials and session. It does **not** revoke the key in
Datadog — do that from the Application Keys page in your org settings if you need
to.

## Audit trail

Every write the tool performs is appended to a local CSV at
`~/.config/dd-sec/audit/dd-sec-YYYYMMDD.csv` with the timestamp, site, org,
target, action, reason, and HTTP status. This is local bookkeeping; it complements
(does not replace) Datadog's own audit log.
