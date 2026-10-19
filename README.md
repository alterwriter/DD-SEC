# DD-SEC

**A terminal-native CLI for day-to-day Datadog Security work — built by reverse-engineering the product's own API surface.**

> ⚠️ **Beta.** `dd-sec` is in **beta testing**. The commands that *read* data are
> safe to lean on; every command that *writes* is dry-run by default and demands
> a `--reason`. Still, treat results as advisory and verify anything important in
> the Datadog UI before you act on it. Interfaces, flags, and output shapes may
> change between beta releases. See [Known limitations](#known-limitations).

---

## What this is

Security engineers spend their day in a handful of Datadog Security screens:
triaging findings, recasting severities, muting noise, writing automation rules,
filing Work Management items, and reading raw SAST violations. Each of those is a
few clicks in the browser — and a few clicks times a few hundred findings is a
morning gone.

`dd-sec` is that workflow as a single, dependency-light shell script. It talks to
Datadog over the **documented v2 API** wherever one exists, and — for the one
capability that has no public endpoint (CI/CD code-scan violations) — over an
**internal endpoint whose request shape was reverse-engineered from the product
UI**. The whole point of the project is that second part: figuring out exactly
what the Datadog web app sends, then rebuilding it as something you can script,
pipe, and run in CI.

It is a tool for Datadog **security operations** — not an attack tool. It
authenticates with *your own* API key and Application key, it is read-only by
default, and it keeps a local audit trail of every change it makes.

## Why reverse-engineer at all?

Most of what a security engineer touches is already a first-class, documented API
— findings, severity overrides, mute, severity-modifier rules, Case Management.
`dd-sec` uses those directly.

But one workflow isn't exposed that way: the **CI/CD code-scan (SAST) violations**
on the `cicodescan` track. The Datadog UI reads them through an *undocumented*
`logs-analytics` endpoint. Rather than leave that gap, `dd-sec` reconstructs the
exact request the UI makes — and then treats the result with suspicion, because an
undocumented endpoint can change without notice:

- it **fails closed** when it detects a truncated or structurally unexpected
  response, instead of quietly reporting "0 violations";
- it tells you *which* of its layered filters killed a result, so a zero is never
  a mystery;
- it reads repository identifiers straight out of the returned data instead of
  guessing field names.

That posture — *use the documented API where it exists, reverse-engineer the gap,
and never trust the gap blindly* — is the design philosophy of the whole tool.

## The experience we're aiming for

- **One command to remember.** `dd-sec start` drops you into an arrow-key menu.
  Everything else is discoverable from there.
- **Lazy authentication.** Nothing asks for a key until an action actually needs
  one. When it does, the login happens inline and the action continues — there's
  no separate "log in first" step.
- **Numbers, not 44-character IDs.** List findings once; from then on you act on
  `#3`, not on an opaque base64 blob you'd have to copy by hand.
- **Safe by default.** Every write is a dry-run until you add `--apply`, and every
  write requires a `--reason` that lands in a local CSV audit log.
- **Honest failures.** A 403 explains which permission is missing. A zero result
  tells you how to find out whether it's real. The tool would rather say "I don't
  know" than print a screen of question marks.
- **Reports you can hand to someone.** `dd-sec report` turns the live posture into
  a shareable Markdown, HTML, or JSON document.

## Quick start

```bash
# 1. Dependencies: bash 3.2+, curl, jq
#    macOS:  brew install jq
#    Debian: sudo apt install jq

# 2. Put dd-sec on your PATH (or run ./dd-sec from here)
chmod +x dd-sec
./dd-sec start          # interactive menu — it will ask you to log in when needed

# Or go straight to a command:
./dd-sec findings list --query '@status:open @severity:critical'
./dd-sec report --format html --out posture.html
```

On first use the tool opens Datadog's **API Keys** and **Application Keys** pages,
you paste the two keys back, and it detects your site automatically. Keys are
stored in the OS keystore (macOS Keychain / libsecret), falling back to a
`chmod 600` file. See [docs/AUTHENTICATION.md](docs/AUTHENTICATION.md).

## What it can do

| Area | Commands |
|---|---|
| **Findings** | list (numbered + cached), show, inspect raw attribute layout |
| **SAST violations** | list / repos / probe on the `cicodescan` track |
| **Recast severity** | by picked number, by ID, by query, or in bulk from a file |
| **Mute / unmute** | with the API's enumerated reasons |
| **Automation rules** | list / create / delete severity-modifier rules |
| **Work Management** | list, view, comment, change status, project access doctor |
| **Reports** | point-in-time posture report in Markdown / HTML / JSON |

Full reference: **[docs/COMMANDS.md](docs/COMMANDS.md)**.

## Reports

```bash
dd-sec report                                   # Markdown to stdout
dd-sec report --format html --out posture.html  # self-contained styled page
dd-sec report --format json --out posture.json  # machine-readable summary
dd-sec report --query '@status:open @severity:(high OR critical)' --days 90
```

A report is **read-only** — it never mutates a finding and needs only the
`*_read` permissions. If the app key can't read SAST data, that section is marked
*unavailable* and the rest of the report is still produced. See
**[docs/REPORTS.md](docs/REPORTS.md)**.

## Documentation

- [Getting started](docs/GETTING_STARTED.md) — install, first login, the menu
- [Command reference](docs/COMMANDS.md) — every command and flag
- [Authentication](docs/AUTHENTICATION.md) — why API keys, how they're stored
- [Permissions](docs/PERMISSIONS.md) — which scope each feature needs
- [Reports](docs/REPORTS.md) — generating and reading posture reports

## Design principles

1. **One file, no runtime.** Pure bash + `curl` + `jq`. No build step, no package
   manager, nothing to install but the script.
2. **Read-only until told otherwise.** Writes are dry-run by default and always
   require a justification that is logged locally.
3. **Fail closed, explain loudly.** Ambiguity is surfaced, never swallowed.
4. **Never handle a secret you don't have to.** The tool refuses to scrape browser
   sessions on purpose — see [docs/AUTHENTICATION.md](docs/AUTHENTICATION.md) for
   the reasoning.

## Known limitations

- **Beta.** Flags and output shapes may change between releases.
- The **SAST (`cicodescan`) endpoint is undocumented.** Its server-side result
  ceiling isn't guaranteed stable; the tool detects truncation and fails closed,
  but a future product change could still break this path.
- `report --format html` embeds everything inline (no external assets) so it opens
  anywhere, but it is a snapshot — regenerate it; it does not auto-update.
- Finding IDs change between scans, so a cached list can go stale. The tool
  re-verifies selections against live data before applying anything.

## Contributing & feedback

This is a beta. Bug reports, reproduction steps, and "this 403 wasn't explained
well" notes are all welcome via issues. When reporting a SAST problem, `dd-sec
sast probe` output is the single most useful thing to attach.

## License

See [LICENSE](LICENSE).
