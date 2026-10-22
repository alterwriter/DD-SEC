# zeroday-inventory

**Zero-Day Blast Radius asset inventory — Datadog API → Excel.**

> Part of the **DD-SEC** toolset. Read-only, interactive Bash. Given a CVE (or a
> package scope), it inventories which of *your* assets run the affected
> packages, by querying your own Datadog org with your own keys, and writes an
> Excel report for remediation planning.

> ⚠️ **Beta.** The Datadog API filter params and response schemas should be
> verified against <https://docs.datadoghq.com/api/latest/> for your org — this
> tool extracts defensively across schema variants, but endpoints evolve. All
> calls are **read-only**.

## What it answers

When a zero-day drops in `next`, `react`, `nuxt`, or a PHP package, the first
question is *"what do we even run that's affected, and where is it?"* This tool
builds that list:

- **JS family**: `next`, `nuxt`, `react` (including React Server Components
  packages)
- **PHP**: any Composer app, optional framework tagging, and host PHP runtime

…and maps each match down to the host and IP so you know exactly what to patch.

## Install / requirements

- **Required**: `bash`, `curl`, `jq`
- **Excel export** (auto-detected, in order):
  1. `python3` + `openpyxl` → full formatted 3-sheet workbook *(recommended)*
  2. `libreoffice --headless` → one `.xlsx` per sheet (cannot merge)
  3. neither → CSV output + install hints

```bash
# jq
brew install jq            # macOS
sudo apt install -y jq     # Debian/Ubuntu
# recommended Excel engine
pip install openpyxl
```

## Usage

### Interactive

```bash
./zeroday.sh
```

It will, in order: check dependencies → load credentials (flags → env → `.env` →
hidden prompt) → validate them → offer to save `.env` (chmod 600) → ask scan
options (scope, CVE ids, env, lookback, output, cache) → show a summary and
confirm → fetch → join → export → print a summary.

### Non-interactive (cron / CI)

```bash
# e.g. a Next.js zero-day fixed in 14.2.5: which of our apps run an affected version?
./zeroday.sh --non-interactive \
  --scope js \
  --package next \
  --affected-below 14.2.5 \
  --output blast_radius.xlsx
```

Target a zero-day with `--package` (name, comma-separated) and `--affected-below`
(the fixed-in version; keeps only strictly-lower versions) — both evaluated
against SBOM data. (`--cve` is a deprecated no-op: Datadog's vulnerability API is
unavailable/forbidden on current orgs; use package + version instead.)

Fails fast with a clear error if any credential is missing (no prompts). Supply
credentials via `--api-key/--app-key/--site`, environment variables, or `.env`.

### All options

Run `./zeroday.sh --help`.

## Credentials

Resolved in priority order: **CLI flags → environment → `.env` → interactive
prompt**. The `.env` file is parsed safely (`KEY=VALUE` only; it is **never**
`source`d, so nothing in it executes), and only an allowlist of keys is honoured.
See `.env.example`.

Prompts for `DD_API_KEY` / `DD_APP_KEY` are hidden (`read -rs`). Secrets are never
printed or written to logs.

### Datadog sites

`datadoghq.com` (US1), `us3.datadoghq.com`, `us5.datadoghq.com`, `datadoghq.eu`
(EU1), `ap1.datadoghq.com`, `ap2.datadoghq.com`, or a custom host. Interactive
mode offers a menu; otherwise set `--site` / `DD_SITE`.

### Required app-key scopes (read-only)

`appsec_vm_read`, `apm_read`, `hosts_read`, `apm_service_catalog_read`, and —
for the DDSQL host-resolution bridge — `timeseries_query`. A dedicated
**service-account** app key is recommended. On a `403`, the tool names the scope
it believes is missing. The DDSQL bridge degrades gracefully: without
`timeseries_query` (or k8s data), you still get the full repo-level inventory,
just without host/IP from that source.

## Output (`.xlsx`, 3 sheets)

| Sheet | Columns |
|---|---|
| `inventory` | `ip, hostname, repo, prog_lang` |
| `details` | `ip, hostname, repo, prog_lang, framework, package, version, service, env, cve_ids, severity, fix_version, data_source, confidence` |
| `unmapped` | repos with matching packages but no resolvable host/IP |

- `data_source`: `sbom_repo` · `sbom_service` · `vulns` · `apm_spans` · `hosts` ·
  `catalog` · `ddsql`
- `confidence`: `high` (resolved to a host, package+version known) · `medium`
  (resolved, version unknown) · `low` (repo-level only — matched a package but no
  host could be resolved)
- Empty cells are left blank (not `N/A`). Rows are deduplicated. Multiple IPs for
  one host are joined with `;`.
- Formatting: bold + frozen header, autofilter, auto column width.

If no Excel engine is present, the same data is written as `inventory.csv`,
`details.csv`, `unmapped.csv` under the run's `report/` directory.

## Package matchers

`matchers.json` controls what counts as affected — edit it without touching code.
JS matches are npm purl prefixes; PHP matches any `pkg:composer/*`, with optional
framework tags and host-runtime (`php*` via deb/rpm/apk) detection.

## How the join works

1. `repo → packages` from Repository SBOMs (the matcher-selected JS/PHP packages).
2. `repo → service` from, in order of reliability: **DDSQL**
   `dd.security_inventory_libraries.related_services`, then APM spans
   (`@git.repository_url`), then the Software Catalog.
3. `service → host` from **DDSQL** `k8s.pods` (service tag → node) and from host
   `service:` tags.
4. `host → ip` from DDSQL k8s node/pod annotations and from the Hosts API.
5. Host/Image SBOM PHP-runtime matches are added directly (even without a repo).
6. `--package` / `--affected-below` filter matches by package name and version
   (zero-day targeting), straight from SBOM data.
7. A matched repo that resolves to a host appears in `inventory`/`details` with
   the host/IP; one that does not still appears (blank host, `low` confidence)
   and is also listed in `unmapped`.

### Host resolution is best-effort, and that is honest

The JS/PHP matches live in **Repository** SBOMs. A repo only gains a host/IP if it
is also a running, tracked **service** (via `related_services` → k8s pod/node).
Source repos that are scanned but not deployed as tracked services will show
**repo-level only** (blank host) — that is the real blast radius at the code
level, not a failure. The `ddsql` path (above) is what lights up hosts for the
repos that *are* deployed; it needs the `timeseries_query` scope and k8s data in
Datadog, and degrades gracefully when absent.

Repo identity is fuzzy across sources (SBOM names vs. git URLs), so repos are
keyed on their **last two path segments** (`group/project`) — lenient by design.

## Reliability

- v2 security pagination follows `links.next`; `429` honours `X-RateLimit-Reset`,
  `5xx`/connection errors use exponential backoff (max 5).
- Raw API responses are cached under `./cache/<timestamp>/`; `--use-cache` reuses
  the most recent run with **no** API calls.
- Each run logs method/path/status/duration to `./logs/run_<timestamp>.log` —
  **never** keys or bodies.
- A `trap` cleans up temp files and restores the terminal on exit / Ctrl-C.

## Project layout

```
zeroday-inventory/
  zeroday.sh              # entrypoint: args, menus, orchestration
  lib/
    ui.sh                 # colors, menus, prompts, spinner, confirm
    env.sh                # safe .env load/save, credential resolution + validation
    dd_api.sh             # curl wrapper: auth, retry, rate-limit, pagination
    sources_sbom.sh       # Repository + Host SBOMs
    sources_vulns.sh      # vulnerabilities (client-side CVE/matcher filtering)
    sources_spans.sh      # APM span aggregation
    sources_hosts.sh      # Hosts API -> IPs
    sources_catalog.sh    # Software Catalog fallback
    join.sh               # jq relational join -> CSVs
    export.sh             # xlsx fallback chain
    csv2xlsx.py           # openpyxl helper
  matchers.json
  .env.example
  tests/                  # bats-core tests + fixtures (no live API calls)
  README.md
```

## Tests

```bash
bats tests/
```

Covers `.env` parsing (incl. the no-code-execution guarantee), purl matching,
repo-key normalization, pagination (mocked transport), and the join logic
(including the CVE filter) against fixtures — no live API calls.

## Beta caveats

- Verify endpoint filter params / response schemas against the Datadog docs for
  your org; extraction is defensive but a zero result can mean "schema moved",
  not "nothing affected".
- `shellcheck` is recommended before changes: `shellcheck zeroday.sh lib/*.sh`.
- Zero rows is not proof of safety — check that Code Security / APM / SBOM
  collection is actually enabled for the assets you expect.
