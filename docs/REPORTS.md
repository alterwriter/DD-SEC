# Reports

> Beta. `dd-sec report` is **read-only** — it never mutates a finding and needs
> only the `*_read` permissions.

## What a report is

A point-in-time snapshot of your Datadog security posture, pulled from the same
data the interactive views show:

- **Security findings** — total, severity distribution, status breakdown, and a
  severity-ranked list of the top findings.
- **SAST violations** (`cicodescan`) — total, severity distribution, and top
  repositories by violation count. This section appears only if the app key can
  read it; otherwise it is marked *unavailable* and the rest of the report is
  still produced.
- **Methodology & caveats** — exactly how the numbers were gathered, so a reader
  knows what they can and cannot conclude.

## Usage

```
report [--query Q] [--days D] [--format md|html|json] [--out FILE]
       [--title T] [--top N] [--limit N] [--no-sast]
```

| Flag | Default | Meaning |
|---|---|---|
| `--query` | `@status:open` | the findings query to report on |
| `--days` | 30 | SAST lookback window |
| `--format` | `md` | `md`, `html`, or `json` |
| `--out` | *(stdout)* | write to a file instead of printing |
| `--title` | "Datadog Security Posture Report" | report title |
| `--top` | 25 | how many findings to list in the top table |
| `--limit` | 1000 | max findings to fetch for the summary |
| `--no-sast` | off | skip the SAST section entirely |

## Examples

```bash
# Markdown to your terminal (pipe it, redirect it, read it)
dd-sec report

# Self-contained HTML page you can open in a browser or email
dd-sec report --format html --out posture.html

# Machine-readable summary for a pipeline or dashboard
dd-sec report --format json --out posture.json | jq '.findings.by_severity'

# Scope it to the findings you care about, over a 90-day SAST window
dd-sec report --query '@status:open @severity:(high OR critical)' --days 90 \
              --title 'Weekly critical/high posture' --out weekly.md
```

## Formats

- **Markdown** (`md`) — tables and headings, ideal for a PR description, a wiki
  page, or a ticket.
- **HTML** (`html`) — a single self-contained page: no external scripts, fonts, or
  images, with a light/dark theme that follows the reader's system. Opens anywhere;
  safe to attach or email.
- **JSON** (`json`) — a structured object (`meta`, `findings`, `sast`) for feeding
  another tool. The `meta.beta_notice` field travels with the data.

## How to read the numbers (the caveats that matter)

- **A report is a snapshot.** It does not auto-update. Regenerate it before you
  rely on it — finding IDs change between scans.
- **Zero SAST is not "clean".** The `cicodescan` track only retains events for
  scans inside the lookback window. A repository last scanned longer ago than
  `--days` reads as zero here even if its findings still show in the UI. Widen
  `--days` if a repo you expect is missing.
- **The SAST endpoint is undocumented.** Its result ceiling is not guaranteed
  stable; the underlying query fails closed on suspected truncation, but the
  numbers are still best treated as advisory during beta.
- **Partial is labelled.** If the SAST section is missing, the report says so and
  why (usually a missing `code_analysis_read` scope) — it does not silently drop
  it.
