# Command reference

> Beta. Every data-changing command is **dry-run by default** and requires
> `--apply` to execute, plus a `--reason` that is written to a local audit log.

```
dd-sec start                 interactive menu (the only command worth memorising)
dd-sec <group> <cmd> ...     direct invocation, for scripts and CI
dd-sec help | version
```

## Findings

```
findings list   [--query Q] [--limit N] [--json] [--export FILE.tsv]
```
Lists findings. Results are **numbered and cached**, so later actions use the
number (`#3`), not the finding ID. `--export` writes a round-trip TSV you can edit
and feed back to `recast bulk`. `--json` prints the raw API response.

```
findings show N
```
Full detail of row `#N` from the last list, including the complete ID.

```
findings keys   [--query Q]
```
Prints the real attribute layout of a finding as dotted paths. Use it when a
column comes out as `-` — finding attribute shapes differ by type and org, and
this shows you exactly where severity/status/name live.

## SAST violations (`cicodescan` track)

```
sast list   [--repo NAME] [--repo-id HOST/PATH] [--branch B] [--sha SHA]
            [--from-git] [--all-categories] [--days D]
```
With no filter this is org-wide. `--repo` tries `@git.repository.name` and then
automatically falls back to a wildcard on `@git.repository.id`, because
`repository.name` is not a confirmed facet on this track. `--from-git` derives the
repo id from the current directory's `origin` remote. Default lookback is 30 days.

```
sast repos   [DAYS]
```
Lists the repository identifiers that **actually exist** in the data (default
90 days). Use these values verbatim with `--repo-id`.

```
sast probe   [--repo N | --repo-id ID] [--branch B] [--days D]
```
Adds filters one at a time and prints the result count at each step. **The first
line that drops to 0 is the cause** of an unexpected empty result. This is the
diagnosis tool for "there should be violations but I get zero".

> **Why so careful here?** The `cicodescan` data comes from an undocumented
> `logs-analytics` endpoint. A filter on a non-existent facet returns zero rows
> with no error — indistinguishable from "no violations". `dd-sec` detects
> truncation, fails closed, and gives you `sast probe` / `sast repos` so a zero is
> never a guess.

## Recast severity

> Requires `severity_mode=direct` (check with `auth probe`). If your org only
> allows rule-based severity changes, use `rule create` instead.

```
recast pick    --select S --to SEV --reason R [--apply]
```
The primary path. `S` is a selection over the last list: `3` | `1,4,9` | `2-10` |
`all` | `all,!7`. No ID to copy. Before applying, the selection is re-verified
against live data and shown **by name**.

```
recast one     --id ID --to SEV --reason R [--apply]
recast query   --query Q --to SEV --reason R [--limit N] [--apply]
recast bulk    --file F.tsv|F.csv|F.json [--apply]
```
`recast bulk` accepts the TSV from `findings list --export` (rows with an empty
`target_severity` are skipped), positional CSV, or JSON. It validates **every**
row before sending anything — a half-applied bulk recast is worse than a rejected
one.

`SEV` is one of `info_none | low | medium | high | critical`. Note that
`static_code_vulnerability`, `secret`, `iac_misconfiguration`, and
`runtime_code_vulnerability` do not support `info_none` (their floor is `low`).

## Mute / unmute

```
mute pick   --select S --reason R [--unmute] [--apply]
mute        (--id ID | --query Q) --reason R [--unmute] [--apply]
```
Reasons are enumerated by the API and differ by direction:

- **mute**: `PENDING_FIX` `FALSE_POSITIVE` `OTHER` `NO_FIX` `DUPLICATE` `RISK_ACCEPTED`
- **unmute**: `NO_PENDING_FIX` `HUMAN_ERROR` `NO_LONGER_ACCEPTED_RISK` `OTHER`

## Automation rules (severity-modifier rules)

```
rule list
rule create   --name N (--to SEV | --shift up|down) --types T[,T]
              [--query Q] --reason R [--apply]
rule delete   --id RULE_ID [--apply]
```
Rules evaluate against `@severity_details.adjusted.value`, and the first matching
rule wins. A rule query may not reference `@severity` or
`@severity_details.user_adjusted`.

## Work Management (Case Management v2)

```
work list       [--filter F] [--limit N]
work view       --key KEY
work comment    --key KEY --text T [--apply]
work status     --key KEY --to STATUS [--apply]
work projects | work types | work use-project --id ID
work project-access --id UUID
work doctor     [--expect 'name1,name2']
```
`work doctor` answers the common "why does the API return fewer projects than the
dashboard?" question — it checks app-key identity, key scope, pagination, and each
project's restriction policy. `work project-access` reads one project's policy by
UUID (from the project URL in the UI), even for a project that doesn't appear in
the list.

Two facts worth knowing: a work type can only be used in a project it has been
added to, and the Case Management v2 API has **no attachment or read-comment
endpoint** — detail lives in comments, which you can write but only read in the UI.

## Reports

```
report   [--query Q] [--days D] [--format md|html|json] [--out FILE]
         [--title T] [--top N] [--limit N] [--no-sast]
```
Read-only point-in-time posture report. See [REPORTS.md](REPORTS.md).

## Session

```
auth login    [--mode browser|manual|env] [--site S] [--api-key K] [--app-key K]
auth status | auth probe | auth logout
```
`auth probe` exercises every feature's permission in one pass, so a later 403 is
never a surprise. `auth logout` deletes the local credentials and session — it
does **not** revoke the key in Datadog.
