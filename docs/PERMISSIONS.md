# Permissions

> Beta. The quickest way to see what your current app key can and can't do is:
>
> ```bash
> dd-sec auth probe
> ```
>
> It exercises each feature against the real endpoint it uses, so a later 403 is
> never a surprise.

## Permission by feature

| Feature | Required permission(s) |
|---|---|
| Findings (list / show) | `security_monitoring_findings_read` — `appsec_vm_read` also satisfies it |
| Recast severity | `security_monitoring_findings_write` or `appsec_vm_write` |
| Mute / unmute | `security_monitoring_findings_write` or `appsec_vm_write` |
| Severity-modifier rules | `security_pipelines_read` / `security_pipelines_write` |
| Work Management | `cases_read` / `cases_write` |
| SAST violations (`cicodescan`) | `code_analysis_read` |
| Reports | only the `*_read` permissions above (reports never write) |

## The one that trips people up: `code_analysis_read`

This is the permission that governs the `cicodescan` track. Without it, the SAST
query returns:

```
403  User does not have permission for track cicodescan
```

which reads like a bad endpoint rather than a missing permission. If `sast list`
gives you a 403, this is almost always why. Confirm with `auth probe`, and check
that `DD_SITE` is correct — a key from another site is rejected with the same
status.

## Scoped application keys

An Application key can be **scoped** to a subset of permissions. A scoped key is
the one cause that makes the same user see *less* through the API than in the
browser. `dd-sec work doctor` checks this explicitly: it names the key in use (by
its last 4 characters), lists which of the scopes this tool needs are present, and
reports a verdict based on that — never on the mere presence of a scope list.

If a key carries hundreds of scopes but still includes the ones you need, scope is
**not** your problem — look at restriction policies instead (`work doctor`
walks you through this).

## Read-only vs write

Everything `dd-sec` does is read-only until you pass `--apply`. The report
generator is read-only with no exceptions — it needs only the `*_read`
permissions, and a section whose permission is missing is marked *unavailable*
rather than failing the whole run.
