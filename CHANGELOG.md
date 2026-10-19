# Changelog

All notable changes to `dd-sec` are documented here.

## [1.1.0-beta.1] — beta

### Added
- **`report` command** — read-only point-in-time posture report in Markdown
  (default), self-contained HTML, or JSON. Covers findings severity/status
  distribution, a severity-ranked top-findings table, and a SAST summary with top
  repositories. Degrades gracefully when SAST permission is missing. Available
  both as `dd-sec report ...` and from the interactive menu.

### Changed
- All user-facing output translated to **English**.
- Version bumped to a beta identifier to reflect beta-testing status.

### Notes
- This is a **beta** release. Flags and output shapes may change.
- The SAST (`cicodescan`) path depends on an undocumented Datadog endpoint; it
  fails closed on suspected truncation, but treat its numbers as advisory.

## [1.0.0] — initial

- Findings list / show / keys, with numbered + cached results.
- Severity recast: pick / one / query / bulk (TSV/CSV/JSON), dry-run by default.
- Mute / unmute with the API's enumerated reasons.
- Severity-modifier rules: list / create / delete.
- Work Management: list / view / comment / status, plus `doctor` and
  `project-access` for diagnosing project visibility.
- SAST violations on the `cicodescan` track: list / repos / probe.
- Lazy authentication, OS-keystore credential storage, local CSV audit log.
