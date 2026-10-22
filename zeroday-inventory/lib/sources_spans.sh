#!/usr/bin/env bash
# sources_spans.sh - APM span analytics aggregation -> service/host/repo map.
#
# POST /api/v2/spans/analytics/aggregate, grouped by service, host, language and
# @git.repository_url, so we can stitch repo -> service -> host.
#
# Output rows: {service, host, language, repo, data_source:"apm_spans"}

# fetch_spans SCOPE_JS SCOPE_PHP OUT_NDJSON   (env via $ENV_FILTER, time via $LOOKBACK)
fetch_spans() {
  local js="$1" php="$2" out="$3"
  local raw="${CACHE_DIR}/spans_aggregate.json"
  : > "$out"

  # Build the language clause from scope.
  local langs=""
  [ "$js" = "1" ]  && langs="javascript"
  [ "$php" = "1" ] && langs="${langs:+$langs OR }php"
  [ -n "$langs" ] || { dim "  (spans skipped: no language in scope)"; return 0; }

  local query="language:(${langs})"
  [ -n "${ENV_FILTER:-}" ] && query="${query} env:${ENV_FILTER}"
  local from="${LOOKBACK:-now-7d}"

  local body
  body="$(jq -nc --arg q "$query" --arg from "$from" '{
    data: { type: "aggregate_request", attributes: {
      compute: [ { aggregation: "count", type: "total" } ],
      filter: { query: $q, from: $from, to: "now" },
      group_by: [
        { facet: "service", limit: 1000 },
        { facet: "@git.repository_url", limit: 1000 }
      ]
    } } }')"

  # The aggregate caps total groups at 10,000 ACROSS all dimensions. This asks for
  # [service x @git.repository_url] to recover repo -> service. service -> host is
  # resolved separately from host `service:` tags (sources_hosts.sh), so host is
  # NOT a dimension here. Buckets live at .data[].attributes.by (verified live).
  progress "[4/6]" "APM spans aggregate (service x @git.repository_url -> repo->service)"
  if ! dd_post "/api/v2/spans/analytics/aggregate" "$body"; then
    warn "Span aggregation failed (HTTP ${HTTP_CODE}) - non-fatal; repos just won't gain a host."
    return 0
  fi
  printf '%s' "$HTTP_BODY" > "$raw"

  jq -c '
    def norm_repo($u):
      ($u // "") | ascii_downcase
      | sub("^https?://";"") | sub("^[^@/]+@";"")
      | sub("\\.git$";"") | sub("/$";"");
    (.data // .buckets // [])[]?
    | (.attributes.by // .by // {}) as $b
    | { service: ($b.service // ""),
        host:    "",
        language:"",
        repo:    norm_repo($b["@git.repository_url"]),
        data_source: "apm_spans" }
    | select(.service != "" and .repo != "")
  ' "$raw" > "$out" 2>/dev/null || : > "$out"

  dim "  span groups: $(wc -l < "$out" | tr -d ' ')"
}
