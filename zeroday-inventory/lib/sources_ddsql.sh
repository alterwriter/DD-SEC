#!/usr/bin/env bash
# sources_ddsql.sh - DDSQL bridge for host resolution.
#
# This is what fills in host/IP when repos are NOT APM-instrumented. It uses two
# datasets the REST SBOM API does not expose:
#   dd.security_inventory_libraries.related_services  -> repo -> service
#   k8s.pods JOIN k8s.nodes                            -> service -> node (+ IP)
#
# Output is appended into the SAME NDJSON the join already reads:
#   repo->service rows -> spans.ndjson   (join maps repo rkey -> service)
#   service->node rows -> hosts.ndjson   (join maps service -> host, host -> ip)
# so no join change is needed.
#
# Needs the app key's 'timeseries_query' scope AND data access (appsec_vm_read
# for the inventory table, infra/k8s read for pods/nodes). Degrades gracefully:
# on any failure, repo-level results are unaffected, hosts just are not added.
#
# DDSQL docs: POST /api/v2/ddsql/query/tabular (column-major result).

# ddsql_rows SQL -> NDJSON rows on stdout (one object per row). Returns non-zero
# if the query did not complete; a truncation warning is surfaced.
ddsql_rows() {
  local sql="$1" body to from
  to=$(( $(date +%s) * 1000 )); from=$(( to - 30 * 86400 * 1000 ))
  body="$(jq -nc --arg q "$sql" --argjson f "$from" --argjson t "$to" \
    '{data:{type:"ddsql_query_request",attributes:{row_limit:10000,
      time:{from_timestamp:$f,to_timestamp:$t},query:$q}}}')"
  dd_post "/api/v2/ddsql/query/tabular" "$body" || return 1
  [ "$(printf '%s' "$HTTP_BODY" | jq -r '.data.attributes.state // "?"' 2>/dev/null)" = "completed" ] || return 1
  if ! printf '%s' "$HTTP_BODY" | jq -e '(.data.attributes.warnings // []) | length == 0' >/dev/null 2>&1; then
    warn "DDSQL: result may be truncated at row_limit (10000) - results could be partial."
  fi
  printf '%s' "$HTTP_BODY" | jq -c '
    .data.attributes.columns as $c
    | if ($c | length) > 0 then
        ($c[0].values | length) as $n
        | range(0; $n) | . as $i
        | reduce range(0; ($c | length)) as $j ({}; .[$c[$j].name] = $c[$j].values[$i])
      else empty end' 2>/dev/null
}

# fetch_ddsql CACHE_DIR
fetch_ddsql() {
  local cache="$1" tmp nrs nk
  progress "[+]" "DDSQL bridge (related_services + k8s pods -> host/IP)"

  # 1) repo -> service(s)
  tmp="$(mktemp)"
  if ! ddsql_rows "SELECT DISTINCT repository, related_services FROM dd.security_inventory_libraries WHERE asset_type='REPOSITORY' AND related_services IS NOT NULL AND cardinality(related_services) > 0" > "$tmp"; then
    warn "DDSQL unavailable (needs 'timeseries_query' scope + data access) - host resolution via DDSQL skipped."
    dim "  Repo-level results are unaffected. Add the scope to the app key to enable host/IP."
    rm -f "$tmp"; return 0
  fi
  jq -c '.related_services[]? as $s
         | select($s != null and $s != "")
         | {service:$s, repo:.repository, host:"", data_source:"ddsql"}' "$tmp" >> "${cache}/spans.ndjson"
  nrs="$(wc -l < "$tmp" | tr -d ' ')"; rm -f "$tmp"

  # 2) service -> node (+ node/pod IP). OVN/OpenShift clusters yield IPs; other
  #    clusters still yield the node hostname (a resolvable host).
  tmp="$(mktemp)"
  if ddsql_rows "SELECT p.tags->'service' AS service, p.spec_node_name AS node, split_part(json_extract_path_text(CAST(n.annotations->'k8s.ovn.org/node-primary-ifaddr' AS json),'ipv4'),'/',1) AS node_ip, split_part(json_extract_path_text(CAST(p.annotations->'k8s.ovn.org/pod-networks' AS json),'default','ip_address'),'/',1) AS pod_ip FROM k8s.pods p LEFT JOIN k8s.nodes n ON n.cluster_name = p.cluster_name AND n.name = p.spec_node_name WHERE p.tags->'service' IS NOT NULL" > "$tmp"; then
    jq -c '{hostname:.node, aliases:[],
            ips:([.node_ip, .pod_ip] | map(select(. != null and . != "")) | unique),
            services:[.service], data_source:"ddsql"}
           | select(.hostname != null and .hostname != "")' "$tmp" >> "${cache}/hosts.ndjson"
    nk="$(wc -l < "$tmp" | tr -d ' ')"
    dim "  DDSQL: ${nrs} repo->service and ${nk} service->node rows merged"
  else
    warn "DDSQL k8s query failed - repo->service added, but service->host from k8s skipped."
  fi
  rm -f "$tmp"
}
