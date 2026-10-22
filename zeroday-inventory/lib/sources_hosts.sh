#!/usr/bin/env bash
# sources_hosts.sh - /api/v1/hosts -> hostname + IPs.
#
# IPs are assembled best-effort from several places a host object may carry
# them (gohai network interfaces, aliases that look like IPs, ip-like tags),
# because no single field is reliably populated across environments.
#
# Output rows: {hostname, aliases[], ips[], data_source:"hosts"}

# fetch_hosts OUT_NDJSON
fetch_hosts() {
  local out="$1"
  local start=0 count=1000 page=1 maxpages=50 raw got
  : > "$out"

  while :; do
    raw="${CACHE_DIR}/hosts_${start}.json"
    progress "[5/6]" "Hosts (start=${start}, count=${count})"
    if ! dd_get "/api/v1/hosts?include_hosts_metadata=true&count=${count}&start=${start}"; then
      warn "Hosts fetch failed (HTTP ${HTTP_CODE}) at start=${start}"
      break
    fi
    printf '%s' "$HTTP_BODY" > "$raw"
    got="$(jq -r '(.host_list // []) | length' "$raw" 2>/dev/null || echo 0)"

    jq -c '
      def ip_re: "^[0-9]{1,3}(\\.[0-9]{1,3}){3}$";
      (.host_list // [])[]?
      | (.name // .host_name // "") as $h
      | ( [ .aliases[]? ] ) as $aliases
      | ( [
            # gohai network interfaces (gohai may be a JSON-encoded string)
            ( (.meta.gohai // null)
              | (if type=="string" then (try fromjson catch null) else . end)
              | (.network.interfaces // [])[]?
              | (.ipv4[]?, .ipv6[]?) ),
            # aliases that are literally IPv4 addresses
            ( .aliases[]? | select(test("^[0-9]{1,3}(\\.[0-9]{1,3}){3}$")) ),
            # ip-like tags (host:1.2.3.4 style or bare)
            ( .tags_by_source[]?[]? | select(test("[0-9]{1,3}(\\.[0-9]{1,3}){3}"))
              | capture("(?<ip>[0-9]{1,3}(\\.[0-9]{1,3}){3})").ip )
          ] | map(select(. != null and . != "")) | unique ) as $ips
      | ( [ .tags_by_source[]?[]? | select(startswith("service:")) | ltrimstr("service:") ]
          | map(select(. != "")) | unique ) as $services
      | { hostname: $h, aliases: $aliases, ips: $ips, services: $services, data_source: "hosts" }
      | select(.hostname != "")
    ' "$raw" >> "$out" 2>/dev/null || true

    page=$(( page + 1 ))
    [ "${got:-0}" -ge "$count" ] || break
    [ "$page" -le "$maxpages" ] || { warn "Hosts: hit ${maxpages}-page safety cap"; break; }
    start=$(( start + count ))
  done

  dim "  hosts: $(wc -l < "$out" | tr -d ' ')"
}
