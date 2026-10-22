#!/usr/bin/env bash
# sources_vulns.sh - Datadog vulnerabilities -> normalized NDJSON.
#
# We fetch AdvisoryVulnerability records and match them CLIENT-SIDE against the
# matchers and the optional CVE/GHSA list. Server-side library/CVE filter names
# are not all verified in the spec, so client-side matching keeps results
# correct regardless; narrow server-side later once params are confirmed.
#
# Output rows: {asset_name, asset_type, repo, package, version, cve_ids[],
#               severity, fix_version, data_source:"vulns"}

# fetch_vulns SCOPE_JS SCOPE_PHP OUT_NDJSON  (CVE list via $CVE_IDS, comma sep)
fetch_vulns() {
  local js="$1" php="$2" out="$3"
  local raw="${CACHE_DIR}/vulnerabilities.json"
  local path="/api/v2/security/vulnerabilities?filter%5Btype%5D=AdvisoryVulnerability"

  progress "[3/6]" "Vulnerabilities (AdvisoryVulnerability)"
  if ! dd_paginate_v2 "$path" "$raw" "vulns"; then
    warn "Vulnerability fetch failed; continuing"
    : > "$out"; return 0
  fi

  # JS library-name prefixes derived from the npm matcher purls.
  local js_names
  js_names="$(jq -c '[.js.purl_prefixes[] | ltrimstr("pkg:npm/")]' "$MATCHERS_FILE")"

  # CVE/GHSA ids as a lowercased jq array (empty = match any).
  local cve_json="[]"
  if [ -n "${CVE_IDS:-}" ]; then
    cve_json="$(printf '%s' "$CVE_IDS" | tr ',' '\n' \
      | jq -R 'select(length>0) | ascii_downcase | gsub("^[[:space:]]+|[[:space:]]+$";"")' \
      | jq -sc '.')"
  fi

  jq -c \
    --argjson want_js "$js" --argjson want_php "$php" \
    --argjson js_names "$js_names" --argjson cves "$cve_json" \
    --arg js_lang "$(jq -r '.js.prog_lang' "$MATCHERS_FILE")" \
    --arg php_lang "$(jq -r '.php.prog_lang' "$MATCHERS_FILE")" '
    # candidate field accessors across schema variants
    def lib_name: (.attributes.library.name // .attributes.package.name
                   // .attributes.library_name // "");
    def lib_eco:  (.attributes.library.ecosystem // .attributes.ecosystem
                   // .attributes.package.ecosystem // "") | ascii_downcase;
    def lib_ver:  (.attributes.library.version // .attributes.package.version
                   // .attributes.version // "");
    def sev:      (.attributes.cvss.base.severity // .attributes.severity // "") ;
    def fixver:   (.attributes.first_patched_version
                   // .attributes.fix.version // .attributes.fix_version // "");
    def cvelist:  ( [ (.attributes.cve_list // .attributes.cve_ids // [])[]?,
                      (.attributes.advisories // [])[]?.cve_id?,
                      .attributes.advisory_id?, .attributes.cve? ]
                    | map(select(. != null and . != "")) | unique );
    def assetname: (.attributes.asset.name
                    // .relationships.asset.data.id // "");
    def assettype: (.attributes.asset.type
                    // .relationships.asset.data.type // "");

    .[]?
    | lib_name as $name | lib_eco as $eco | cvelist as $cl
    | (if ($eco=="npm" or $eco=="node")
         and ($want_js==1)
         and (any($js_names[]; . as $pre | ($name|ascii_downcase) | startswith($pre|ascii_downcase)))
       then $js_lang
       elif ($eco=="composer" or $eco=="packagist") and ($want_php==1)
       then $php_lang
       else null end) as $lang
    | select($lang != null)
    # CVE filter: if a list was given, require an intersection
    | select( ($cves|length)==0
              or (any($cl[]; ($cves | index(ascii_downcase)) != null)) )
    | { asset_name: assetname, asset_type: assettype, repo: assetname,
        package: $name, version: lib_ver, cve_ids: $cl,
        severity: sev, fix_version: fixver, prog_lang: $lang,
        data_source: "vulns" }
  ' "$raw" > "$out" 2>/dev/null || : > "$out"

  dim "  vulnerability matches: $(wc -l < "$out" | tr -d ' ')"
}
