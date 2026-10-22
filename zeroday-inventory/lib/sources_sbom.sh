#!/usr/bin/env bash
# sources_sbom.sh - Repository and Host SBOMs -> normalized NDJSON.
#
# Datadog SBOM payloads are CycloneDX. The exact JSON paths differ by API
# version, so extraction tries several candidate paths and is defensive: an
# unexpected shape yields zero rows loudly (a warning), never a silent success.
#
# NOTE: verify filter params and response schema against
#   https://docs.datadoghq.com/api/latest/  before relying on results.

# jq program: given a CycloneDX doc + matcher config, emit matched components.
# Shared by repo and host extraction; $kind selects which matcher set to apply.
_SBOM_JQ='
  # candidate component list across schema variants
  def comps: (.attributes.components
              // .attributes.bom.components
              // .attributes.cyclonedx.components
              // .attributes.sbom.components // []);
  # asset/repo identity across variants. In the live API the identifier is the
  # top-level .id (e.g. a repo host/group/project path or a hostname); attribute
  # paths are tried first in case a nicer name is present, then .id as the
  # reliable fallback.
  def asset_name: (.attributes.asset.name
                   // .attributes.repository.name
                   // .attributes.name
                   // .attributes.asset_name
                   // .id // "");
  def match_prefix($purl; $prefixes):
    ($purl | ascii_downcase) as $p
    | any($prefixes[]; . as $pre | $p | startswith($pre | ascii_downcase));
  def framework_of($purl; $fw):
    ($purl | ascii_downcase) as $p
    | [ $fw | to_entries[]
        | select(any(.value[]; . as $pre | $p | startswith($pre|ascii_downcase)))
        | .key ] | (.[0] // "");
'

# fetch_sbom_repo SCOPE_JS(0|1) SCOPE_PHP(0|1) OUT_NDJSON
fetch_sbom_repo() {
  local js="$1" php="$2" out="$3"
  local raw; raw="${CACHE_DIR}/sbom_repository.json"
  progress "[1/6]" "Repository SBOMs (filter[asset_type]=Repository)"
  if ! dd_paginate_v2 "/api/v2/security/sboms?filter%5Basset_type%5D=Repository" "$raw" "sbom:repo"; then
    warn "Repository SBOM fetch failed; continuing with what we have"
    : > "$out"; return 0
  fi

  local jsp phpp
  jsp="$(jq -c '.js.purl_prefixes' "$MATCHERS_FILE")"
  phpp="$(jq -c '.php.purl_prefixes' "$MATCHERS_FILE")"

  jq -c \
    --argjson want_js "$js" --argjson want_php "$php" \
    --argjson js_pre "$jsp" --argjson php_pre "$phpp" \
    --argjson js_fw "$(jq -c '.js.frameworks' "$MATCHERS_FILE")" \
    --argjson php_fw "$(jq -c '.php.frameworks' "$MATCHERS_FILE")" \
    --arg js_lang "$(jq -r '.js.prog_lang' "$MATCHERS_FILE")" \
    --arg php_lang "$(jq -r '.php.prog_lang' "$MATCHERS_FILE")" \
    "$_SBOM_JQ"'
    .[]? | asset_name as $repo | comps as $cs
    | $cs[]? | (.purl // "") as $purl | select($purl != "")
    | (.name // "") as $pkg | (.version // "") as $ver
    | if ($want_js==1 and match_prefix($purl; $js_pre)) then
        {repo:$repo, purl:$purl, package:$pkg, version:$ver,
         framework: framework_of($purl; $js_fw), prog_lang:$js_lang,
         data_source:"sbom_repo"}
      elif ($want_php==1 and match_prefix($purl; $php_pre)) then
        {repo:$repo, purl:$purl, package:$pkg, version:$ver,
         framework: framework_of($purl; $php_fw), prog_lang:$php_lang,
         data_source:"sbom_repo"}
      else empty end
  ' "$raw" > "$out" 2>/dev/null || : > "$out"

  dim "  repo SBOM matches: $(wc -l < "$out" | tr -d ' ')"
}

# fetch_sbom_service SCOPE_JS(0|1) SCOPE_PHP(0|1) OUT_NDJSON
# Per-SERVICE SBOMs. The component list is identical to repo SBOMs, but the asset
# (.id) is a SERVICE NAME. This is the key to host resolution in orgs where repos
# don't map to services: service -> package here, then service -> host via host
# `service:` tags, then host -> ip. No repo-key matching needed.
fetch_sbom_service() {
  local js="$1" php="$2" out="$3"
  local raw; raw="${CACHE_DIR}/sbom_service.json"
  : > "$out"
  progress "[2/6]" "Service SBOMs (filter[asset_type]=Service)"
  if ! dd_paginate_v2 "/api/v2/security/sboms?filter%5Basset_type%5D=Service" "$raw" "sbom:service"; then
    warn "Service SBOM fetch failed; host mapping may be incomplete"
    return 0
  fi

  jq -c \
    --argjson want_js "$js" --argjson want_php "$php" \
    --argjson js_pre "$(jq -c '.js.purl_prefixes' "$MATCHERS_FILE")" \
    --argjson php_pre "$(jq -c '.php.purl_prefixes' "$MATCHERS_FILE")" \
    --argjson js_fw "$(jq -c '.js.frameworks' "$MATCHERS_FILE")" \
    --argjson php_fw "$(jq -c '.php.frameworks' "$MATCHERS_FILE")" \
    --arg js_lang "$(jq -r '.js.prog_lang' "$MATCHERS_FILE")" \
    --arg php_lang "$(jq -r '.php.prog_lang' "$MATCHERS_FILE")" \
    "$_SBOM_JQ"'
    .[]? | asset_name as $svc | comps as $cs
    | $cs[]? | (.purl // "") as $purl | select($purl != "")
    | (.name // "") as $pkg | (.version // "") as $ver
    | if ($want_js==1 and match_prefix($purl; $js_pre)) then
        {service:$svc, purl:$purl, package:$pkg, version:$ver,
         framework: framework_of($purl; $js_fw), prog_lang:$js_lang,
         data_source:"sbom_service"}
      elif ($want_php==1 and match_prefix($purl; $php_pre)) then
        {service:$svc, purl:$purl, package:$pkg, version:$ver,
         framework: framework_of($purl; $php_fw), prog_lang:$php_lang,
         data_source:"sbom_service"}
      else empty end
  ' "$raw" > "$out" 2>/dev/null || : > "$out"

  dim "  service SBOM matches: $(wc -l < "$out" | tr -d ' ')"
}

# fetch_sbom_host SCOPE_PHP(0|1) OUT_NDJSON
# Host/Image SBOMs carry OS packages; we only look for the PHP runtime here
# (host runtime PHP implies a PHP asset even without a repo mapping).
fetch_sbom_host() {
  local php="$1" out="$2"
  : > "$out"
  [ "$php" = "1" ] || { dim "  (host SBOM skipped: PHP not in scope)"; return 0; }

  local atype raw nameglob rtpre phplang
  nameglob="$(jq -r '.php.host_runtime_name_glob' "$MATCHERS_FILE")"
  rtpre="$(jq -c '.php.host_runtime_prefixes' "$MATCHERS_FILE")"
  phplang="$(jq -r '.php.prog_lang' "$MATCHERS_FILE")"

  for atype in Host Image; do
    raw="${CACHE_DIR}/sbom_$(printf '%s' "$atype" | tr '[:upper:]' '[:lower:]').json"
    progress "[1/6]" "Host SBOMs (asset_type=${atype}, PHP runtime only)"
    if ! dd_paginate_v2 "/api/v2/security/sboms?filter%5Basset_type%5D=${atype}" "$raw" "sbom:${atype}"; then
      warn "${atype} SBOM fetch failed; skipping"
      continue
    fi
    jq -c \
      --argjson rt_pre "$rtpre" --arg glob "$nameglob" --arg lang "$phplang" \
      "$_SBOM_JQ"'
      .[]? | asset_name as $host | comps as $cs
      | $cs[]? | (.purl // "") as $purl | select($purl != "")
      | (.name // "") as $pkg | (.version // "") as $ver
      | select( (any($rt_pre[]; . as $pre | ($purl|ascii_downcase) | startswith($pre|ascii_downcase)))
                and ($pkg|ascii_downcase|startswith($glob)) )
      | {hostname:$host, purl:$purl, package:$pkg, version:$ver,
         framework:"", prog_lang:$lang, data_source:"hosts"}
    ' "$raw" >> "$out" 2>/dev/null || true
  done
  dim "  host PHP-runtime matches: $(wc -l < "$out" | tr -d ' ')"
}
