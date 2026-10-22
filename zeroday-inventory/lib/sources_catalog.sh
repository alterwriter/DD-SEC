#!/usr/bin/env bash
# sources_catalog.sh - Software Catalog -> service -> {languages, repo}.
# Fallback for repo<->service mapping when APM spans don't carry a git URL.
#
# Output rows: {service, languages[], repo, data_source:"catalog"}

# fetch_catalog OUT_NDJSON
fetch_catalog() {
  local out="$1"
  local raw="${CACHE_DIR}/catalog_services.json"
  : > "$out"

  progress "[6/6]" "Software Catalog (kind=service)"
  if ! dd_paginate_v2 "/api/v2/catalog/entity?filter%5Bkind%5D=service" "$raw" "catalog"; then
    warn "Catalog fetch failed (HTTP ${HTTP_CODE}); continuing"
    return 0
  fi

  jq -c '
    def norm_repo($u):
      ($u // "") | ascii_downcase
      | sub("^https?://";"") | sub("^[^@/]+@";"")
      | sub("\\.git$";"") | sub("/$";"");
    .[]?
    | (.attributes.name // .attributes.metadata.name // "") as $svc
    | ( [ .attributes.spec.languages[]?,
          .attributes.languages[]? ] | map(select(. != null)) | unique ) as $langs
    | ( [ (.attributes.metadata.links // .attributes.spec.links // [])[]?
          | select((.type // "" | ascii_downcase) == "repo"
                   or (.type // "" | ascii_downcase) == "repository")
          | .url ] | (.[0] // "") ) as $repo_url
    | { service: $svc, languages: $langs, repo: norm_repo($repo_url),
        data_source: "catalog" }
    | select(.service != "")
  ' "$raw" > "$out" 2>/dev/null || : > "$out"

  dim "  catalog services: $(wc -l < "$out" | tr -d ' ')"
}
