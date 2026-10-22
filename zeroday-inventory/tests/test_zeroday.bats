#!/usr/bin/env bats
# Tests for zeroday.sh. Run with bats-core:  bats tests/
# No live API calls: sources are mocked and the join runs on fixtures.

setup() {
  ROOT="$(cd "$BATS_TEST_DIRNAME/.." && pwd)"
  MATCHERS_FILE="$ROOT/matchers.json"; export MATCHERS_FILE
  TMP="$(mktemp -d)"
  # quiet ui helpers so output stays clean under bats
  info(){ :; }; step(){ :; }; ok(){ :; }; warn(){ :; }; dim(){ :; }; hdr(){ :; }; progress(){ :; }
  export -f info step ok warn dim hdr progress 2>/dev/null || true
}
teardown() { rm -rf "$TMP"; }

# ---------- .env parsing (safe, no code execution) --------------------------
@test "load_env_file reads allowlisted keys and ignores others" {
  . "$ROOT/lib/ui.sh"; . "$ROOT/lib/env.sh"
  cat > "$TMP/.env" <<EOF
DD_SITE=ap1.datadoghq.com
DD_API_KEY=abc123
UNKNOWN_KEY=should_be_ignored
DEFAULT_SCOPE=js
EOF
  unset DD_SITE DD_API_KEY DEFAULT_SCOPE UNKNOWN_KEY
  load_env_file "$TMP/.env"
  [ "$DD_SITE" = "ap1.datadoghq.com" ]
  [ "$DD_API_KEY" = "abc123" ]
  [ "$DEFAULT_SCOPE" = "js" ]
  [ -z "${UNKNOWN_KEY:-}" ]
}

@test "load_env_file does not execute shell code in values" {
  . "$ROOT/lib/ui.sh"; . "$ROOT/lib/env.sh"
  printf 'DD_API_KEY=$(touch %s/pwned)\n' "$TMP" > "$TMP/.env"
  unset DD_API_KEY
  load_env_file "$TMP/.env"
  [ ! -f "$TMP/pwned" ]                       # command must NOT have run
  [ "$DD_API_KEY" = '$(touch '"$TMP"'/pwned)' ] # value kept literally
}

@test "load_env_file does not overwrite an already-set env var" {
  . "$ROOT/lib/ui.sh"; . "$ROOT/lib/env.sh"
  printf 'DD_SITE=fromfile\n' > "$TMP/.env"
  DD_SITE=fromenv
  load_env_file "$TMP/.env"
  [ "$DD_SITE" = "fromenv" ]
}

# ---------- rkey repo normalization -----------------------------------------
rkey() { # STRING -> last two path segments, normalized
  jq -rn --arg r "$1" '
    ($r) | ascii_downcase | sub("\\.git$";"") | sub("/$";"")
    | (split("/") | if length>=2 then (.[-2]+"/"+.[-1]) else (.[-1]//"") end)'
}

@test "rkey collapses git URL and plain name to the same key" {
  [ "$(rkey "https://github.com/acme/webapp.git")" = "acme/webapp" ]
  [ "$(rkey "git@github.com:acme/webapp.git")" = "acme/webapp" ]  # strip handled upstream; here no creds
  [ "$(rkey "github.com/acme/webapp")" = "acme/webapp" ]
}

@test "rkey keeps last two segments for gitlab subgroups" {
  [ "$(rkey "gitlab.example.com/group/subgroup/project")" = "subgroup/project" ]
}

# ---------- purl matching ----------------------------------------------------
match_js() { # PURL -> "1" if it matches a JS prefix, else "0"
  jq -rn --arg p "$1" --argjson pre "$(jq -c '.js.purl_prefixes' "$MATCHERS_FILE")" '
    if any($pre[]; . as $x | ($p|ascii_downcase)|startswith($x|ascii_downcase)) then "1" else "0" end'
}
match_php() {
  jq -rn --arg p "$1" --argjson pre "$(jq -c '.php.purl_prefixes' "$MATCHERS_FILE")" '
    if any($pre[]; . as $x | ($p|ascii_downcase)|startswith($x|ascii_downcase)) then "1" else "0" end'
}

@test "JS matchers hit next / react / nuxt, miss unrelated npm" {
  [ "$(match_js "pkg:npm/next@14.2.1")" = "1" ]
  [ "$(match_js "pkg:npm/react-dom@18.2.0")" = "1" ]
  [ "$(match_js "pkg:npm/@nuxt/kit@3.1.0")" = "1" ]
  [ "$(match_js "pkg:npm/lodash@4.17.21")" = "0" ]
}

@test "PHP matcher hits any composer package" {
  [ "$(match_php "pkg:composer/laravel/framework@11.0")" = "1" ]
  [ "$(match_php "pkg:npm/next@14")" = "0" ]
}

# ---------- join logic -------------------------------------------------------
@test "join maps repo->service->host->ip and lists unmapped repos" {
  . "$ROOT/lib/ui.sh"; . "$ROOT/lib/join.sh"
  cp "$ROOT"/tests/fixtures/join/*.ndjson "$TMP"/
  build_reports "$TMP" "$TMP/report" "prod" ""
  # webapp resolves to host-1 with both IPs joined
  grep -q '"10.0.0.5;10.0.0.6","host-1","github.com/acme/webapp"' "$TMP/report/inventory.csv"
  # php host-runtime shows up as its own asset
  grep -q '"10.0.0.9","host-2","","PHP"' "$TMP/report/inventory.csv"
  # legacy repo has a match but no host -> unmapped
  grep -q 'github.com/acme/legacy' "$TMP/report/unmapped.csv"
  [ "$INV_COUNT" -eq 2 ]
  [ "$UNMAP_COUNT" -eq 1 ]
}

@test "CVE filter keeps only assets present in vuln results" {
  . "$ROOT/lib/ui.sh"; . "$ROOT/lib/join.sh"
  cp "$ROOT"/tests/fixtures/join/*.ndjson "$TMP"/
  build_reports "$TMP" "$TMP/report" "prod" "CVE-2025-1234"
  # legacy (react) is not in the CVE results -> dropped entirely
  ! grep -q 'legacy' "$TMP/report/details.csv"
  # php host-runtime has no CVE link -> dropped under a CVE filter
  ! grep -q 'php8.2' "$TMP/report/details.csv"
  grep -q 'CVE-2025-1234' "$TMP/report/details.csv"
  [ "$INV_COUNT" -eq 1 ]
}

# ---------- pagination (mocked transport) -----------------------------------
@test "dd_paginate_v2 follows links.next and accumulates pages" {
  . "$ROOT/lib/ui.sh"; . "$ROOT/lib/dd_api.sh"
  # Mock the transport: page 1 has links.next, page 2 ends it.
  dd_request_retry() {
    if [[ "$2" == *"cursor=PAGE2"* ]]; then
      HTTP_CODE=200
      HTTP_BODY='{"data":[{"id":"c"}],"links":{}}'
    else
      HTTP_CODE=200
      HTTP_BODY='{"data":[{"id":"a"},{"id":"b"}],"links":{"next":"https://api.x/foo?cursor=PAGE2"}}'
    fi
    return 0
  }
  CACHE_DIR="$TMP"; export CACHE_DIR
  dd_paginate_v2 "/foo" "$TMP/acc.json" "test"
  [ "$(jq 'length' "$TMP/acc.json")" -eq 3 ]
  [ "$(jq -r '.[-1].id' "$TMP/acc.json")" = "c" ]
}
