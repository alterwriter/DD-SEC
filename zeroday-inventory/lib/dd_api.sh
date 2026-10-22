#!/usr/bin/env bash
# dd_api.sh - Datadog HTTP layer: auth, retry, rate-limit, pagination, logging.
# Requires DD_SITE / DD_API_KEY / DD_APP_KEY in the environment. LOG_FILE and
# CACHE_DIR are optional (set by the orchestrator). ui.sh must be sourced first.

HTTP_CODE=""; HTTP_BODY=""; RL_RESET=""

# Redact anything key-shaped before it can reach a log. Defensive only; we also
# simply never pass keys to log_line.
_redact() { sed -E 's/([A-Fa-f0-9]{24,})/<redacted>/g'; }

log_line() {
  [ -n "${LOG_FILE:-}" ] || return 0
  printf '%s\t%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >> "$LOG_FILE"
}

api_base() { printf 'https://api.%s' "$DD_SITE"; }

# dd_request METHOD PATH [BODY]
# Sets HTTP_CODE, HTTP_BODY, RL_RESET. Returns 0 only on 2xx.
# Never logs headers, keys, or the request/response body.
dd_request() {
  local method="$1" path="$2" body="${3:-}"
  local hdrfile start dur url raw
  hdrfile="$(mktemp)"
  url="$(api_base)${path}"
  start="$(date +%s)"

  set -- -sS -X "$method" -D "$hdrfile" -o /dev/stdout -w '\n%{http_code}' \
         --connect-timeout 10 --max-time 60 --retry 0 \
         -H "DD-API-KEY: ${DD_API_KEY}" \
         -H "DD-APPLICATION-KEY: ${DD_APP_KEY}" \
         -H "Accept: application/json" \
         -H "User-Agent: zeroday-inventory"
  if [ -n "$body" ]; then
    set -- "$@" -H "Content-Type: application/json" --data-binary "$body"
  fi

  raw="$(curl "$@" "$url" 2>/dev/null)"
  HTTP_CODE="${raw##*$'\n'}"
  HTTP_BODY="${raw%$'\n'*}"
  RL_RESET="$(sed -n 's/^[Xx]-[Rr]ate[Ll]imit-[Rr]eset: *//p' "$hdrfile" | tr -d '\r' | tail -1)"
  rm -f "$hdrfile"
  dur="$(( $(date +%s) - start ))"
  [ -n "$HTTP_CODE" ] || HTTP_CODE="000"

  # Log method, path (query redacted of key-shaped tokens), status, duration.
  log_line "$(printf '%s %s %s %ss' "$method" "$(printf '%s' "$path" | _redact)" "$HTTP_CODE" "$dur")"

  case "$HTTP_CODE" in 2*) return 0 ;; *) return 1 ;; esac
}

# dd_request_retry METHOD PATH [BODY]
# 429 -> honour X-RateLimit-Reset. 5xx / connection fail -> exponential backoff.
# Other 4xx -> return immediately (retrying a validation error is pointless).
dd_request_retry() {
  local attempt=1 max=5 wait
  while :; do
    dd_request "$@" && return 0
    case "$HTTP_CODE" in
      429)
        wait="${RL_RESET:-}"
        case "$wait" in ''|*[!0-9]*) wait=$(( attempt * 5 )) ;; esac
        [ "$wait" -gt 120 ] && wait=120
        warn "Rate limited (429) - waiting ${wait}s [${attempt}/${max}]"
        sleep "$wait" ;;
      5*|000)
        wait=$(( 2 ** attempt ))
        [ "$wait" -gt 60 ] && wait=60
        warn "HTTP ${HTTP_CODE} - backing off ${wait}s [${attempt}/${max}]"
        sleep "$wait" ;;
      *) return 1 ;;
    esac
    attempt=$(( attempt + 1 ))
    [ "$attempt" -le "$max" ] || return 1
  done
}

dd_get()  { dd_request_retry GET  "$1"; }
dd_post() { dd_request_retry POST "$1" "$2"; }

# urlencode STRING
urlencode() { printf '%s' "$1" | jq -sRr @uri; }

# _pg_status LABEL PAGE TOTAL START PHASE
# One self-updating status line on a TTY (so hundreds of pages don't scroll);
# a periodic line otherwise. Shows stage, page, running record count, elapsed.
_pg_status() {
  local el=$(( $(date +%s) - $4 ))
  if [ -t 2 ]; then
    printf '\r\033[2K  %s · page %s · %s records · %ss' "$1" "$2" "$3" "$el" >&2
  else
    if [ $(( $2 % 20 )) -eq 0 ]; then
      printf '  %s · page %s · %s records · %ss\n' "$1" "$2" "$3" "$el" >&2
    fi
  fi
}

# dd_paginate_v2 PATH OUTFILE [LABEL]
# Accumulates `.data[]` from a v2 endpoint into a JSON array at OUTFILE,
# following `.links.next`. Prints progress. Caps pages defensively (the first
# response is often slow; later pages reuse the page token in links.next).
dd_paginate_v2() {
  local path="$1" out="$2" label="${3:-page}"
  local page=1 maxpages=200 tmp ndj next got total=0 start_ts
  tmp="$(mktemp)"; ndj="$(mktemp)"
  : > "$ndj"
  start_ts="$(date +%s)"

  while :; do
    _pg_status "$label" "$page" "$total" "$start_ts" fetching
    if ! dd_request_retry GET "$path"; then
      warn "${label}: HTTP ${HTTP_CODE} on page ${page}"
      printf '%s' "$(head -c 300 <<<"$HTTP_BODY" | _redact)" >&2; printf '\n' >&2
      rm -f "$tmp" "$ndj"; printf '[]' > "$out"
      return 1
    fi
    printf '%s' "$HTTP_BODY" > "$tmp"

    if ! jq -e 'has("data")' "$tmp" >/dev/null 2>&1; then
      warn "${label}: response has no .data array (schema change?) - stopping"
      break
    fi
    # Append this page's elements as NDJSON (one compact object per line). This is
    # an O(page) append, NOT a re-merge of everything seen so far, so total work
    # is linear in record count instead of quadratic in page count.
    if ! jq -c '.data[]?' "$tmp" >> "$ndj"; then
      warn "${label}: failed to read page ${page} (invalid JSON?) - stopping"
      break
    fi
    got="$(jq -r '(.data // []) | length' "$tmp")"
    total=$(( total + got ))
    _pg_status "$label" "$page" "$total" "$start_ts" ok

    next="$(jq -r '.links.next // ""' "$tmp" 2>/dev/null)"
    [ -n "$next" ] && [ "$next" != "null" ] && [ "$got" -gt 0 ] || break

    # links.next may be absolute; reduce to a path for api_base.
    case "$next" in
      https://*) path="/${next#https://*/}" ;;
      http://*)  path="/${next#http://*/}" ;;
      /*)        path="$next" ;;
      *)         path="/$next" ;;
    esac
    page=$(( page + 1 ))
    [ "$page" -le "$maxpages" ] || { warn "${label}: hit ${maxpages}-page safety cap"; break; }
  done
  [ -t 2 ] && printf '\n' >&2 || true   # close off the self-updating status line

  # One final pass wraps the NDJSON stream into the JSON array consumers expect.
  jq -s '.' "$ndj" > "$out" 2>/dev/null || printf '[]' > "$out"
  rm -f "$tmp" "$ndj"
  dim "  ${label}: ${total} record(s) across ${page} page(s)"
  return 0
}
