#!/usr/bin/env bash
# =============================================================================
# zeroday.sh - Zero-Day Blast Radius asset inventory (Datadog API -> Excel)
#
# Interactive, read-only. Given a CVE (or a package scope), it inventories which
# of YOUR assets run the affected packages, by querying your own Datadog org with
# your own API + Application keys, and writes an Excel report.
#
#   ./zeroday.sh                         interactive
#   ./zeroday.sh --non-interactive ...   for cron / CI (see --help)
#
# Part of the DD-SEC toolset. Read-only; needs only *_read scopes.
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib/ui.sh
. "${SCRIPT_DIR}/lib/ui.sh"
# shellcheck source=lib/dd_api.sh
. "${SCRIPT_DIR}/lib/dd_api.sh"
# shellcheck source=lib/env.sh
. "${SCRIPT_DIR}/lib/env.sh"
# shellcheck source=lib/sources_sbom.sh
. "${SCRIPT_DIR}/lib/sources_sbom.sh"
# shellcheck source=lib/sources_vulns.sh
. "${SCRIPT_DIR}/lib/sources_vulns.sh"
# shellcheck source=lib/sources_spans.sh
. "${SCRIPT_DIR}/lib/sources_spans.sh"
# shellcheck source=lib/sources_hosts.sh
. "${SCRIPT_DIR}/lib/sources_hosts.sh"
# shellcheck source=lib/sources_catalog.sh
. "${SCRIPT_DIR}/lib/sources_catalog.sh"
# shellcheck source=lib/sources_ddsql.sh
. "${SCRIPT_DIR}/lib/sources_ddsql.sh"
# shellcheck source=lib/join.sh
. "${SCRIPT_DIR}/lib/join.sh"
# shellcheck source=lib/export.sh
. "${SCRIPT_DIR}/lib/export.sh"

export SCRIPT_DIR
MATCHERS_FILE="${SCRIPT_DIR}/matchers.json"
export MATCHERS_FILE

# ---- defaults / state -------------------------------------------------------
INTERACTIVE=1
ENV_FILE="${SCRIPT_DIR}/.env"
SCOPE="" ; SCOPE_JS=0 ; SCOPE_PHP=0
CVE_IDS="" ; ENV_FILTER="" ; LOOKBACK="" ; OUTPUT="" ; USE_CACHE=0 ; SKIP_REPO_SBOM=0
PKG_FILTER="" ; AFFECTED_BELOW=""
TMP_ROOT=""

cleanup() {
  [ -t 0 ] && stty echo 2>/dev/null || true
  [ -n "$TMP_ROOT" ] && rm -rf "$TMP_ROOT" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

usage() {
  cat >&2 <<'EOF'
zeroday.sh - Zero-Day Blast Radius asset inventory (Datadog -> Excel)

USAGE
  ./zeroday.sh                                 interactive
  ./zeroday.sh --non-interactive --scope js --package next --affected-below 14.2.5 \
               --output out.xlsx

OPTIONS
  --api-key KEY        Datadog API key   (else env DD_API_KEY, .env, or prompt)
  --app-key KEY        Datadog App key   (else env DD_APP_KEY, .env, or prompt)
  --site SITE          e.g. datadoghq.com, ap1.datadoghq.com (else prompt)
  --env-file PATH      .env to load (default: ./.env)
  --scope LIST         js | php | js,php                      (default js,php)
  --package LIST       target package(s), comma-separated (empty = all matching)
  --affected-below VER keep only versions strictly below VER (the fixed-in
                       version) - this is how you scope a zero-day, from SBOM data
  --cve LIST           DEPRECATED/no-op: Datadog's vuln API is unavailable here;
                       use --package / --affected-below instead
  --env ENV            APM env filter, e.g. prod              (default: all)
  --lookback WINDOW    APM lookback, e.g. now-7d              (default now-7d)
  --output FILE        output .xlsx (default zero_day_inventory_<ts>.xlsx)
  --use-cache          reuse the most recent ./cache/<ts> instead of fetching
  --no-repo-sbom       skip Repository SBOMs (faster); host-resolved inventory
                       comes from Service SBOMs + host service: tags anyway
  --non-interactive    no prompts; fail fast if a credential is missing
  --help               this help

OUTPUT (.xlsx, 3 sheets)
  inventory: ip, hostname, repo, prog_lang
  details  : + framework, package, version, service, env, cve_ids, severity,
             fix_version, data_source, confidence
  unmapped : repos with matching packages but no resolvable host/IP

Read-only. Required app-key scopes: appsec_vm_read, apm_read, hosts_read,
apm_service_catalog_read. A dedicated service-account key is recommended.
EOF
}

# ---- arg parsing ------------------------------------------------------------
while [ $# -gt 0 ]; do
  case "$1" in
    --api-key) DD_API_KEY="${2:-}"; shift 2 ;;
    --app-key) DD_APP_KEY="${2:-}"; shift 2 ;;
    --site) DD_SITE="${2:-}"; shift 2 ;;
    --env-file) ENV_FILE="${2:-}"; shift 2 ;;
    --scope) SCOPE="${2:-}"; shift 2 ;;
    --cve) CVE_IDS="${2:-}"; shift 2 ;;
    --package) PKG_FILTER="${2:-}"; shift 2 ;;
    --affected-below) AFFECTED_BELOW="${2:-}"; shift 2 ;;
    --env) ENV_FILTER="${2:-}"; shift 2 ;;
    --lookback) LOOKBACK="${2:-}"; shift 2 ;;
    --output) OUTPUT="${2:-}"; shift 2 ;;
    --use-cache) USE_CACHE=1; shift ;;
    --no-repo-sbom) SKIP_REPO_SBOM=1; shift ;;
    --non-interactive) INTERACTIVE=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "Unknown argument: $1  (see --help)" ;;
  esac
done
export DD_API_KEY DD_APP_KEY DD_SITE CVE_IDS ENV_FILTER LOOKBACK

# ---- dependency check -------------------------------------------------------
check_deps() {
  local missing=""
  command -v curl >/dev/null 2>&1 || missing="$missing curl"
  command -v jq   >/dev/null 2>&1 || missing="$missing jq"
  if [ -n "$missing" ]; then
    warn "Missing required dependency:$missing"
    dim "  macOS : brew install${missing}"
    dim "  Debian: sudo apt install -y${missing}"
    dim "  RHEL  : sudo yum install -y${missing}"
    exit 1
  fi
  if command -v python3 >/dev/null 2>&1 && python3 -c 'import openpyxl' >/dev/null 2>&1; then
    dim "  xlsx engine: python3 + openpyxl"
  elif command -v libreoffice >/dev/null 2>&1; then
    dim "  xlsx engine: libreoffice (single-sheet fallback)"
  else
    warn "No xlsx engine (openpyxl/libreoffice) - will emit CSV only."
    dim "  pip install openpyxl   # for a formatted 3-sheet workbook"
  fi
}

# ---- scope resolution -------------------------------------------------------
apply_scope() {
  local s="$1"
  SCOPE_JS=0; SCOPE_PHP=0
  case ",$s," in *",js,"*) SCOPE_JS=1 ;; esac
  case ",$s," in *",php,"*) SCOPE_PHP=1 ;; esac
  [ "$SCOPE_JS" = "1" ] || [ "$SCOPE_PHP" = "1" ] || die "Invalid --scope '$s' (want js | php | js,php)"
}

# ---- interactive scan options ----------------------------------------------
interactive_options() {
  local pick
  pick="$(menu "Scan scope" \
    "js,php:JS + PHP (default)" \
    "js:JS only (next / nuxt / react)" \
    "php:PHP only (composer apps)")" || die "cancelled"
  SCOPE="$pick"

  PKG_FILTER="$(ask "Target package(s) for a zero-day, comma-separated (empty = all matching)" "${PKG_FILTER:-}")"
  AFFECTED_BELOW="$(ask "Affected if version is below (the fixed-in version; empty = any version)" "${AFFECTED_BELOW:-}")"
  ENV_FILTER="$(ask "APM env filter (empty = all)" "${ENV_FILTER:-${DEFAULT_ENV:-}}")"
  LOOKBACK="$(ask "APM lookback" "${LOOKBACK:-${DEFAULT_LOOKBACK:-now-7d}}")"
  OUTPUT="$(ask "Output filename" "${OUTPUT:-zero_day_inventory_$(date +%Y%m%d_%H%M).xlsx}")"
  if confirm "Reuse cached API responses from the last run?" n; then USE_CACHE=1; fi
}

# ---- cache / log dirs -------------------------------------------------------
setup_run_dirs() {
  local ts; ts="$(date +%Y%m%d_%H%M%S)"
  mkdir -p "${SCRIPT_DIR}/cache" "${SCRIPT_DIR}/logs"
  if [ "$USE_CACHE" = "1" ]; then
    CACHE_DIR="$(ls -dt "${SCRIPT_DIR}"/cache/*/ 2>/dev/null | head -1)"
    [ -n "$CACHE_DIR" ] || die "--use-cache set but no previous cache under ./cache/"
    CACHE_DIR="${CACHE_DIR%/}"
    warn "Reusing cache: $CACHE_DIR (no API calls will be made)"
  else
    CACHE_DIR="${SCRIPT_DIR}/cache/${ts}"
    mkdir -p "$CACHE_DIR"
  fi
  LOG_FILE="${SCRIPT_DIR}/logs/run_${ts}.log"
  : > "$LOG_FILE"; chmod 600 "$LOG_FILE" 2>/dev/null || true
  export CACHE_DIR LOG_FILE
}

# ---- fetch all sources ------------------------------------------------------
run_fetch() {
  [ "$USE_CACHE" = "1" ] && { dim "  (cache mode: skipping all API fetches)"; return 0; }
  if [ "$SKIP_REPO_SBOM" = "1" ]; then
    dim "  (skipping Repository SBOMs: --no-repo-sbom)"; : > "${CACHE_DIR}/sbom_repo.ndjson"
  else
    fetch_sbom_repo  "$SCOPE_JS" "$SCOPE_PHP" "${CACHE_DIR}/sbom_repo.ndjson"
  fi
  fetch_sbom_service "$SCOPE_JS" "$SCOPE_PHP" "${CACHE_DIR}/sbom_service.ndjson"
  fetch_sbom_host    "$SCOPE_PHP" "${CACHE_DIR}/sbom_host.ndjson"
  fetch_vulns     "$SCOPE_JS" "$SCOPE_PHP" "${CACHE_DIR}/vulns.ndjson"
  fetch_spans     "$SCOPE_JS" "$SCOPE_PHP" "${CACHE_DIR}/spans.ndjson"
  fetch_hosts     "${CACHE_DIR}/hosts.ndjson"
  fetch_catalog   "${CACHE_DIR}/catalog.ndjson"
  # DDSQL bridge LAST: it appends repo->service + service->node/ip into the
  # spans/hosts NDJSON above, so the join resolves hosts the REST path cannot.
  fetch_ddsql     "${CACHE_DIR}"
}

# ---- main -------------------------------------------------------------------
main() {
  hdr "zeroday.sh - Zero-Day Blast Radius inventory"
  check_deps

  load_env_file "$ENV_FILE"
  : "${SCOPE:=${DEFAULT_SCOPE:-js,php}}"
  : "${LOOKBACK:=${DEFAULT_LOOKBACK:-now-7d}}"
  : "${ENV_FILTER:=${DEFAULT_ENV:-}}"

  local creds_were_prompted=0
  if [ -z "${DD_API_KEY:-}" ] || [ -z "${DD_APP_KEY:-}" ] || [ -z "${DD_SITE:-}" ]; then
    [ "$INTERACTIVE" = "1" ] && creds_were_prompted=1
  fi
  resolve_credentials "$INTERACTIVE"
  export DD_API_KEY DD_APP_KEY DD_SITE

  if [ "$INTERACTIVE" = "1" ] && [ "$creds_were_prompted" = "1" ]; then
    if confirm "Save credentials to ${ENV_FILE}?" n; then save_env_file "$ENV_FILE"; fi
  fi

  if [ "$INTERACTIVE" = "1" ]; then
    interactive_options
  fi
  apply_scope "$SCOPE"
  [ -n "$OUTPUT" ] || OUTPUT="zero_day_inventory_$(date +%Y%m%d_%H%M).xlsx"

  [ -z "$CVE_IDS" ] || warn "Note: --cve has no effect (Datadog vulnerability API is deprecated/forbidden here). Use --package / --affected-below to target a zero-day from SBOM data."

  hdr "Run summary"
  info "  Site      : ${DD_SITE}"
  info "  Scope     : ${SCOPE}  (js=${SCOPE_JS} php=${SCOPE_PHP})"
  info "  Package   : ${PKG_FILTER:-<all matching>}"
  info "  Affected< : ${AFFECTED_BELOW:-<any version>}"
  info "  Env filter: ${ENV_FILTER:-<all>}"
  info "  Lookback  : ${LOOKBACK}"
  info "  Output    : ${OUTPUT}"
  info "  Cache     : $([ "$USE_CACHE" = 1 ] && echo reuse-latest || echo fresh)"
  if [ "$INTERACTIVE" = "1" ]; then
    confirm "Proceed?" y || { warn "Aborted by user."; exit 0; }
  fi

  setup_run_dirs
  export CVE_IDS ENV_FILTER LOOKBACK
  run_fetch

  hdr "Joining sources"
  local outdir="${CACHE_DIR}/report"
  build_reports "$CACHE_DIR" "$outdir" "$ENV_FILTER" "$CVE_IDS" "$PKG_FILTER" "$AFFECTED_BELOW" || die "join failed"

  hdr "Exporting"
  export_xlsx "$OUTPUT" "$outdir"

  hdr "Done"
  info "  Assets (inventory rows) : ${INV_COUNT:-0}"
  info "  Detail rows             : ${DET_COUNT:-0}"
  info "  Unmapped repos          : ${UNMAP_COUNT:-0}"
  info "  Report CSVs             : ${outdir}/"
  info "  Log                     : ${LOG_FILE}"
  [ -f "$OUTPUT" ] && info "  Workbook                : ${OUTPUT}"
  ok "Complete."
}

main "$@"
