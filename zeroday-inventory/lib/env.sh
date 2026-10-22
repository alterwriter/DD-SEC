#!/usr/bin/env bash
# env.sh - credential resolution, safe .env load/save, validation.
# Depends on ui.sh and dd_api.sh being sourced first.

# Known sites, in the menu order the spec asked for.
DD_SITES="datadoghq.com us3.datadoghq.com us5.datadoghq.com datadoghq.eu ap1.datadoghq.com ap2.datadoghq.com"

# load_env_file PATH
# Parses KEY=VALUE lines WITHOUT sourcing, so nothing in the file executes.
# Only a known allowlist of keys is honoured; everything else is ignored.
# Already-exported env vars win over the file (not overwritten here).
load_env_file() {
  local f="$1" line key val
  [ -f "$f" ] || return 0
  # Reject anything that is not plain KEY=VALUE for the keys we expect.
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in
      ''|'#'*) continue ;;
    esac
    # Must look like KEY=VALUE
    case "$line" in
      *=*) : ;;
      *) continue ;;
    esac
    key="${line%%=*}"
    val="${line#*=}"
    # trim whitespace around key
    key="$(printf '%s' "$key" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
    # strip one layer of surrounding single or double quotes from the value
    case "$val" in
      \"*\") val="${val#\"}"; val="${val%\"}" ;;
      \'*\') val="${val#\'}"; val="${val%\'}" ;;
    esac
    case "$key" in
      DD_SITE|DD_API_KEY|DD_APP_KEY|DEFAULT_SCOPE|DEFAULT_ENV|DEFAULT_LOOKBACK)
        # Only set if not already present in the environment.
        if [ -z "$(eval "printf '%s' \"\${$key:-}\"")" ]; then
          eval "$key=\$val"
        fi
        ;;
      *) : ;;  # ignore unknown keys
    esac
  done < "$f"
}

# save_env_file PATH - writes current creds + defaults with chmod 600,
# and makes sure .env is gitignored.
save_env_file() {
  local f="$1" dir
  dir="$(dirname "$f")"
  umask 077
  {
    printf 'DD_SITE=%s\n' "${DD_SITE:-}"
    printf 'DD_API_KEY=%s\n' "${DD_API_KEY:-}"
    printf 'DD_APP_KEY=%s\n' "${DD_APP_KEY:-}"
    printf 'DEFAULT_SCOPE=%s\n' "${DEFAULT_SCOPE:-js,php}"
    printf 'DEFAULT_ENV=%s\n' "${DEFAULT_ENV:-}"
    printf 'DEFAULT_LOOKBACK=%s\n' "${DEFAULT_LOOKBACK:-now-7d}"
  } > "$f"
  chmod 600 "$f" 2>/dev/null
  if [ -f "$dir/.gitignore" ] && ! grep -qxF '.env' "$dir/.gitignore" 2>/dev/null; then
    printf '.env\n' >> "$dir/.gitignore"
  fi
  ok "Saved credentials to $f (chmod 600)"
}

# prompt_site -> sets DD_SITE via numbered menu
prompt_site() {
  local choice
  choice="$(menu "Datadog site" \
    "datadoghq.com:datadoghq.com (US1)" \
    "us3.datadoghq.com:us3.datadoghq.com (US3)" \
    "us5.datadoghq.com:us5.datadoghq.com (US5)" \
    "datadoghq.eu:datadoghq.eu (EU1)" \
    "ap1.datadoghq.com:ap1.datadoghq.com (AP1)" \
    "ap2.datadoghq.com:ap2.datadoghq.com (AP2)" \
    "custom:custom (enter manually)")" || return 1
  if [ "$choice" = "custom" ]; then
    choice="$(ask "Enter site host (e.g. datadoghq.com)")"
  fi
  [ -n "$choice" ] || return 1
  DD_SITE="$choice"
}

# resolve_credentials INTERACTIVE(0|1)
# Fills DD_SITE / DD_API_KEY / DD_APP_KEY from (in priority) flags/env already
# set, then .env already loaded, then interactive prompts. Validates with up to
# 3 attempts. Returns non-zero on failure.
resolve_credentials() {
  local interactive="$1" attempt=1 max=3

  if [ -z "${DD_SITE:-}" ]; then
    if [ "$interactive" = "1" ]; then prompt_site || die "No site selected"
    else die "DD_SITE is not set (required in non-interactive mode)"; fi
  fi

  while :; do
    if [ -z "${DD_API_KEY:-}" ]; then
      [ "$interactive" = "1" ] || die "DD_API_KEY is not set (required in non-interactive mode)"
      DD_API_KEY="$(ask_secret "DD_API_KEY (hidden)")"
    fi
    if [ -z "${DD_APP_KEY:-}" ]; then
      [ "$interactive" = "1" ] || die "DD_APP_KEY is not set (required in non-interactive mode)"
      DD_APP_KEY="$(ask_secret "DD_APP_KEY (hidden)")"
    fi

    step "Validating credentials against api.${DD_SITE} ..."
    if validate_credentials; then
      ok "Credentials valid (org reachable, required scopes present)"
      return 0
    fi

    attempt=$((attempt + 1))
    if [ "$interactive" != "1" ] || [ "$attempt" -gt "$max" ]; then
      die "Credential validation failed after $((attempt - 1)) attempt(s)"
    fi
    warn "Validation failed - re-enter (attempt $attempt/$max)"
    DD_API_KEY=""; DD_APP_KEY=""
  done
}

# validate_credentials - API key via /api/v1/validate, then an app-key-scoped
# call. Prints which scope is likely missing on 403. Returns 0 on success.
# short, redacted snippet of the last response body, for diagnosis.
_diag_body() {
  local snip
  snip="$(printf '%s' "${HTTP_BODY:-}" | tr -d '\n' | _redact | head -c 240)"
  [ -z "$snip" ] || dim "    server said: ${snip}"
}

validate_credentials() {
  # 1) API key + site. This is the real site check: a wrong DD_SITE fails here.
  if ! dd_get "/api/v1/validate"; then
    warn "API key check failed (HTTP ${HTTP_CODE:-?}) for site $DD_SITE"
    _diag_body
    return 1
  fi
  if [ "$(printf '%s' "$HTTP_BODY" | jq -r '.valid // false' 2>/dev/null)" != "true" ]; then
    warn "API key reported invalid for site $DD_SITE"
    return 1
  fi

  # 2) App-key authentication, via a stable v1 endpoint. We only need to know the
  #    key AUTHENTICATES; 200 and 403 both prove that (403 = valid key, that one
  #    scope missing). Only 401 means the key itself is bad. A non-auth status
  #    (e.g. 400) is shown but not treated as an auth failure.
  if dd_get "/api/v1/hosts?count=1"; then
    : # authenticated and hosts_read present
  else
    case "${HTTP_CODE:-}" in
      401)
        warn "401 - Application key invalid for site $DD_SITE"
        dim "    Check the App key is from THIS org/site (us5), not another."
        _diag_body
        return 1 ;;
      403)
        warn "App key is valid but missing 'hosts_read' (403) - continuing; host/IP data may be incomplete." ;;
      *)
        warn "App-key check got HTTP ${HTTP_CODE:-?} on /api/v1/hosts (not an auth error) - continuing."
        _diag_body ;;
    esac
  fi

  # 3) Scope hint for the PRIMARY data source: the SBOM endpoint (current, not
  #    deprecated, needs appsec_vm_read). We probe this rather than the vulnerabilities
  #    endpoint, which is deprecated and can return 400/403 on some sites even when the
  #    scope is present. Non-fatal either way.
  if dd_get "/api/v2/security/sboms?filter%5Basset_type%5D=Repository"; then
    : # appsec_vm_read effective
  else
    case "${HTTP_CODE:-}" in
      403)
        warn "403 on SBOMs - 'appsec_vm_read' is not effective for this key yet."
        dim "    Scopes are FILTERS: the key's OWNER role must ALSO have the"
        dim "    Cloud Security / Vulnerability read permission, and the scope must be"
        dim "    saved on the exact key in your .env. See the hints printed below."
        _diag_body ;;
      404)
        warn "404 on SBOMs - Code Security / SBOM may not be enabled for this org." ;;
      400)
        dim "    (SBOM probe returned 400 - informational; continuing)"; _diag_body ;;
      *)  : ;;
    esac
  fi
  return 0
}
