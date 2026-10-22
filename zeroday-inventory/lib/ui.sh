#!/usr/bin/env bash
# ui.sh - presentation helpers. Everything here writes to stderr so stdout
# stays clean for data/pipes. No business logic lives in this file.

if [ -t 2 ] && [ -z "${NO_COLOR:-}" ]; then
  C_RED=$'\033[31m'; C_GRN=$'\033[32m'; C_YLW=$'\033[33m'
  C_BLU=$'\033[34m'; C_CYN=$'\033[36m'; C_BLD=$'\033[1m'
  C_DIM=$'\033[2m';  C_OFF=$'\033[0m'
else
  C_RED=""; C_GRN=""; C_YLW=""; C_BLU=""; C_CYN=""; C_BLD=""; C_DIM=""; C_OFF=""
fi

info() { printf '%s\n' "$*" >&2; }
step() { printf '%s=>%s %s\n' "$C_BLU" "$C_OFF" "$*" >&2; }
ok()   { printf '%s[ok]%s %s\n' "$C_GRN" "$C_OFF" "$*" >&2; }
warn() { printf '%s[!]%s %s\n'  "$C_YLW" "$C_OFF" "$*" >&2; }
dim()  { printf '%s%s%s\n' "$C_DIM" "$*" "$C_OFF" >&2; }
hdr()  { printf '\n%s%s%s\n' "$C_BLD" "$*" "$C_OFF" >&2; }
die()  { printf '%s[x]%s %s\n' "$C_RED" "$C_OFF" "$*" >&2; exit 1; }

# progress "[2/6]" "Fetching repository SBOMs... page 3/12"
progress() { printf '%s%s%s %s\n' "$C_CYN" "$1" "$C_OFF" "$2" >&2; }

# ask PROMPT DEFAULT -> echoes answer on stdout (callers capture it).
# Reads on its own line; trims surrounding whitespace so a stray paste newline
# cannot shift the next prompt.
ask() {
  local prompt="$1" def="${2:-}" ans=""
  if [ -n "$def" ]; then printf '%s [%s]: ' "$prompt" "$def" >&2
  else printf '%s: ' "$prompt" >&2; fi
  IFS= read -r ans || ans=""
  ans="$(printf '%s' "$ans" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
  [ -n "$ans" ] || ans="$def"
  printf '%s' "$ans"
}

# ask_secret PROMPT -> echoes secret on stdout, input hidden, never logged.
ask_secret() {
  local prompt="$1" ans=""
  printf '%s: ' "$prompt" >&2
  if [ -t 0 ]; then stty -echo 2>/dev/null; fi
  IFS= read -r ans || ans=""
  if [ -t 0 ]; then stty echo 2>/dev/null; printf '\n' >&2; fi
  printf '%s' "$ans"
}

# confirm QUESTION DEFAULT(y|n) -> returns 0 for yes, 1 for no.
confirm() {
  local q="$1" def="${2:-n}" ans="" hint="[y/N]"
  [ "$def" = "y" ] && hint="[Y/n]"
  printf '%s %s ' "$q" "$hint" >&2
  IFS= read -r ans || ans=""
  ans="$(printf '%s' "$ans" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z]//g')"
  [ -n "$ans" ] || ans="$def"
  case "$ans" in y|yes) return 0 ;; *) return 1 ;; esac
}

# menu TITLE "val1:Label one" "val2:Label two" ... -> echoes chosen value.
# Numbered prompt (portable, pipe/CI friendly). Loops until a valid pick.
menu() {
  local title="$1"; shift
  local n=$# i choice
  printf '\n%s%s%s\n' "$C_BLD" "$title" "$C_OFF" >&2
  i=1
  for item in "$@"; do
    printf '  %d) %s\n' "$i" "${item#*:}" >&2
    i=$((i + 1))
  done
  while :; do
    printf '  select [1-%d]: ' "$n" >&2
    IFS= read -r choice || { printf '\n' >&2; return 1; }
    case "$choice" in
      ''|*[!0-9]*) warn "enter a number"; continue ;;
    esac
    if [ "$choice" -ge 1 ] && [ "$choice" -le "$n" ]; then
      eval "item=\${$choice}"
      printf '%s' "${item%%:*}"
      return 0
    fi
    warn "out of range"
  done
}

# spinner PID MESSAGE - shows a spinner on stderr while PID runs (TTY only).
spinner() {
  local pid="$1" msg="${2:-working}" frames='-\|/' i=0
  if [ ! -t 2 ]; then wait "$pid" 2>/dev/null; return $?; fi
  while kill -0 "$pid" 2>/dev/null; do
    i=$(((i + 1) % 4))
    printf '\r%s %s ' "${frames:$i:1}" "$msg" >&2
    sleep 0.2
  done
  printf '\r\033[2K' >&2
  wait "$pid" 2>/dev/null
}
