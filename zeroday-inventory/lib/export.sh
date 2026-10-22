#!/usr/bin/env bash
# export.sh - turn the three CSVs into an .xlsx via a fallback chain:
#   1) python3 + openpyxl  (full 3-sheet workbook, formatted)
#   2) libreoffice --headless --convert-to xlsx  (one sheet per file; cannot
#      merge, so emits inventory.xlsx + keeps the other CSVs, with a warning)
#   3) neither available -> leave CSVs, print install hints
#
# SCRIPT_DIR must be exported by the caller (location of lib/csv2xlsx.py).

# has CMD
_has() { command -v "$1" >/dev/null 2>&1; }

_python_openpyxl() {
  _has python3 || return 1
  python3 -c 'import openpyxl' >/dev/null 2>&1 || return 1
  return 0
}

# export_xlsx OUT_XLSX OUT_DIR
export_xlsx() {
  local out="$1" dir="$2"
  local inv="${dir}/inventory.csv" det="${dir}/details.csv" unm="${dir}/unmapped.csv"

  if _python_openpyxl; then
    step "Building workbook with python3 + openpyxl"
    if python3 "${SCRIPT_DIR}/lib/csv2xlsx.py" "$out" \
         "inventory=${inv}" "details=${det}" "unmapped=${unm}"; then
      ok "Wrote ${out}"
      return 0
    fi
    warn "openpyxl export failed; trying next method"
  fi

  if _has libreoffice; then
    step "python/openpyxl unavailable - converting with libreoffice (single-sheet)"
    warn "libreoffice cannot merge sheets; writing separate .xlsx files per CSV"
    local outdir_abs
    outdir_abs="$(cd "$dir" && pwd)"
    local csv
    for csv in "$inv" "$det" "$unm"; do
      [ -f "$csv" ] || continue
      libreoffice --headless --convert-to xlsx --outdir "$outdir_abs" "$csv" >/dev/null 2>&1 \
        || warn "libreoffice failed on $(basename "$csv")"
    done
    ok "Wrote per-sheet .xlsx files into ${dir} (inventory/details/unmapped)"
    warn "Combined single-file workbook needs python3 + openpyxl."
    return 0
  fi

  warn "No xlsx converter found - leaving CSV output in ${dir}"
  dim "  CSVs: inventory.csv, details.csv, unmapped.csv"
  dim "  To get a formatted .xlsx, install one of:"
  dim "    pip install openpyxl        (recommended; enables full 3-sheet workbook)"
  dim "    apt/brew install libreoffice"
  return 0
}
