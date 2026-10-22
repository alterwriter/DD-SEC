#!/usr/bin/env python3
"""csv2xlsx.py - build a multi-sheet .xlsx from CSV files, with formatting.

Usage:
    csv2xlsx.py OUTPUT.xlsx SHEETNAME=path/to.csv [SHEETNAME=path/to.csv ...]

Formatting per sheet: bold + frozen header row, autofilter over the used range,
and auto (clamped) column widths. Reads nothing from the network and executes
no CSV content; it only renders cells as text/plain values.
"""
import csv
import sys

try:
    from openpyxl import Workbook
    from openpyxl.styles import Font
    from openpyxl.utils import get_column_letter
except Exception as e:  # noqa: BLE001
    sys.stderr.write("openpyxl not available: %s\n" % e)
    sys.exit(3)


def add_sheet(ws, csv_path):
    max_widths = {}
    nrows = 0
    ncols = 0
    with open(csv_path, newline="", encoding="utf-8") as fh:
        reader = csv.reader(fh)
        for r, row in enumerate(reader, start=1):
            nrows = r
            ncols = max(ncols, len(row))
            for c, val in enumerate(row, start=1):
                ws.cell(row=r, column=c, value=val)
                w = len(val)
                if w > max_widths.get(c, 0):
                    max_widths[c] = w
    if nrows == 0:
        ws.cell(row=1, column=1, value="(no data)")
        return
    # header styling
    for c in range(1, ncols + 1):
        ws.cell(row=1, column=c).font = Font(bold=True)
    ws.freeze_panes = "A2"
    last_col = get_column_letter(max(ncols, 1))
    ws.auto_filter.ref = "A1:%s%d" % (last_col, nrows)
    # column widths (clamped so one long cell can't blow the layout out)
    for c, w in max_widths.items():
        ws.column_dimensions[get_column_letter(c)].width = min(max(w + 2, 8), 60)


def main(argv):
    if len(argv) < 3:
        sys.stderr.write(__doc__)
        return 2
    out = argv[1]
    wb = Workbook()
    wb.remove(wb.active)
    for pair in argv[2:]:
        if "=" not in pair:
            sys.stderr.write("bad arg (want SHEET=csv): %s\n" % pair)
            return 2
        name, path = pair.split("=", 1)
        ws = wb.create_sheet(title=name[:31])  # Excel caps sheet names at 31
        try:
            add_sheet(ws, path)
        except FileNotFoundError:
            ws.cell(row=1, column=1, value="(missing: %s)" % path)
    wb.save(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
