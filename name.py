"""Sets the name, and optionally the mangled symbol, of a row in symbols.csv.

    name.py ADDRESS NAME [SYMBOL]
    name.py --add ADDRESS SYMBOL

Adds the row if the address is new (size left empty). With --add, adds
another symbol at an address that already has one: functions the linker
folded into one copy share an address, and the column lists them all,
separated by spaces. The name stays the first function's.
"""
import csv, os, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIELDS = ["address", "size", "name", "symbol"]


def main():
    if sys.argv[1] == "--add":
        return add(int(sys.argv[2], 16), sys.argv[3])
    addr, name = int(sys.argv[1], 16), sys.argv[2]
    symbol = sys.argv[3] if len(sys.argv) > 3 else None
    path = os.path.join(ROOT, "config/symbols.csv")
    rows = {int(r["address"], 16): r for r in csv.DictReader(open(path))}
    row = rows.setdefault(addr, {"address": f"0x{addr:08x}", "size": "", "symbol": ""})
    row["name"] = name
    if symbol is not None:
        row["symbol"] = symbol
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, FIELDS, lineterminator="\n")
        w.writeheader()
        for a in sorted(rows):
            w.writerow({k: rows[a].get(k) or "" for k in FIELDS})
    print(",".join(row.get(k) or "" for k in FIELDS))


def add(addr, symbol):
    path = os.path.join(ROOT, "config/symbols.csv")
    rows = list(csv.DictReader(open(path)))
    for row in rows:
        if int(row["address"], 16) == addr:
            if symbol not in row["symbol"].split():
                row["symbol"] = (row["symbol"] + " " + symbol).strip()
            break
    else:
        sys.exit(f"no row at {addr:#x}")
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, FIELDS, lineterminator="\n")
        w.writeheader()
        w.writerows(rows)
    print(",".join(row.get(k) or "" for k in FIELDS))


if __name__ == "__main__":
    main()
