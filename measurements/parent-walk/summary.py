"""summary.py CSV...: print the median and IQR of each column run.sh wrote,
one row per cap. The quartiles are statistics.quantiles(method="inclusive")."""

import csv
import statistics
import sys
from collections import defaultdict


def main() -> None:
    by_cap = defaultdict(list)
    for path in sys.argv[1:]:
        with open(path, newline="") as f:
            for row in csv.DictReader(f):
                by_cap[int(row["cap"])].append(row)
    cols = ["shallow_ms", "nested_ms", "us_per_step"]
    print("| cap | runs | " + " | ".join(f"{c} median (IQR)" for c in cols) + " |")
    print("|---:|---:|" + "---:|" * len(cols))
    for cap, rows in sorted(by_cap.items()):
        cells = []
        for c in cols:
            xs = [float(r[c]) for r in rows]
            q1, med, q3 = statistics.quantiles(xs, n=4, method="inclusive")
            cells.append(f"{med:.2f} ({q1:.2f} to {q3:.2f})")
        print(f"| {cap} | {len(rows)} | " + " | ".join(cells) + " |")


if __name__ == "__main__":
    main()
