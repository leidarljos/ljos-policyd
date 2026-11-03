"""summary.py CSV...: print the median and IQR over the runs in each CSV
that run.sh wrote. The µs per step of a run is computed from its raw
shallow_ms, nested_ms and step columns. The quartiles are
statistics.quantiles(method="inclusive")."""

import csv
import os
import statistics
import sys


def per_step(row: dict) -> float:
    steps = int(row["nested_steps"]) - int(row["shallow_steps"])
    return (float(row["nested_ms"]) - float(row["shallow_ms"])) * 1000 / steps


def cell(xs: list) -> str:
    q1, med, q3 = statistics.quantiles(xs, n=4, method="inclusive")
    return f"{med:.2f} ({q1:.2f} to {q3:.2f})"


def baseline(rows: list) -> None:
    print("| line | runs | p50 ms |")
    print("|---|---:|---:|")
    for name in dict.fromkeys(r["line"] for r in rows):
        xs = [float(r["p50_ms"]) for r in rows if r["line"] == name]
        print(f"| {name} | {len(xs)} | {cell(xs)} |")


def main() -> None:
    walks = []
    for path in sys.argv[1:]:
        with open(path, newline="") as f:
            rows = list(csv.DictReader(f))
        if rows and "line" in rows[0]:
            baseline(rows)
        else:
            walks.append((path, rows))
    if not walks:
        return
    print("| file | runs | shallow ms | nested ms | µs per step |")
    print("|---|---:|---:|---:|---:|")
    for path, rows in walks:
        shallow = [float(r["shallow_ms"]) for r in rows]
        nested = [float(r["nested_ms"]) for r in rows]
        steps = [per_step(r) for r in rows]
        name = os.path.basename(path)
        print(f"| {name} | {len(rows)} | {cell(shallow)} | {cell(nested)} | {cell(steps)} |")


if __name__ == "__main__":
    main()
