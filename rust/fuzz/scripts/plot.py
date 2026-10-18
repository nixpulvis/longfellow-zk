#!/usr/bin/env python3
"""Plot and summarize a run-matrix directory.

    python3 scripts/plot.py out/matrix/mdoc [--out mdoc.png]

Reads <dir>/<mode>-<tag>/stats.csv, groups runs by configuration (the part of
the directory name before the trailing -tN), and draws two small multiples:
edges vs wall-clock time, and edges vs executions (log x). Each line is the
median across trials with a min-max band. Prints a markdown summary table.
"""
import argparse, csv, re, statistics, sys
from pathlib import Path

# Fixed configuration -> color slot, so a color always means the same mode
# (validated categorical palette; aqua/yellow are under 3:1 on the light
# surface, so every line is also direct-labeled and dashed differently).
STYLE = {
    "bytes":         ("#2a78d6", "-"),
    "bytes-cmplog":  ("#eb6834", "--"),
    "arbitrary":     ("#1baf7a", "-."),
    "nautilus":      ("#eda100", "-"),
    "bytes-noseeds": ("#6250d6", ":"),
}
INK, MUTED, GRID, SURFACE = "#1f1f1e", "#6b6a64", "#e6e5e0", "#fcfcfb"


def load(d):
    groups = {}
    for run in sorted(Path(d).iterdir()):
        f = run / "stats.csv"
        if not f.exists():
            continue
        name = re.sub(r"-t\d+$", "", run.name)
        rows = list(csv.DictReader(open(f)))
        if rows:
            groups.setdefault(name, []).append(rows)
    return groups


def series(runs, x):
    """Median/min/max of edges on a common grid of x."""
    xs = sorted({float(r[x]) for rows in runs for r in rows})
    if x == "elapsed_s":
        step = max(1.0, xs[-1] / 200)
        grid = [i * step for i in range(int(xs[-1] / step) + 1)]
    else:
        lo, hi = max(1.0, xs[0]), xs[-1]
        grid = [lo * (hi / lo) ** (i / 200) for i in range(201)]
    med, mn, mx = [], [], []
    for g in grid:
        vals = []
        for rows in runs:
            v = [int(r["edges"]) for r in rows if float(r[x]) <= g]
            if v and float(rows[-1][x]) >= g:
                vals.append(v[-1])
        if len(vals) == len(runs):  # only where every trial has data
            med.append(statistics.median(vals)); mn.append(min(vals)); mx.append(max(vals))
        else:
            med.append(None); mn.append(None); mx.append(None)
    pts = [(g, a, b, c) for g, a, b, c in zip(grid, med, mn, mx) if a is not None]
    return [list(t) for t in zip(*pts)] if pts else [[], [], [], []]


def summary(groups):
    best = max(int(rows[-1]["edges"]) for runs in groups.values() for rows in runs)
    print(f"| config | trials | final edges (median) | min-max | execs/s (median) | time to 90% of best ({int(best * .9)}) |")
    print("|---|---|---|---|---|---|")
    for name, runs in sorted(groups.items(), key=lambda kv: -statistics.median(int(r[-1]["edges"]) for r in kv[1])):
        finals = [int(r[-1]["edges"]) for r in runs]
        rates = [int(r[-1]["execs"]) / max(float(r[-1]["elapsed_s"]), 1e-9) for r in runs]
        t90 = []
        for rows in runs:
            hit = next((float(r["elapsed_s"]) for r in rows if int(r["edges"]) >= best * .9), None)
            t90.append(hit)
        reached = [t for t in t90 if t is not None]
        t90s = f"{statistics.median(reached):.0f}s ({len(reached)}/{len(runs)} runs)" if reached else "never"
        print(f"| {name} | {len(runs)} | {statistics.median(finals):.0f} | {min(finals)}-{max(finals)} | {statistics.median(rates):,.0f} | {t90s} |")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dir")
    ap.add_argument("--out")
    a = ap.parse_args()
    groups = load(a.dir)
    if not groups:
        sys.exit(f"no stats.csv under {a.dir}")
    summary(groups)

    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    fig, axes = plt.subplots(1, 2, figsize=(12, 4.6), facecolor=SURFACE)
    for ax, x, label in [(axes[0], "elapsed_s", "wall-clock seconds"),
                         (axes[1], "execs", "executions (log)")]:
        ax.set_facecolor(SURFACE)
        for name, runs in groups.items():
            color, ls = STYLE.get(name, (MUTED, "-"))
            g, med, mn, mx = series(runs, x)
            if not g:
                continue
            ax.fill_between(g, mn, mx, color=color, alpha=0.15, linewidth=0)
            ax.plot(g, med, color=color, linestyle=ls, linewidth=2, label=name)
            ax.annotate(name, (g[-1], med[-1]), xytext=(4, 0), textcoords="offset points",
                        va="center", fontsize=9, color=INK)
        if x == "execs":
            ax.set_xscale("log")
        ax.set_xlabel(label, color=MUTED)
        ax.grid(True, color=GRID, linewidth=0.8)
        for s in ("top", "right"):
            ax.spines[s].set_visible(False)
        for s in ("left", "bottom"):
            ax.spines[s].set_color(GRID)
        ax.tick_params(colors=MUTED)
        ax.margins(x=0.12)
    axes[0].set_ylabel("edges covered (median, min-max band)", color=MUTED)
    axes[0].legend(frameon=False, fontsize=9, labelcolor=INK, loc="lower right")
    fig.suptitle(f"Coverage over time: {Path(a.dir).name}", color=INK, x=0.01, ha="left")
    fig.tight_layout()
    out = a.out or str(Path(a.dir) / "coverage.png")
    fig.savefig(out, dpi=150)
    print(f"\nwrote {out}")


if __name__ == "__main__":
    main()
