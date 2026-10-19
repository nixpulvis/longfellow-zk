#!/usr/bin/env python3
"""Write report.md for a scripts/compare.sh output directory.

    python3 scripts/report.py out/compare/<timestamp>

Expects <dir>/<target>/<mode>-<tag>/{stats.csv,triage.txt}. For each target:
the coverage summary from plot.py, a coverage chart (with matplotlib), and a
table of crash signatures with, per configuration, how many trials found
each one and when. The headline numbers for bytes vs grammar are distinct
signatures and time to first find; coverage is context.
"""
import contextlib, io, re, statistics, subprocess, sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import plot  # noqa: E402

LINE = re.compile(r"^first@(\S+)\s+x(\d+)\s+(.*?)\s+\[(.*)\]$")
# Configuration order in tables: grammar first, then the byte-level modes.
ORDER = ["nautilus", "arbitrary", "bytes", "bytes-cmplog", "bytes-noseeds"]
NOT_BUGS = ("no crash on replay",)


def clean(sig):
    """Repo-relative paths, so signatures read the same on every machine."""
    return re.sub(r"\S*/rust/", "", sig)


def triage(run):
    """{signature: (first_find_seconds or None, count)} for one run."""
    found = {}
    f = run / "triage.txt"
    if not f.exists():
        return found
    for line in f.read_text().splitlines():
        m = LINE.match(line.strip())
        if not m:
            continue
        t, n, sig = m.group(1), int(m.group(2)), clean(m.group(3))
        secs = float(t[:-1]) if t.endswith("s") and t[:-1].replace(".", "").isdigit() else None
        found[sig] = (secs, n)
    return found


def configs(target_dir):
    """{config: [run dirs]}, ordered grammar first."""
    groups = {}
    for run in sorted(p for p in target_dir.iterdir() if (p / "stats.csv").exists()):
        groups.setdefault(re.sub(r"-t\d+$", "", run.name), []).append(run)
    rank = lambda c: (ORDER.index(c) if c in ORDER else len(ORDER), c)
    return dict(sorted(groups.items(), key=lambda kv: rank(kv[0])))


def fmt_s(s):
    return f"{s:.0f}s" if s < 600 else f"{s / 60:.0f}m"


def bug_table(groups):
    per_run = {c: [triage(r) for r in runs] for c, runs in groups.items()}
    sigs = sorted({s for runs in per_run.values() for found in runs for s in found})
    if not sigs:
        return "No crashes in any run.\n", per_run
    head = "| crash signature | " + " | ".join(groups) + " |\n"
    head += "|---|" + "---|" * len(groups) + "\n"
    rows = []
    for sig in sigs:
        cells = []
        for c, runs in per_run.items():
            times = [f[sig][0] for f in runs if sig in f]
            k, n = len(times), len(runs)
            known = [t for t in times if t is not None]
            if not k:
                cells.append(f"0/{n}")
            elif known:
                rng = f" ({fmt_s(min(known))}-{fmt_s(max(known))})" if len(known) > 1 else ""
                cells.append(f"**{k}/{n}**, {fmt_s(statistics.median(known))}{rng}")
            else:
                cells.append(f"**{k}/{n}**")
        label = f"`{sig}`" + (" (not a bug: did not reproduce)" if sig.startswith(NOT_BUGS) else "")
        rows.append(f"| {label} | " + " | ".join(cells) + " |")
    note = (
        "\nEach cell: trials that found it / trials run, then the median time to first "
        "find over those trials (min-max).\n"
    )
    return head + "\n".join(rows) + "\n" + note, per_run


def distinct(found_list):
    """Median and union of real crash signatures across a config's trials."""
    real = [{s for s in f if not s.startswith(NOT_BUGS)} for f in found_list]
    union = set().union(*real) if real else set()
    return (statistics.median(len(r) for r in real) if real else 0), len(union)


def coverage_rows(target_dir):
    groups = plot.load(target_dir)
    rows = {}
    for name, runs in groups.items():
        finals = [int(r[-1]["edges"]) for r in runs]
        rates = [int(r[-1]["execs"]) / max(float(r[-1]["elapsed_s"]), 1e-9) for r in runs]
        rows[name] = (statistics.median(finals), statistics.median(rates))
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        plot.summary(groups)
    return rows, buf.getvalue()


def chart(target_dir):
    png = target_dir / "coverage.png"
    try:
        import matplotlib  # noqa: F401
    except ImportError:
        return None
    subprocess.run(
        [sys.executable, str(Path(__file__).parent / "plot.py"), str(target_dir), "--out", str(png)],
        check=False, capture_output=True,
    )
    return png if png.exists() else None


def settings(d):
    jobs = (d / "jobs.txt").read_text().split("\n") if (d / "jobs.txt").exists() else []
    jobs = [j for j in jobs if j.strip()]
    secs = re.search(r"--seconds (\d+)", jobs[0]).group(1) if jobs else "?"
    seeds = {re.search(r"--seed (\d+)", j).group(1) for j in jobs if "--seed" in j}
    try:
        commit = subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True,
                                text=True, cwd=Path(__file__).parent).stdout.strip()
    except OSError:
        commit = "?"
    cpu = "?"
    try:
        cpu = next(l.split(":", 1)[1].strip() for l in open("/proc/cpuinfo") if l.startswith("model name"))
    except (OSError, StopIteration):
        pass
    return (f"{len(jobs)} runs, {secs} s each, {len(seeds)} trial(s) per configuration, "
            f"one core per run. Commit `{commit}`, CPU {cpu}.")


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    d = Path(sys.argv[1])
    targets = [p for p in sorted(d.iterdir()) if p.is_dir() and p.name != "logs" and configs(p)]
    if not targets:
        sys.exit(f"no runs under {d}")

    summary = ["| target | config | edges (median) | execs/s (median) | crash signatures per trial (median) | distinct signatures, all trials |",
               "|---|---|---|---|---|---|"]
    sections = []
    for t in targets:
        groups = configs(t)
        cov, cov_table = coverage_rows(t)
        bugs, per_run = bug_table(groups)
        for c in groups:
            med, union = distinct(per_run[c])
            edges, rate = cov.get(c, (0, 0))
            summary.append(f"| {t.name} | {c} | {edges:.0f} | {rate:,.0f} | {med:g} | {union} |")
        png = chart(t)
        sec = [f"## {t.name}", "", "### Crashes", "", bugs, "### Coverage", "", cov_table]
        if png:
            sec += [f"![coverage over time: {t.name}]({png.relative_to(d)})", ""]
        sections.append("\n".join(sec))

    report = [
        "# Fuzzer comparison: bytes vs grammar",
        "",
        settings(d),
        "",
        "Modes: `nautilus` is the grammar; `bytes` and `bytes-cmplog` start from the "
        "target's real seeds; `bytes-noseeds` starts from random bytes, as the grammar "
        "does; `arbitrary` (verify) decodes typed proof edits. Crash signatures come from "
        "`scripts/triage.sh`, which replays every crash.",
        "",
        "## Summary",
        "",
        *summary,
        "",
        *sections,
    ]
    (d / "report.md").write_text("\n".join(report))
    print(f"wrote {d / 'report.md'}")


if __name__ == "__main__":
    main()
