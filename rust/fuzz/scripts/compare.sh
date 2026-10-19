#!/usr/bin/env bash
# Run every fuzzer in every mode and report bytes vs grammar.
#
#   scripts/compare.sh [--seconds N] [--trials N] [--jobs N] [--targets "a b"]
#                      [--out DIR] [--no-build] [--quick]
#
# For each target it runs the modes scripts/run-matrix.sh lists for it
# (cbor, mdoc, circuit: bytes, bytes-cmplog, nautilus, bytes --no-seeds;
# proof: bytes, bytes-cmplog; verify: bytes, arbitrary), every mode for
# --trials trials of --seconds each, all targets in one pool of --jobs
# parallel runs, one core each. Then it triages every run's crashes and
# writes <out>/report.md: coverage, execution rate, and for each crash
# signature the trials that found it and when, per mode. Fuzzer logs go to
# <out>/logs/.
#
# Defaults: 1800 s x 3 trials, jobs = physical cores, all five targets, out
# = out/compare/<timestamp>. That is 48 runs: about 6 hours on 4 cores. The
# script prints its estimate before starting. --quick is 60 s x 1 trial, to
# check the setup.
#
# Needs Linux (fork-based fuzzers; triage.sh uses GNU stat), Rust, and
# python3. pip install matplotlib for coverage charts; without it the report
# has the tables only. LF_FUZZ_* settings (README.md) pass through, e.g.
# LF_FUZZ_MAX_DEPTH=1000 to keep the known CBOR recursion crash out of the
# mdoc and cbor runs.
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"

physical_cores() {
  if command -v lscpu >/dev/null; then
    lscpu -p=Core,Socket 2>/dev/null | grep -v '^#' | sort -u | wc -l
  elif command -v sysctl >/dev/null && sysctl -n hw.physicalcpu >/dev/null 2>&1; then
    sysctl -n hw.physicalcpu
  else
    nproc
  fi
}

secs=1800 trials=3 jobs="" targets="cbor mdoc circuit proof verify" out="" build=1
while [[ $# -gt 0 ]]; do
  case "$1" in
    --seconds) secs="$2"; shift 2 ;;
    --trials) trials="$2"; shift 2 ;;
    --jobs) jobs="$2"; shift 2 ;;
    --targets) targets="$2"; shift 2 ;;
    --out) out="$2"; shift 2 ;;
    --no-build) build=0; shift ;;
    --quick) secs=60; trials=1; shift ;;
    -h|--help) sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1 (see --help)" >&2; exit 2 ;;
  esac
done
jobs="${jobs:-$(physical_cores)}"
[[ "$jobs" -ge 1 ]] || jobs=1
out="$(realpath -m "${out:-$here/out/compare/$(date +%Y%m%d-%H%M%S)}")"

command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 1; }
python3 -c 'import matplotlib' 2>/dev/null \
  || echo "note: matplotlib not installed; the report will have tables but no charts"

if [[ $build == 1 ]]; then
  echo "building fuzzers..."
  "$here/scripts/build.sh"
fi
for t in $targets; do
  [[ -x "$here/target/release/$t" ]] || { echo "no fuzzer binary for $t (run scripts/build.sh)" >&2; exit 1; }
done

# One pool for all targets, so no core idles while a target's last runs end.
mkdir -p "$out/logs"
cmds=()
for t in $targets; do
  while IFS= read -r c; do cmds+=("$c"); done \
    < <(DRY_RUN=1 OUT="$out" "$here/scripts/run-matrix.sh" "$t" "$secs" "$trials")
done
printf '%s\n' "${cmds[@]}" > "$out/jobs.txt"
n=${#cmds[@]}
rounds=$(( (n + jobs - 1) / jobs ))
eta=$(( rounds * secs ))
printf 'running %d fuzzer runs (%s x %d trials, %d at a time) -> %s\n' "$n" "${secs}s" "$trials" "$jobs" "$out"
printf 'estimated time: %dh%02dm, plus build and triage\n' $((eta / 3600)) $((eta % 3600 / 60))

# Each job logs to logs/<target>-<mode>-<tag>.log. A run that crashes keeps
# going (the restarting manager restarts it), so a nonzero exit is unusual
# and is reported, not fatal.
run_job() {
  local cmd="$1" out="$2"
  local t m tag
  t="$(basename "${cmd%% *}")"
  m="$(grep -oE -- '--mode [a-z-]+' <<<"$cmd" | cut -d' ' -f2)"
  tag="$(grep -oE -- '--tag [^ ]+' <<<"$cmd" | cut -d' ' -f2)"
  local log="$out/logs/$t-$m-$tag.log"
  echo "$cmd" > "$log"
  if ! $cmd >> "$log" 2>&1; then
    echo "  exited nonzero: $t $m $tag (see $log)"
  fi
  echo "  finished $t $m $tag"
}
export -f run_job
start=$(date +%s)
printf '%s\n' "${cmds[@]}" | xargs -P "$jobs" -I{} bash -c 'run_job "$1" "$2"' _ {} "$out"
echo "fuzzing done in $(( ($(date +%s) - start) / 60 )) min"

# Triage: replay every crash and group by signature (scripts/triage.sh), one
# run per core. Runs with thousands of crashes take a few minutes each.
echo "triaging crashes..."
triage_run() {
  local dir="$1" here="$2"
  local t m
  t="$(basename "$(dirname "$dir")")"
  m="$(basename "$dir")"; m="${m%-*}"; m="${m%-noseeds}"
  if [[ -d "$dir/crashes" ]]; then
    "$here/scripts/triage.sh" "$t" "$m" "$dir/crashes" 20 > "$dir/triage.txt" 2>/dev/null || true
  else
    : > "$dir/triage.txt"
  fi
}
export -f triage_run
find "$out" -mindepth 2 -maxdepth 2 -type d -name '*-*t[0-9]*' -print0 \
  | xargs -0 -P "$jobs" -I{} bash -c 'triage_run "$1" "$2"' _ {} "$here"

python3 "$here/scripts/report.py" "$out"
echo "report: $out/report.md"
