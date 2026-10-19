#!/usr/bin/env bash
# Replay every input in a crashes/ dir and group by crash signature, with the
# time each signature was first found (crash file mtime relative to the run's
# first stats.csv row). Distinct real bugs and time-to-first-find per bug are
# the numbers that compare modes.
# Usage: scripts/triage.sh <target> <mode> <crashes-dir> [timeout-secs]
set -uo pipefail
bin="$(dirname "$0")/../target/release/$1"; mode="$2"; dir="$3"; t="${4:-20}"
declare -A count example first
start_ms="$(sed -n 2p "$dir/../stats.csv" 2>/dev/null | cut -d, -f1)"
for f in "$dir"/*; do
  case "$f" in *.metadata|*.lafl_lock|*/.*) continue ;; esac
  [[ -f "$f" ]] || continue
  out="$(RUST_BACKTRACE=0 timeout "$t" "$bin" --mode "$mode" --replay "$f" 2>&1)"; rc=$?
  if [[ $rc == 124 ]]; then sig="timeout (>${t}s)"
  elif grep -q "replayed 1 inputs without crashing" <<<"$out"; then sig="no crash on replay (timeout or flaky)"
  else
    sig="$(grep -m1 -oE "panicked at [^ ]+:[0-9]+:[0-9]+:" <<<"$out")"
    msg="$(grep -m1 -A1 "panicked at" <<<"$out" | tail -1 | cut -c1-100)"
    [[ -z "$sig" ]] && sig="$(grep -m1 -oE "stack overflow|memory allocation of [0-9]+ bytes failed|SIG[A-Z]+|capacity overflow" <<<"$out")"
    [[ -z "$sig" ]] && sig="exit $rc"
    [[ -n "${msg:-}" ]] && sig="$sig $msg"
    # One allocation bug fails with a different size per input.
    sig="$(sed -E 's/allocation of [0-9]+ bytes/allocation of N bytes/' <<<"$sig")"
  fi
  count["$sig"]=$(( ${count["$sig"]:-0} + 1 ))
  : "${example["$sig"]:=$f}"
  t_ms=$(( $(stat -c %Y "$f") * 1000 ))
  if [[ -z "${first["$sig"]:-}" || $t_ms -lt ${first["$sig"]} ]]; then first["$sig"]=$t_ms; example["$sig"]=$f; fi
done
for s in "${!count[@]}"; do
  ttf="?"; [[ -n "$start_ms" ]] && ttf="$(( (${first[$s]} - start_ms) / 1000 ))s"
  printf "first@%-8s x%-5d %s  [%s]\n" "$ttf" "${count[$s]}" "$s" "${example[$s]}"
done | sort -t@ -k2 -n
