#!/usr/bin/env bash
# Replay every input in a crashes/ dir and group by crash signature.
# Usage: scripts/triage.sh <target> <mode> <crashes-dir> [timeout-secs]
set -uo pipefail
bin="$(dirname "$0")/../target/release/$1"; mode="$2"; dir="$3"; t="${4:-20}"
declare -A count example
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
  fi
  count["$sig"]=$(( ${count["$sig"]:-0} + 1 ))
  : "${example["$sig"]:=$f}"
done
for s in "${!count[@]}"; do printf "%5d  %s\n       e.g. %s\n" "${count[$s]}" "$s" "${example[$s]}"; done | sort -rn
