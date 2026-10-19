#!/usr/bin/env bash
# Run the bytes-vs-grammar comparison for one target.
#
#   scripts/run-matrix.sh <target> [seconds=3600] [trials=5] [modes...]
#
# Each (mode, trial) runs with --seed <trial> --tag t<trial> under
# out/matrix/<target>/, using as many parallel jobs as cores (override with
# JOBS=N). Pin trials to a quiet machine: concurrent runs share CPU and cache,
# so keep JOBS <= physical cores. Plot with scripts/plot.py out/matrix/<target>.
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
target="$1"; secs="${2:-3600}"; trials="${3:-5}"; shift $(( $# < 3 ? $# : 3 ))
modes=("$@")
if [[ ${#modes[@]} == 0 ]]; then
  case "$target" in
    cbor|mdoc|circuit) modes=(bytes bytes-cmplog nautilus "bytes --no-seeds") ;;
    verify)    modes=(bytes arbitrary) ;;
    *)         modes=(bytes bytes-cmplog) ;;
  esac
fi
bin="$here/target/release/$target"
[[ -x "$bin" ]] || { echo "build first: scripts/build.sh"; exit 1; }
jobs="${JOBS:-$(nproc)}"
out="${OUT:-$here/out/matrix}"

cmds=()
for m in "${modes[@]}"; do
  read -r mode extra <<<"$m"
  label="t"; [[ -n "${extra:-}" ]] && label="noseeds-t"
  for t in $(seq 1 "$trials"); do
    cmds+=("$bin --mode $mode ${extra:-} --seconds $secs --seed $t --tag $label$t --out $out")
  done
done
mkdir -p "$out/$target"
printf '%s\n' "${cmds[@]}" > "$out/$target/jobs.txt"
echo "running ${#cmds[@]} jobs ($jobs parallel, ${secs}s each) -> $out/$target"
printf '%s\n' "${cmds[@]}" | xargs -P "$jobs" -I{} sh -c '{} > /dev/null 2>&1 || true'
echo "done. plot: python3 $here/scripts/plot.py $out/$target"
