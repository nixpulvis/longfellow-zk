#!/usr/bin/env bash
# Build the instrumented fuzzers. Usage: scripts/build.sh [cargo build args...]
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
export LF_FUZZ_ROOT="$(cd "$here/.." && pwd)"
export RUSTC_WRAPPER="$here/scripts/sancov-rustc.sh"
# Separate target dir from normal builds of the workspace.
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$here/target}"
# Cargo's fingerprint does not see flags added by the wrapper, so fold a hash
# of the wrapper and its LF_FUZZ_* settings into RUSTFLAGS: changing
# either forces a rebuild.
wrapper_hash="$( (cat "$RUSTC_WRAPPER"; echo "${LF_FUZZ_CHECKS:-on} ${LF_FUZZ_INSTRUMENT:-parsers}") | sha256sum | cut -c1-12)"
# Setting RUSTFLAGS makes cargo ignore rust/.cargo/config.toml's
# `target-cpu=native`, which the GF(2^128) code depends on (carry-less
# multiply). Without it one verification is ~11x slower, so restate it.
export RUSTFLAGS="${RUSTFLAGS:-} -Ctarget-cpu=native -Cmetadata=lfwrap-$wrapper_hash"
if [[ "${LF_FUZZ_ASAN:-0}" == 1 ]]; then
  export RUSTC_BOOTSTRAP=1
  export RUSTFLAGS="${RUSTFLAGS:-} -Zsanitizer=address"
fi
cd "$here"
exec cargo build --release "$@"
