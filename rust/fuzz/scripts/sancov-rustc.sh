#!/usr/bin/env bash
# RUSTC_WRAPPER that adds SanitizerCoverage instrumentation to selected
# longfellow crates only. LibAFL, the harness code, the EDN assembler and
# third-party crates stay uninstrumented, so the coverage map measures target
# code only. That is what makes bytes-vs-grammar coverage numbers comparable.
#
# Works on stable Rust: -Cpasses and -Cllvm-args are stable codegen options.
# AddressSanitizer must be applied to every crate (rustc requires
# consistency), so it is set via RUSTFLAGS in build.sh rather than here.
#
# Knobs (build.sh folds them into the build fingerprint):
#
#   LF_FUZZ_INSTRUMENT=parsers (default) | all
#     parsers: core_proto, runtime_proto, mdoc_zk_circuits, i.e. the crates
#     that parse untrusted bytes (CBOR/mdoc, circuits, proofs).
#     all: every longfellow crate.
#
#     Why not instrument the verifier too: proof verification is generic over
#     the field, so the Ligero/sumcheck loops get monomorphized (and
#     instrumented) inside runtime_zk / mdoc_zk_runtime. Rust runs the sancov
#     pass before inlining, so even function-level counters land inside those
#     loops after inlining and block vectorization. Measured on one mdoc
#     verification: 0.38s uninstrumented / parsers, 2.0s with all
#     (edge-level or function-level alike).
#
#   LF_FUZZ_CHECKS=on (default) | off
#     Debug assertions + overflow checks on instrumented crates, so silent
#     wraparound in offset/length arithmetic becomes a crash.
set -euo pipefail
rustc="$1"; shift

root="${LF_FUZZ_ROOT:?LF_FUZZ_ROOT must point at the rust/ directory}"

in_tree=0
fuzz_bin=0
crate=""
prev=""
for arg in "$@"; do
  if [[ "$prev" == "--crate-name" ]]; then crate="$arg"; fi
  case "$arg" in
    *.rs)
      if [[ $in_tree == 0 ]]; then
        p="$(realpath -m "$arg" 2>/dev/null || echo "$arg")"
        if [[ "$p" == "$root"/* && "$p" != "$root"/fuzz/* ]]; then in_tree=1; fi
        if [[ "$p" == "$root"/fuzz/src/bin/* ]]; then fuzz_bin=1; fi
      fi ;;
  esac
  prev="$arg"
done

# Harness binaries are instrumented too: generic target code (proof and
# circuit readers, parse_mdoc) is monomorphized where it is called with
# concrete types, which is in these files. Anything mode-specific (the
# Arbitrary edit decoder, the EDN assembler, property checks) lives in the
# uninstrumented library so no mode gets credit for its own harness code.
instrument=$fuzz_bin
if [[ $in_tree == 1 ]]; then
  case "${LF_FUZZ_INSTRUMENT:-parsers}" in
    all) instrument=1 ;;
    *) case "$crate" in
         core_proto|runtime_proto|mdoc_zk_circuits) instrument=1 ;;
       esac ;;
  esac
fi

extra=()
if [[ $instrument == 1 ]]; then
  extra+=(
    -Cpasses=sancov-module
    -Cllvm-args=-sanitizer-coverage-level=3
    -Cllvm-args=-sanitizer-coverage-inline-8bit-counters
    -Cllvm-args=-sanitizer-coverage-trace-compares
  )
  if [[ "${LF_FUZZ_CHECKS:-on}" == on ]]; then
    extra+=(-Cdebug-assertions=on -Coverflow-checks=on)
  fi
fi
exec "$rustc" "$@" "${extra[@]}"
