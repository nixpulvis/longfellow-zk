# LibAFL fuzzers for longfellow-zk

In-process LibAFL fuzzers for the Rust implementation. They serve two goals:
find bugs, and measure how grammar-based fuzzing (Nautilus) compares with
byte-level fuzzing on the same targets with the same scheduler, feedback and
objectives.

This is a standalone crate (its own `[workspace]`), so the main workspace and
its CI never build LibAFL.

## Build

Stable Rust is enough (no `cargo-fuzz`, no nightly):

```sh
cd rust/fuzz
scripts/build.sh          # -> target/release/{cbor,mdoc,circuit,proof,verify}
```

`build.sh` sets `scripts/sancov-rustc.sh` as `RUSTC_WRAPPER`. The wrapper adds
SanitizerCoverage (inline 8-bit counters plus comparison tracing for cmplog),
debug assertions and overflow checks, but only to:

- the crates that parse untrusted bytes: `core_proto`, `runtime_proto`,
  `mdoc_zk_circuits`
- the harness binaries in `src/bin/`, where generic readers are monomorphized

LibAFL, the runner, the EDN assembler, the `Arbitrary` decoder and third-party
crates stay uninstrumented. As a result the coverage numbers count target code
only, in every mode. The comments in the wrapper explain why the verifier
crates are excluded (instrumenting them made one verification 5× slower).
`LF_FUZZ_INSTRUMENT=all` and `LF_FUZZ_CHECKS=off` change those defaults;
`LF_FUZZ_ASAN=1` adds AddressSanitizer via `RUSTC_BOOTSTRAP`.

Unit tests for the assembler and grammars (`cargo test --release --lib`) run
without instrumentation. Use a separate target dir:
`CARGO_TARGET_DIR=target/test cargo test --release --lib`.

## Targets

| binary | function under test | modes | oracle beyond crashes |
|---|---|---|---|
| `cbor` | `CborParser::parse_exact` (host CBOR) | bytes, bytes-cmplog, nautilus | none |
| `mdoc` | `parse_mdoc` (prover-side mdoc parsing) | bytes, bytes-cmplog, nautilus | offsets/lengths in the result stay in bounds (`src/mdoc_props.rs`) |
| `circuit` | `CircuitArchive::from_bytes`, `CircuitReader` LFC1/LFC2 | bytes, bytes-cmplog | none |
| `proof` | `MdocProof::read` with a real circuit's geometry | bytes, bytes-cmplog | accepted proofs re-encode to the same bytes (no malleability) |
| `verify` | `run_mdoc_verifier`, fixed circuit/key/transcript/attrs | bytes, arbitrary | any accepted proof that differs from the honest one |

`proof` and `verify` build a fixture once before forking: a stored v7 circuit,
its geometry, and an honest proof (generated with the deterministic RNG, cached
in `target/fixtures/`). One verification takes about 0.38 s, so `verify` is a
slow, long-running soundness check rather than a throughput target.

## Modes

```sh
target/release/mdoc --mode bytes        --seconds 3600   # havoc + tokens
target/release/mdoc --mode bytes-cmplog --seconds 3600   # + cmplog / I2S stage
target/release/mdoc --mode nautilus     --seconds 3600   # grammar
target/release/verify --mode arbitrary  --seconds 3600   # typed proof edits
```

Output goes to `out/<target>/<mode>[-<tag>]/`: `queue/`, `crashes/` and
`stats.csv` (one row per `--stats-every` seconds: execs, corpus, crashes and
edges covered, read from the map feedback's own metadata). `--no-seeds` starts
bytes mode from random inputs instead of the real mdocs/circuits/proofs.

The runner uses LibAFL's restarting manager: a crash or timeout restarts the
child with the fuzzer state intact, so known bugs don't end a run.

### Grammars and the EDN assembler

CBOR prefixes byte strings with their length, and mdoc nests CBOR inside byte
strings (`24(<< ... >>)`) everywhere. A context-free grammar can't compute
those lengths. So the Nautilus grammars (`src/grammar.rs`) emit CBOR
diagnostic notation, and `src/edn.rs` assembles it with every length filled
in. Extensions cover what a fuzzer needs: `_0`..`_3` head widths (the circuit
requires the MSO's tag-24 bstr to use a 2-byte length), `!N` to declare a
wrong length or count, `[_ ...]` for indefinite length, and `raw'..'` for
verbatim bytes. `--dump-grammar` prints the rules.

The mdoc grammar follows ISO 18013-5. It generates all 24 IssuerSignedItem
field orders, which the circuit records as a permutation. Every structured slot
can also fall back to an arbitrary CBOR item, and missing, duplicated and
reordered fields appear next to the well-formed shapes.

## Comparing bytes and grammar

```sh
JOBS=2 scripts/run-matrix.sh mdoc 3600 5            # 5 trials x 4 configs x 1h
python3 scripts/plot.py out/matrix/mdoc            # coverage.png + summary table
scripts/triage.sh mdoc nautilus out/matrix/mdoc/nautilus-t1/crashes
```

Keep `JOBS` at or below the physical core count: concurrent runs share CPU and
cache and skew executions per second.

## Findings so far

See [FINDINGS.md](FINDINGS.md) for full write-ups (three bugs so far).

1. **Circuit readers panic on a zero output count.** `lfc1.rs` and `lfc2.rs`
   check `noutput <= MAX_WIRES` and then call `ceil_log2(noutput)`, which
   panics on 0. A malformed circuit aborts the process instead of returning
   `Err`. Found by `circuit` within seconds.
2. **`CborParser` recursion has no depth limit.** About 50k nested arrays
   (a 50 KB input) overflow an 8 MB main-thread stack; on a 2 MB worker thread
   it takes about 12 KB. Found by reading the code, not by the fuzzer: bytes
   mode never grows inputs that large. Set `LF_FUZZ_MAX_DEPTH=1000` to filter
   these inputs out during comparison runs.
