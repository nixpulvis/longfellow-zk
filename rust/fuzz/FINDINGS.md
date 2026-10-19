# Findings

Bugs found while fuzzing the Rust implementation. None are fixed yet.

## 1. Circuit readers panic on a zero output count

- **Where:** `core/proto/src/reader/lfc1.rs` and `core/proto/src/reader/lfc2.rs`, in
  `from_stream_lfc{1,2}_inner`, right after reading `noutput` (`nv`).
- **Cause:** `nv` is only checked against `MAX_WIRES`, then passed to
  `util::ceil_log2`, which panics on 0 (`"log2 of zero is undefined"`).
- **Effect:** a malformed circuit aborts the process instead of returning `Err`.
  Reachable through `CircuitReader::from_bytes`/`from_stream` and through
  `CircuitArchive` (both LFA1 and LFA2 paths), so also through
  `decompress_circuits` and `circuit_id`.
- **How found:** the `circuit` target in bytes mode, within about a second;
  every crash in that run (117) had this signature. In the circuit race
  (below) the grammar found it at 0s in all 3 trials, seeded bytes at 1s,
  2s and 1s, bytes from scratch at 0s, and bytes-cmplog at 167s, 120s and
  116s.
- **Suggested fix:** reject `nv == 0` with an error before computing `logv`.

## 2. `CborParser` recursion has no depth limit

- **Where:** `applications/mdoc_zk/circuits/src/cbor/parse.rs`, `CborParser::parse_val`.
- **Cause:** arrays, maps and tags recurse into `parse_val` with no depth bound.
- **Effect:** deeply nested input overflows the stack and aborts the process.
  About 50k levels (roughly a 50 KB input) is enough on an 8 MB main-thread
  stack; on a 2 MB worker thread it would take about a quarter of that.
  Reachable from `parse_mdoc` (prover side) and from `circuit_supports`
  (verifier side, on requested attribute values).
- **How found:** code review, confirmed by replay. The fuzzers never grew
  inputs large enough to hit it.
- **Suggested fix:** track depth in the parser and return an error past a
  small limit (mdoc structures need well under 32 levels).

## 3. LFA2 archive reader trusts the declared payload length

- **Where:** `core/proto/src/archive/lfa2/reader.rs`, `from_stream_lfa2_body`.
- **Cause:** each entry's `payload_len` is an unbounded ULEB128 that goes
  straight into `vec![0u8; payload_len]`, before the payload is read and
  before the combined ID is checked.
- **Effect:** a small archive that declares a huge payload makes the
  allocation fail and aborts the process instead of returning `Err`.
- **How found:** code review while planning the circuit grammar, confirmed by
  replay. Then found by the fuzzers in the circuit race (below): the grammar
  at 3s, 2s and 7s, seeded bytes at 326s, 430s and 109s, bytes-cmplog at
  184s and 1124s (missed in one trial), and never by bytes from scratch.
- **Suggested fix:** cap `payload_len` (the reader already caps strings and
  entry counts), or read in bounded chunks and fail on EOF.

### Related, lower severity: LFC2 pre-allocates from declared counts

In `reader/lfc2.rs`, `numconst`, `ndeltas`, `n_segments`, each segment length
and `ntokens` are checked only against large limits (5M to 20M) and then used
for `Vec::with_capacity` before any of the data is read. A tiny input can make
the reader allocate hundreds of MB briefly before it fails on EOF. Not a
crash, but cheap memory pressure for anything that loads untrusted circuits.
Growing the vectors as data is actually read would avoid it.

## Time to first find: circuit race

`JOBS=4 scripts/run-matrix.sh circuit 1200 3`: 20 minutes, 3 trials per
configuration, one core each, scored with `scripts/triage.sh`. Times are per
trial; "never" means not found within the 20 minutes. The harness had no
geometry step and no memory cap yet (NEXT.md step 3).

| config | #1 zero output count | #3 LFA2 payload length | edges (median) | execs/s (median) |
|---|---|---|---|---|
| nautilus (no seeds) | 0s, 0s, 0s | 3s, 2s, 7s | 1236 | 883 |
| bytes (seeded) | 1s, 2s, 1s | 326s, 430s, 109s | 1149 | 733 |
| bytes-cmplog (seeded) | 167s, 120s, 116s | never, 184s, 1124s | 933 | 162 |
| bytes, no seeds | 0s, 0s, 0s | never, never, never | 353 | 2717 |

No run found a crash outside these two bugs. #2 is not reachable from this
target.
