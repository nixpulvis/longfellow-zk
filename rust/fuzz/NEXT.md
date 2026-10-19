# Next: bytes vs grammar on the circuit target

## Why this target

The grammar only proves its worth by finding real bugs faster than byte
fuzzing, or finding more of them. Coverage alone doesn't count.

On mdoc, a 2-hour head-to-head (seeded bytes vs Nautilus from scratch, one
core each) found no bugs in either mode. Nautilus kept a small coverage lead
(621 vs 593 edges) with 24x fewer executions, but that is a draw on the
measure that matters. `parse_mdoc` looks robust: it checks types, lengths and
duplicate keys carefully.

The `circuit` target (archive and circuit readers in `core_proto`) is the only
place real bugs have shown up so far (see FINDINGS.md). Bytes mode found the
zero output count panic within about a second. It has no grammar mode yet, so
it is where a fair race is still possible.

The readers check declared counts only against large upper limits, and
`validate_raw_circuit` checks counts, not whether the circuit is internally
consistent. So a circuit that parses can still be inconsistent in ways that
only matter when the verifier uses it. Reaching that code needs inputs that
get through the parser, which is what a grammar is for.

## Steps

1. **Grammar.** Done: `grammar::circuit` in `src/grammar.rs`. It covers
   LFA2, LFA1, LFC1 and LFC2. About 45% of generated circuits and 40% of
   generated archives parse (`circuit_grammar_reaches_past_parsing` checks
   this); the rest are deliberate near-misses. Plain generation already hits
   FINDINGS.md #1 (zero output count) and #3 (LFA2 payload length).

2. **Assembler.** Done: `src/circasm.rs`, in the uninstrumented library.
   Labels give counts, lengths, SHA-256 and in-bounds indices; round-trip
   tests check its output against `CircuitWriter` and `to_bytes_lfa2`.

3. **Harness.** In `src/bin/circuit.rs`:
   - Done: `nautilus` mode (grammar plus assembler), alongside `bytes`.
   - Done: an archive that parses has its `sig` and `hash` entries read as
     circuits, as `decompress_circuits` does. This applies to bytes mode too.
   - For both modes, after a successful parse also run `compute_id` and the
     verifier's geometry step (`ZkVerifier::new(..).geometry(..)`), which is
     what the verifier does with a loaded circuit before it reads a proof.
     The grammar keeps `npublic_input <= ninput` in the common case, which
     `geometry` asserts.
   - Cap fuzzer memory so allocation failures become crashes in both modes,
     instead of quietly exhausting RAM. The LFA2 payload-length bug and the
     LFC2 pre-allocation issue are both allocation problems.
   - Seed bytes mode with LFA2 artifacts only. LFA1 decompresses to ~88 MB
     and made each execution take seconds.

4. **Race.** A first one is done (below); what's left is a longer one once
   the step 3 harness work is in.

### First race (20 min, 3 trials per config, one core each)

`JOBS=4 scripts/run-matrix.sh circuit 1200 3`, before the geometry step and
the memory cap. Times are first finds from `scripts/triage.sh`, per trial.

| config | edges (median) | execs/s | #1 zero noutput | #3 LFA2 payload length |
|---|---|---|---|---|
| nautilus (no seeds) | 1236 | 883 | 0s, 0s, 0s | 3s, 2s, 7s |
| bytes (seeded) | 1149 | 733 | 1s, 2s, 1s | 326s, 430s, 109s |
| bytes-cmplog (seeded) | 933 | 162 | 167s, 120s, 116s | never, 184s, 1124s |
| bytes, no seeds | 353 | 2717 | 0s, 0s, 0s | never in 3 trials |

The grammar finds #3 about 50x sooner than seeded bytes, with more
coverage in every trial and a higher execution rate (the seeded runs spend
time in the 1.5 MB archive seed). Bytes from scratch runs fastest but stays
at the headers. No run found anything beyond the two known bugs, so the open
question is still whether either mode finds new bugs past the parser.

The plan for the race: Bytes and grammar on equal cores and equal time, fully detached:
background jobs in this environment stop at 2 hours, and an earlier run
lost its Nautilus process that way. Score each run with
`scripts/triage.sh`, which groups crashes by signature and reports when
each was first found. The comparison is distinct real bugs per mode and
time to first find for each. One trial is an anecdote; repeat trials
separate luck from a real edge.
