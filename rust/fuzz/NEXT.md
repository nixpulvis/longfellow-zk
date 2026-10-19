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

1. **Grammar.** A Nautilus grammar for the circuit target's input, in
   `src/grammar.rs` next to the CBOR and mdoc grammars, written the same way
   (templates with `@NT@` references, weighted alternatives, regex rules for
   fixed-size blobs). It should follow the archive format and the circuit
   format inside it, so generated inputs reach past the header checks.

2. **Assembler.** The format is mostly ULEB128 counts and fixed-size blobs
   whose sizes a context-free grammar can't compute, so the grammar emits a
   small token language and an assembler fills in the bytes. Same pattern as
   `src/edn.rs` for mdoc. It lives in the uninstrumented library so it adds no
   coverage of its own. A draft exists outside the repo; it needs review and
   tests before it goes on the branch.

3. **Harness.** In `src/bin/circuit.rs`:
   - Add a `nautilus` mode (grammar plus assembler), alongside `bytes`.
   - For both modes, after a successful parse also run `compute_id` and the
     verifier's geometry step (`ZkVerifier::new(..).geometry(..)`), which is
     what the verifier does with a loaded circuit before it reads a proof.
   - Cap fuzzer memory so allocation failures become crashes in both modes,
     instead of quietly exhausting RAM. The LFA2 payload-length bug and the
     LFC2 pre-allocation issue are both allocation problems.
   - Seed bytes mode with LFA2 artifacts only. LFA1 decompresses to ~88 MB
     and made each execution take seconds.

4. **Race.** Bytes and grammar on equal cores and equal time, fully detached:
   background jobs in this environment stop at 2 hours, and an earlier run
   lost its Nautilus process that way. Score each run with
   `scripts/triage.sh`, which groups crashes by signature and reports when
   each was first found. The comparison is distinct real bugs per mode and
   time to first find for each. One trial is an anecdote; repeat trials
   separate luck from a real edge.
