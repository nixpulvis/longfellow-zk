# Next: bytes vs grammar on the circuit target

The `circuit` target is the only one that has produced real bugs (see
FINDINGS.md) and it has no grammar mode yet. Goal: compare bytes and grammar
there, scored on distinct real bugs and time to first find.

1. **Grammar.** Add a Nautilus grammar for the circuit target's input, in
   `src/grammar.rs` alongside the CBOR and mdoc grammars.
2. **Assembler.** Turn the grammar's output into the target's input bytes, the
   way `src/edn.rs` does for the mdoc grammar.
3. **Harness.** Add a `nautilus` mode to `src/bin/circuit.rs`. For both modes,
   after a successful parse also run `compute_id` and the verifier's geometry
   step, and cap fuzzer memory so allocation failures count as crashes.
4. **Race.** Run bytes and grammar fully detached (background jobs here stop
   at 2 hours), equal cores and time, then score each with
   `scripts/triage.sh` (distinct signatures plus first-found time).
