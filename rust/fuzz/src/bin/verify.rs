//! Full mdoc verifier (`run_mdoc_verifier`) on a fixed circuit, public key,
//! transcript and attribute set, fuzzing only the proof.
//!
//! Oracle: the verifier must reject every proof that differs from the honest
//! one. An accepted modified proof is either a soundness bug or proof
//! malleability. Both are findings.
//!
//! - `bytes`: havoc on the raw proof, seeded with the honest proof.
//! - `arbitrary`: the input decodes (via `arbitrary`) to a list of typed edits
//!   applied to the parsed honest proof: set a field element, flip a Merkle
//!   bit, change a MAC. The result always parses, so every execution reaches
//!   the sumcheck/Ligero checks instead of dying in the reader.

use std::sync::OnceLock;

use longfellow_fuzz::{fixtures, runner};
use mdoc_zk_runtime::MdocProof;
use runtime_algebra::{gf2_128::Gf2_128Field, p256::P256Field};

fn check(f: &fixtures::ProofFixture, proof: &[u8]) {
    if proof == f.proof.as_slice() {
        return;
    }
    if f.verify(proof).is_ok() {
        panic!(
            "verifier accepted a modified proof ({} bytes, honest is {})",
            proof.len(),
            f.proof.len()
        );
    }
}

fn bytes(data: &[u8]) {
    check(fixtures::proof_fixture(), data);
}

fn honest_parsed() -> &'static MdocProof<Gf2_128Field, P256Field> {
    static P: OnceLock<MdocProof<Gf2_128Field, P256Field>> = OnceLock::new();
    P.get_or_init(|| {
        let f = fixtures::proof_fixture();
        let (used, p) = f.read(&f.proof).expect("honest proof parses");
        assert_eq!(used, f.proof.len());
        p
    })
}

fn arbitrary(data: &[u8]) {
    let f = fixtures::proof_fixture();
    let mut p = honest_parsed().clone();
    longfellow_fuzz::proof_edits::decode_and_apply(data, &mut p, f, 8);
    // Edits that leave a subfield make the writer refuse; nothing to test.
    let Ok(bytes) = f.write(&p) else { return };
    check(f, &bytes);
}

fn main() {
    runner::main(runner::Target {
        name: "verify",
        bytes: Some(bytes),
        arbitrary: Some(arbitrary),
        seeds: || vec![fixtures::proof_fixture().proof.clone()],
        setup: || {
            fixtures::proof_fixture();
            honest_parsed();
        },
        ..Default::default()
    });
}
