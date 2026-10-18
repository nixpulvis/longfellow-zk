//! Proof deserialization (`MdocProof::read`) with the geometry of a real
//! circuit. Oracle: any proof the reader accepts must re-serialize to exactly
//! the bytes it consumed. If not, the encoding is malleable: two different
//! byte strings decode to the same proof.
//!
//! The reader is generic, so it is called here (in the instrumented harness)
//! rather than through the fixture, to get coverage of its monomorphized code.

use longfellow_fuzz::{fixtures, runner};
use mdoc_zk_runtime::MdocProof;

fn target(data: &[u8]) {
    let f = fixtures::proof_fixture();
    let Ok((rest, proof)) = MdocProof::read(data, &f.geom, &f.gf2, &f.sf_hash, f.p256, &f.sf_sig)
    else {
        return;
    };
    let used = data.len() - rest.len();
    match proof.write(&f.geom, &f.gf2, &f.sf_hash, f.p256, &f.sf_sig) {
        Ok(bytes) => assert!(
            bytes == data[..used],
            "non-canonical proof encoding accepted: {used} bytes read, re-encoding differs"
        ),
        Err(e) => panic!("reader accepted a proof the writer rejects: {e}"),
    }
}

fn main() {
    runner::main(runner::Target {
        name: "proof",
        bytes: Some(target),
        seeds: || vec![fixtures::proof_fixture().proof.clone()],
        setup: || {
            fixtures::proof_fixture();
        },
        ..Default::default()
    });
}
