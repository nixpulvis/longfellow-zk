//! Host-side mdoc parser (`mdoc_zk_circuits::cbor::mdoc::parse_mdoc`), which
//! the prover runs on the holder's credential to build the circuit witness.
//!
//! Besides crashes, successful parses are checked against the invariants in
//! `longfellow_fuzz::mdoc_props`.

use longfellow_fuzz::{edn, fixtures, grammar, runner};
use mdoc_zk_circuits::cbor::mdoc::parse_mdoc;
use runtime_algebra::RuntimeNat;

const DOC_TYPE: &str = "org.iso.18013.5.1.mDL";

fn target(data: &[u8]) {
    if let Some(limit) = longfellow_fuzz::max_depth_from_env() {
        if longfellow_fuzz::cbor_depth_exceeds(data, limit) {
            return;
        }
    }
    let transcript = mdoc_zk_testcases::TEST_DATA.transcript;
    if let Ok(parsed) = parse_mdoc::<RuntimeNat<4>>(data, transcript, DOC_TYPE) {
        longfellow_fuzz::mdoc_props::check(&parsed);
    }
}

fn nautilus(text: &[u8]) {
    if let Some(cbor) = edn::assemble(text) {
        target(&cbor);
    }
}

fn seeds() -> Vec<Vec<u8>> {
    fixtures::mdocs().iter().map(|d| d.mdoc.to_vec()).collect()
}

fn main() {
    runner::main(runner::Target {
        name: "mdoc",
        bytes: Some(target),
        nautilus: Some((grammar::mdoc, nautilus)),
        seeds,
        tokens: fixtures::keyword_tokens,
        ..Default::default()
    });
}
