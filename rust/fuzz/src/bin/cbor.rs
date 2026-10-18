//! Host-side CBOR parser (`mdoc_zk_circuits::cbor::parse::CborParser`).

use longfellow_fuzz::{edn, fixtures, grammar, runner};
use mdoc_zk_circuits::cbor::parse::CborParser;

fn target(data: &[u8]) {
    if let Some(limit) = longfellow_fuzz::max_depth_from_env() {
        if longfellow_fuzz::cbor_depth_exceeds(data, limit) {
            return;
        }
    }
    let _ = CborParser::new(data).parse_exact();
}

fn nautilus(text: &[u8]) {
    if let Some(cbor) = edn::assemble(text) {
        target(&cbor);
    }
}

fn seeds() -> Vec<Vec<u8>> {
    let mut s: Vec<Vec<u8>> = fixtures::mdocs().iter().map(|d| d.mdoc.to_vec()).collect();
    s.push(vec![0x00]);
    s.push(vec![0x82, 0x01, 0xa1, 0x61, b'a', 0xf5]);
    s
}

fn main() {
    runner::main(runner::Target {
        name: "cbor",
        bytes: Some(target),
        nautilus: Some((grammar::cbor, nautilus)),
        seeds,
        tokens: fixtures::keyword_tokens,
        ..Default::default()
    });
}
