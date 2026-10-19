//! Circuit archive (LFA1/LFA2) and circuit (LFC1/LFC2) readers. The first
//! byte selects the reader; the rest is the input. An archive that parses has
//! its "sig" and "hash" entries read as circuits, as `decompress_circuits`
//! does for the verifier. Seeds are one stored LFA2 archive (1.5 MB
//! decompressed) and its two LFC2 circuits. LFA1 artifacts decompress to
//! ~88 MB each, which made every execution take seconds; the LFC1 path is
//! still reachable through the archive reader.
//!
//! The `nautilus` mode generates inputs from `grammar::circuit` and
//! assembles them with `circasm`.

use std::io::Read;
use std::sync::OnceLock;

use core_proto::{archive::CircuitArchive, reader::CircuitReader, FieldID};
use longfellow_fuzz::{circasm, grammar, runner};
use runtime_algebra::{gf2_128::Gf2_128Field, p256::P256Field};

fn fields() -> &'static (P256Field, Gf2_128Field) {
    static F: OnceLock<(P256Field, Gf2_128Field)> = OnceLock::new();
    F.get_or_init(|| (P256Field::new(), Gf2_128Field::new()))
}

fn target(data: &[u8]) {
    let Some((&sel, rest)) = data.split_first() else { return };
    let (p256, gf2) = fields();
    match sel % 3 {
        0 => {
            let Ok(archive) = CircuitArchive::from_bytes(rest) else { return };
            if let Some(e) = archive.get("sig") {
                let _ = CircuitReader::new(p256, FieldID::P256).from_bytes(&e.payload, false);
            }
            if let Some(e) = archive.get("hash") {
                let _ = CircuitReader::new(gf2, FieldID::Gf2_128).from_bytes(&e.payload, false);
            }
        }
        1 => {
            let _ = CircuitReader::new(p256, FieldID::P256).from_bytes(rest, false);
        }
        _ => {
            let _ = CircuitReader::new(gf2, FieldID::Gf2_128).from_bytes(rest, false);
        }
    }
}

fn nautilus(text: &[u8]) {
    if let Some(bytes) = circasm::assemble(text) {
        target(&bytes);
    }
}

fn seeds() -> Vec<Vec<u8>> {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../applications/mdoc_zk/artifacts/circuits");
    let mut paths: Vec<_> = std::fs::read_dir(dir)
        .expect("artifacts dir")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .collect();
    paths.sort();
    let mut out = Vec::new();
    for path in paths
        .iter()
        .filter(|p| p.extension().is_some_and(|e| e == "lfa2"))
        .take(1)
    {
        let mut raw = Vec::new();
        let compressed = std::fs::read(path).unwrap();
        if zstd::stream::read::Decoder::new(&compressed[..])
            .and_then(|mut d| d.read_to_end(&mut raw))
            .is_err()
        {
            continue;
        }
        if let Ok(archive) = CircuitArchive::from_bytes(&raw) {
            for e in &archive.entries {
                let sel = if e.name == "sig" { 1 } else { 2 };
                out.push([&[sel][..], &e.payload].concat());
            }
        }
        out.push([&[0u8][..], &raw].concat());
    }
    eprintln!("circuit seeds: {} ({} bytes total)", out.len(), out.iter().map(Vec::len).sum::<usize>());
    out
}

fn main() {
    runner::main(runner::Target {
        name: "circuit",
        bytes: Some(target),
        nautilus: Some((grammar::circuit, nautilus)),
        seeds,
        ..Default::default()
    });
}
