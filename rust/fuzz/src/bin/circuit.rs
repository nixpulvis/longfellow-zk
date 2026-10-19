//! Circuit archive (LFA1/LFA2) and circuit (LFC1/LFC2) readers. The first
//! byte selects the reader; the rest is the input. An archive that parses has
//! its "sig" and "hash" entries read as circuits, as `decompress_circuits`
//! does for the verifier. A circuit that parses then has its ID computed (what
//! the reader does when asked to enforce one) and its proof geometry derived
//! (what the verifier does before reading a proof), so circuits that parse but
//! are inconsistent get exercised too.
//!
//! Single allocations above `LF_FUZZ_MALLOC_LIMIT_MB` (default 2048) abort,
//! so untrusted sizes become crashes regardless of the machine's memory.
//!
//! Seeds are one stored LFA2 archive (1.5 MB
//! decompressed) and its two LFC2 circuits. LFA1 artifacts decompress to
//! ~88 MB each, which made every execution take seconds; the LFC1 path is
//! still reachable through the archive reader.
//!
//! The `nautilus` mode generates inputs from `grammar::circuit` and
//! assembles them with `circasm`.

use std::io::Read;
use std::sync::OnceLock;

use core_proto::{
    archive::CircuitArchive,
    circuit::compute_id,
    reader::CircuitReader,
    FieldID,
};
use longfellow_fuzz::{alloc_limit, circasm, grammar, runner};
use mdoc_zk_runtime::zk_spec::CURRENT_ZK_SPECS;
use runtime_algebra::{
    fp2::Fp2Field, gf2_128::Gf2_128Field, lch14_reed_solomon::Lch14InterpolatorFactory,
    p256::P256Field, reed_solomon::FftInterpolatorFactory, subfield::BinarySubfield, SupportsFFT,
};
use runtime_zk::{common::ZkContext, ZkVerifier};

#[global_allocator]
static ALLOC: alloc_limit::LimitAlloc = alloc_limit::LimitAlloc;

fn fields() -> &'static (P256Field, Gf2_128Field) {
    static F: OnceLock<(P256Field, Gf2_128Field)> = OnceLock::new();
    F.get_or_init(|| (P256Field::new(), Gf2_128Field::new()))
}

fn sig(bytes: &[u8]) {
    let p256 = &fields().0;
    let Ok((c, _)) = CircuitReader::new(p256, FieldID::P256).from_bytes(bytes, false) else {
        return;
    };
    let _ = compute_id(p256, &c.raw);
    // Same setup as run_mdoc_verifier_inner, with the current spec's config.
    let p256_2 = Fp2Field::new(p256);
    let make = FftInterpolatorFactory::new(p256, &p256_2, p256_2.omega(), p256_2.omega_order());
    let _ = ZkVerifier::<4, _>::new(c, CURRENT_ZK_SPECS[0].ligero_sig).geometry(&ZkContext {
        f: p256,
        make_interpolator: &make,
    });
}

fn hash(bytes: &[u8]) {
    let gf2 = &fields().1;
    let Ok((c, _)) = CircuitReader::new(gf2, FieldID::Gf2_128).from_bytes(bytes, false) else {
        return;
    };
    let _ = compute_id(gf2, &c.raw);
    let sf = BinarySubfield::new(&core_algebra::proto::GF2_16_BASIS_V1);
    let make = Lch14InterpolatorFactory::new(gf2, &sf);
    let _ = ZkVerifier::<2, _>::new(c, CURRENT_ZK_SPECS[0].ligero_hash).geometry(&ZkContext {
        f: gf2,
        make_interpolator: &make,
    });
}

fn target(data: &[u8]) {
    let Some((&sel, rest)) = data.split_first() else { return };
    match sel % 3 {
        0 => {
            let Ok(archive) = CircuitArchive::from_bytes(rest) else { return };
            if let Some(e) = archive.get("sig") {
                sig(&e.payload);
            }
            if let Some(e) = archive.get("hash") {
                hash(&e.payload);
            }
        }
        1 => sig(rest),
        _ => hash(rest),
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
        setup: alloc_limit::init,
        // compute_id hashes every term: about 1.8 s for a real archive.
        timeout_ms: 10_000,
        ..Default::default()
    });
}
