//! Typed edits on a parsed mdoc proof, decoded from fuzzer bytes with
//! `arbitrary`. Used by the verify target's `arbitrary` mode. Lives in the
//! uninstrumented library so the decoder adds no coverage of its own.

use arbitrary::{Arbitrary, Unstructured};
use core_proto::SerializableField;
use mdoc_zk_runtime::MdocProof;
use runtime_algebra::{gf2_128::Gf2_128Field, p256::P256Field, ElementOf};
use runtime_proto::ZkProof;

use crate::fixtures::ProofFixture;

/// Decode up to `max` edits from `data` and apply them to `proof`.
pub fn decode_and_apply(
    data: &[u8],
    proof: &mut MdocProof<Gf2_128Field, P256Field>,
    f: &ProofFixture,
    max: usize,
) {
    let mut u = Unstructured::new(data);
    let mut n = 0;
    while !u.is_empty() && n < max {
        let Ok(e) = Edit::arbitrary(&mut u) else { break };
        apply(proof, &e, f);
        n += 1;
    }
}

#[derive(Arbitrary, Debug)]
pub enum Edit {
    Mac { i: u8, v: u128 },
    MacBit { i: u8, bit: u8 },
    HashElt { section: u8, idx: u32, v: [u8; 16] },
    SigElt { section: u8, idx: u32, v: [u8; 32] },
    HashSwap { section: u8, a: u32, b: u32 },
    SigSwap { section: u8, a: u32, b: u32 },
    HashRootBit { bit: u16 },
    SigRootBit { bit: u16 },
    HashPathBit { idx: u32, bit: u16 },
    SigPathBit { idx: u32, bit: u16 },
    HashNonceBit { idx: u32, bit: u16 },
    SigNonceBit { idx: u32, bit: u16 },
}

/// Mutable references to every field element in a proof, grouped by section:
/// 0 sumcheck round evaluations, 1 layer claims, 2 y_ldt, 3 y_dot,
/// 4 y_quad_0, 5 y_quad_2, 6 column openings (req).
fn section<'a, const W: usize, F: core_proto::SerializableField>(
    p: &'a mut ZkProof<W, F>,
    s: u8,
) -> Vec<&'a mut ElementOf<F>> {
    match s % 7 {
        0 => p
            .sumcheck_proof
            .layers
            .iter_mut()
            .flat_map(|l| l.hp.iter_mut().flatten().flat_map(|r| r.evaluations.iter_mut()))
            .collect(),
        1 => p.sumcheck_proof.layers.iter_mut().flat_map(|l| l.claims.iter_mut()).collect(),
        2 => p.com_proof.y_ldt.iter_mut().collect(),
        3 => p.com_proof.y_dot.iter_mut().collect(),
        4 => p.com_proof.y_quad_0.iter_mut().collect(),
        5 => p.com_proof.y_quad_2.iter_mut().collect(),
        _ => p.com_proof.req.iter_mut().collect(),
    }
}

fn set_elt<const W: usize, F: SerializableField>(
    p: &mut ZkProof<W, F>,
    f: &F,
    s: u8,
    idx: u32,
    v: &[u8],
) {
    let mut elts = section(p, s);
    if elts.is_empty() {
        return;
    }
    let n = elts.len();
    if let Ok(e) = f.bytes_to_element(v) {
        *elts[idx as usize % n] = e;
    }
}

fn swap<const W: usize, F: SerializableField>(p: &mut ZkProof<W, F>, s: u8, a: u32, b: u32)
where
    ElementOf<F>: Clone,
{
    let mut elts = section(p, s);
    let n = elts.len();
    if n < 2 {
        return;
    }
    let (a, b) = (a as usize % n, b as usize % n);
    let va = elts[a].clone();
    let vb = elts[b].clone();
    *elts[a] = vb;
    *elts[b] = va;
}

fn flip(bytes: &mut [u8], bit: u16) {
    if bytes.is_empty() {
        return;
    }
    let bit = bit as usize % (bytes.len() * 8);
    bytes[bit / 8] ^= 1 << (bit % 8);
}

pub fn apply(
    p: &mut MdocProof<Gf2_128Field, P256Field>,
    e: &Edit,
    f: &ProofFixture,
) {
    match *e {
        Edit::Mac { i, v } => p.macs[i as usize % 6] = v,
        Edit::MacBit { i, bit } => p.macs[i as usize % 6] ^= 1u128 << (bit % 128),
        Edit::HashElt { section, idx, ref v } => set_elt(&mut p.proof_hash, &f.gf2, section, idx, v),
        Edit::SigElt { section, idx, ref v } => set_elt(&mut p.proof_sig, f.p256, section, idx, v),
        Edit::HashSwap { section, a, b } => swap(&mut p.proof_hash, section, a, b),
        Edit::SigSwap { section, a, b } => swap(&mut p.proof_sig, section, a, b),
        Edit::HashRootBit { bit } => flip(&mut p.proof_hash.com.root.data, bit),
        Edit::SigRootBit { bit } => flip(&mut p.proof_sig.com.root.data, bit),
        Edit::HashPathBit { idx, bit } => {
            let path = &mut p.proof_hash.com_proof.merkle.path;
            if !path.is_empty() {
                let n = path.len();
                flip(&mut path[idx as usize % n].data, bit);
            }
        }
        Edit::SigPathBit { idx, bit } => {
            let path = &mut p.proof_sig.com_proof.merkle.path;
            if !path.is_empty() {
                let n = path.len();
                flip(&mut path[idx as usize % n].data, bit);
            }
        }
        Edit::HashNonceBit { idx, bit } => {
            let nonces = &mut p.proof_hash.com_proof.merkle.nonce;
            if !nonces.is_empty() {
                let n = nonces.len();
                flip(&mut nonces[idx as usize % n].bytes, bit);
            }
        }
        Edit::SigNonceBit { idx, bit } => {
            let nonces = &mut p.proof_sig.com_proof.merkle.nonce;
            if !nonces.is_empty() {
                let n = nonces.len();
                flip(&mut nonces[idx as usize % n].bytes, bit);
            }
        }
    }
}

