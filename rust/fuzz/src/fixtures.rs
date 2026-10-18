//! Shared seeds and expensive fixtures.

use mdoc_zk_testcases::{TestDataStatic, ALL_TEST_CASES};

/// Every real mdoc in the test vectors.
pub fn mdocs() -> Vec<&'static TestDataStatic> {
    ALL_TEST_CASES.iter().map(|c| c.data).collect()
}

pub fn keyword_tokens() -> Vec<Vec<u8>> {
    let mut t: Vec<Vec<u8>> = crate::grammar::KEYWORDS
        .iter()
        .map(|k| {
            // Include the CBOR text head so the token lands as a whole item.
            let mut v = Vec::new();
            mdoc_zk_circuits::cbor::encode_cbor_string_into(k.as_bytes(), &mut v);
            v
        })
        .collect();
    t.push(vec![0xd8, 0x18]); // tag 24
    t.push(vec![0xd8, 0x18, 0x59]); // tag 24 + bstr with 2-byte length
    t.push(vec![0x58, 0x20]); // bstr(32)
    t.push(vec![0x58, 0x40]); // bstr(64)
    t.push(vec![0x43, 0xa1, 0x01, 0x26]); // <<{1: -7}>>
    t
}

use std::sync::OnceLock;

use mdoc_zk_runtime::{
    decompress_circuits, provider, req_attr, MdocProof, MdocProofGeometry, RequestedAttribute,
    ZkSpecStruct,
};
use runtime_algebra::{
    gf2_128::Gf2_128Field,
    lch14_reed_solomon::Lch14InterpolatorFactory,
    p256::{P256Field, P256Subfield},
    reed_solomon::FftInterpolatorFactory,
    subfield::BinarySubfield,
    SupportsFFT,
};
use runtime_zk::{common::ZkContext, ZkVerifier};

/// A stored (prior-version) circuit, the inputs that go with it, and one
/// valid proof. Built once before the fuzzer forks.
pub struct ProofFixture {
    pub spec: ZkSpecStruct,
    pub compressed: Vec<u8>,
    pub geom: MdocProofGeometry,
    pub test: &'static TestDataStatic,
    pub attrs: Vec<RequestedAttribute>,
    pub doc_type: &'static str,
    /// A proof the verifier accepts for exactly these inputs.
    pub proof: Vec<u8>,
    pub gf2: Gf2_128Field,
    pub sf_hash: BinarySubfield,
    pub p256: &'static P256Field,
    pub sf_sig: P256Subfield<'static>,
}

impl ProofFixture {
    pub fn read(&self, bytes: &[u8]) -> Result<(usize, MdocProof<Gf2_128Field, P256Field>), String> {
        MdocProof::read(bytes, &self.geom, &self.gf2, &self.sf_hash, self.p256, &self.sf_sig)
            .map(|(rest, p)| (bytes.len() - rest.len(), p))
    }

    pub fn write(&self, proof: &MdocProof<Gf2_128Field, P256Field>) -> Result<Vec<u8>, String> {
        proof.write(&self.geom, &self.gf2, &self.sf_hash, self.p256, &self.sf_sig)
    }

    pub fn verify(&self, proof: &[u8]) -> Result<(), mdoc_zk_runtime::MdocVerifierErrorCode> {
        mdoc_zk_runtime::verifier::run_mdoc_verifier(
            &self.spec,
            &self.compressed,
            self.test.pkx,
            self.test.pky,
            self.test.transcript,
            &self.attrs,
            self.test.now,
            self.doc_type,
            proof,
        )
    }
}

pub fn proof_fixture() -> &'static ProofFixture {
    static F: OnceLock<ProofFixture> = OnceLock::new();
    F.get_or_init(build_proof_fixture)
}

fn build_proof_fixture() -> ProofFixture {
    let started = std::time::Instant::now();
    // Newest circuit that ships as a stored artifact (no circuit compile).
    let (version, _) = *provider::all_prior_versions_and_attrs()
        .last()
        .expect("at least one stored circuit");
    let provided = provider::materialize(version, 1).expect("materialize stored circuit");
    let spec = provided.spec;
    let compressed = provided.compressed;

    let p256: &'static P256Field = Box::leak(Box::new(P256Field::new()));
    let gf2 = Gf2_128Field::new();
    let sf_hash = BinarySubfield::new(&core_algebra::proto::GF2_16_BASIS_V1);
    let sf_sig = P256Subfield::new(p256);

    // Same geometry derivation as run_mdoc_verifier_inner.
    let geom = {
        let p256_2 = runtime_algebra::fp2::Fp2Field::new(p256);
        let make_sig =
            FftInterpolatorFactory::new(p256, &p256_2, p256_2.omega(), p256_2.omega_order());
        let make_hash = Lch14InterpolatorFactory::new(&gf2, &sf_hash);
        let (config_hash, config_sig) = mdoc_zk_runtime::ligero_configs(&spec);
        let (c_sig, c_hash) =
            decompress_circuits(&compressed, p256, &gf2).expect("decompress circuits");
        let geom_hash = ZkVerifier::<2, _>::new(c_hash, config_hash).geometry(&ZkContext {
            f: &gf2,
            make_interpolator: &make_hash,
        });
        let geom_sig = ZkVerifier::<4, _>::new(c_sig, config_sig).geometry(&ZkContext {
            f: p256,
            make_interpolator: &make_sig,
        });
        MdocProofGeometry { geom_hash, geom_sig }
    };

    let test = &mdoc_zk_testcases::BIRTHDATE_1971_09_01_MDOC_3;
    let doc_type = "org.iso.18013.5.1.mDL";
    let attrs = vec![req_attr(
        "org.iso.18013.5.1",
        "family_name",
        [0x6a, b'M', b'u', b's', b't', b'e', b'r', b'm', b'a', b'n', b'n'],
    )];

    let cache = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("target/fixtures")
        .join(format!("proof-{}.bin", spec.combined_hash_hex()));
    let proof = match std::fs::read(&cache) {
        Ok(p) => p,
        Err(_) => {
            eprintln!("generating fixture proof for v{version} (one time)...");
            let mut rng = runtime_random::DeterministicRng::new(42);
            let p = mdoc_zk_runtime::prover::run_mdoc_prover_inner(
                &spec, &compressed, test.mdoc, test.pkx, test.pky, test.transcript, &attrs,
                test.now, doc_type, &mut rng,
            )
            .expect("fixture proof generation failed");
            std::fs::create_dir_all(cache.parent().unwrap()).ok();
            std::fs::write(&cache, &p).ok();
            p
        }
    };

    let f = ProofFixture {
        spec,
        compressed,
        geom,
        test,
        attrs,
        doc_type,
        proof,
        gf2,
        sf_hash,
        p256,
        sf_sig,
    };
    let t = std::time::Instant::now();
    let _ = decompress_circuits(&f.compressed, f.p256, &f.gf2).expect("decompress");
    let decompress = t.elapsed();
    let t = std::time::Instant::now();
    f.verify(&f.proof).expect("fixture proof must verify");
    eprintln!(
        "proof fixture: v{} ({} attr), proof {} bytes, setup {:.1?}, one verify {:.1?} (of which circuit decompress+parse ~{:.1?})",
        version,
        f.spec.num_attributes,
        f.proof.len(),
        started.elapsed(),
        t.elapsed(),
        decompress
    );
    f
}
