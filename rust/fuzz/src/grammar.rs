//! Nautilus grammars. The CBOR and mdoc grammars emit the EDN-like notation
//! from [`crate::edn`]; the circuit grammar emits [`crate::circasm`] text.
//!
//! Rules are written as templates: `@NT@` references a nonterminal and
//! everything else is literal (Nautilus's own `{`, `}` and `\` are escaped
//! automatically). Repeating a rule raises its weight, since Nautilus picks
//! uniformly among a nonterminal's rules. Fixed-width hex blobs (digests,
//! nonces, signatures) are regex rules, so each one is a single tree node
//! instead of dozens.

use libafl::common::nautilus::grammartec::context::Context;
use libafl::generators::nautilus::NautilusContext;

#[derive(Default)]
pub struct Grammar {
    start: Option<String>,
    rules: Vec<(String, Vec<u8>)>,
    regexes: Vec<(String, String)>,
}

impl Grammar {
    fn new(start: &str) -> Self {
        Self {
            start: Some(start.to_string()),
            ..Self::default()
        }
    }

    /// Add `nt -> template`, where `@X@` in the template is nonterminal `X`.
    fn r(&mut self, nt: &str, template: &str) -> &mut Self {
        self.rules.push((nt.to_string(), compile_template(template)));
        self
    }

    /// Add the same rule `n` times (weighting).
    fn rw(&mut self, n: usize, nt: &str, template: &str) -> &mut Self {
        for _ in 0..n {
            self.r(nt, template);
        }
        self
    }

    fn regex(&mut self, nt: &str, re: &str) -> &mut Self {
        self.regexes.push((nt.to_string(), re.to_string()));
        self
    }

    /// Build the Nautilus context. `max_len` bounds the tree size.
    pub fn context(&self, max_len: usize) -> NautilusContext {
        let mut ctx = Context::new();
        for (nt, rule) in &self.rules {
            ctx.add_rule(nt, rule);
        }
        for (nt, re) in &self.regexes {
            ctx.add_regex(nt, re);
        }
        let start = self.start.as_deref().expect("grammar has a start symbol");
        ctx.add_rule("START", format!("{{{start}}}").as_bytes());
        ctx.initialize(max_len);
        NautilusContext { ctx }
    }

    /// Human-readable dump, one rule per line (for inspection and docs).
    pub fn dump(&self) -> String {
        let mut s = String::new();
        for (nt, rule) in &self.rules {
            s.push_str(&format!("{nt} -> {}\n", String::from_utf8_lossy(rule)));
        }
        for (nt, re) in &self.regexes {
            s.push_str(&format!("{nt} -> /{re}/\n"));
        }
        s
    }
}

fn compile_template(t: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let mut parts = t.split('@');
    let mut is_nt = false;
    // split('@') alternates literal / nonterminal / literal ...
    if let Some(first) = parts.next() {
        escape_into(first, &mut out);
    }
    for part in parts {
        is_nt = !is_nt;
        if is_nt {
            assert!(
                !part.is_empty() && part.chars().next().unwrap().is_ascii_uppercase(),
                "bad nonterminal reference {part:?} in {t:?}"
            );
            out.push(b'{');
            out.extend_from_slice(part.as_bytes());
            out.push(b'}');
        } else {
            escape_into(part, &mut out);
        }
    }
    assert!(!is_nt, "unbalanced @ in template {t:?}");
    out
}

fn escape_into(lit: &str, out: &mut Vec<u8>) {
    for b in lit.bytes() {
        if matches!(b, b'{' | b'}' | b'\\') {
            out.push(b'\\');
        }
        out.push(b);
    }
}

/// Keywords that appear in mdoc / COSE structures. Used both as text-string
/// leaves in the generic grammar and as a byte-fuzzer dictionary.
pub const KEYWORDS: &[&str] = &[
    "version",
    "1.0",
    "documents",
    "status",
    "docType",
    "org.iso.18013.5.1.mDL",
    "org.iso.18013.5.1",
    "issuerSigned",
    "nameSpaces",
    "issuerAuth",
    "deviceSigned",
    "deviceAuth",
    "deviceSignature",
    "deviceMac",
    "digestAlgorithm",
    "SHA-256",
    "valueDigests",
    "deviceKeyInfo",
    "deviceKey",
    "validityInfo",
    "signed",
    "validFrom",
    "validUntil",
    "digestID",
    "random",
    "elementIdentifier",
    "elementValue",
    "age_over_18",
    "family_name",
    "birth_date",
    "issue_date",
    "height",
    "nym",
];

/// Generic CBOR: every major type, all head widths, indefinite lengths,
/// mismatched declared lengths, and raw-byte escapes for malformed input.
fn add_cbor(g: &mut Grammar) {
    g.rw(3, "ITEM", "@UINT@")
        .r("ITEM", "@NINT@")
        .rw(3, "ITEM", "@BSTR@")
        .rw(3, "ITEM", "@TSTR@")
        .rw(3, "ITEM", "@ARRAY@")
        .rw(3, "ITEM", "@MAP@")
        .rw(2, "ITEM", "@TAG@")
        .r("ITEM", "@SIMPLE@")
        .r("ITEM", "@FLOAT@")
        .rw(2, "ITEM", "@EMBED@")
        .r("ITEM", "@RAW@");

    g.r("UINT", "@NUM@@ENC@");
    g.r("NINT", "-@NUMNZ@@ENC@");
    g.rw(2, "NUM", "0").rw(6, "NUM", "@NUMNZ@");
    for v in [
        "1", "2", "7", "23", "24", "25", "255", "256", "65535", "65536",
        "4294967295", "4294967296", "18446744073709551615",
    ] {
        g.r("NUMNZ", v);
    }
    g.rw(3, "NUMNZ", "@DIGNZ@@DIGS@");
    g.r("DIGS", "").r("DIGS", "@DIG@@DIGS@");
    for d in 0..10 {
        g.r("DIG", &d.to_string());
        if d > 0 {
            g.r("DIGNZ", &d.to_string());
        }
    }
    g.r("SMALL", "@DIG@").r("SMALL", "@DIGNZ@@DIG@");
    g.rw(8, "ENC", "")
        .r("ENC", "_i")
        .r("ENC", "_0")
        .r("ENC", "_1")
        .r("ENC", "_2")
        .r("ENC", "_3");
    g.rw(10, "LENOV", "").r("LENOV", "!@SMALL@").r("LENOV", "!@NUM@");

    g.rw(3, "BSTR", "h'@HEX@'@LENOV@@ENC@")
        .r("BSTR", "h'@H32@'")
        .r("BSTR", "h'@H64@'");
    g.r("HEX", "").r("HEX", "@HB@@HEX@").r("HEX", "@H32@");
    g.regex("HB", "[0-9a-f]{2}");
    g.regex("H16", "[0-9a-f]{32}");
    g.regex("H32", "[0-9a-f]{64}");
    g.regex("H64", "[0-9a-f]{128}");

    g.rw(2, "TSTR", "\"@STR@\"@LENOV@@ENC@").rw(2, "TSTR", "\"@KW@\"");
    g.r("STR", "").rw(3, "STR", "@CH@@STR@");
    g.regex("CH", "[a-zA-Z0-9_.:\\- ]");
    g.r("CH", "\\x@HD@@HD@");
    g.regex("HD", "[0-9a-f]");
    for kw in KEYWORDS {
        g.r("KW", kw);
    }

    g.r("ARRAY", "[@AOPT@]").rw(4, "ARRAY", "[@AOPT@@ITEMS@]");
    g.rw(8, "AOPT", "")
        .r("AOPT", "_ ")
        .r("AOPT", "!@SMALL@ ")
        .r("AOPT", "_0 ")
        .r("AOPT", "_1 ");
    g.rw(2, "ITEMS", "@ITEM@").r("ITEMS", "@ITEM@, @ITEMS@");

    g.r("MAP", "{@AOPT@}").rw(4, "MAP", "{@AOPT@@PAIRS@}");
    g.rw(2, "PAIRS", "@KEY@: @ITEM@").r("PAIRS", "@KEY@: @ITEM@, @PAIRS@");
    g.rw(2, "KEY", "\"@KW@\"")
        .r("KEY", "@UINT@")
        .r("KEY", "@NINT@")
        .r("KEY", "@ITEM@");

    for t in ["0", "1", "18", "24", "1004", "55799"] {
        g.r("TAGNUM", t);
    }
    g.r("TAGNUM", "@NUM@");
    g.rw(3, "TAG", "@TAGNUM@@ENC@(@ITEM@)").r("TAG", "24(<<@ITEM@>>)");

    g.rw(3, "EMBED", "<<@ITEM@>>@LENOV@@ENC@")
        .r("EMBED", "<<>>")
        .r("EMBED", "<<@ITEM@, @ITEM@>>");

    for s in ["true", "false", "null", "undefined"] {
        g.r("SIMPLE", s);
    }
    g.r("SIMPLE", "simple(@SMALL@)").r("SIMPLE", "simple(@NUM@)");

    g.r("FLOAT", "fh'@HB@@HB@'")
        .r("FLOAT", "ff'@HB@@HB@@HB@@HB@'")
        .r("FLOAT", "fd'@H8@'");
    g.regex("H8", "[0-9a-f]{16}");

    g.r("RAW", "raw'@HEX@'");
}

/// Generic CBOR grammar for the host CBOR parser.
pub fn cbor() -> Grammar {
    let mut g = Grammar::new("ITEM");
    add_cbor(&mut g);
    g
}

/// mdoc DeviceResponse grammar. The shape follows ISO 18013-5 (documents ->
/// issuerSigned/deviceSigned -> COSE_Sign1 -> tag-24 MSO), with every slot
/// also able to fall back to an arbitrary CBOR item. Near-miss variants
/// (missing, duplicated and reordered fields, wrong head widths) are listed
/// next to the well-formed ones because that's where parser bugs tend to be.
pub fn mdoc() -> Grammar {
    let mut g = Grammar::new("MDOC");
    let any = "@ITEM@";

    g.rw(4, "MDOC", "{\"version\": \"1.0\", \"documents\": [@DOC@], \"status\": 0}")
        .r("MDOC", "{\"version\": \"1.0\", \"documents\": [@DOC@]}")
        .r("MDOC", "{\"documents\": [@DOCS@]}")
        .r("MDOC", "{\"version\": \"1.0\", \"documents\": [@DOC@], \"documents\": [@DOC@]}")
        .r("MDOC", "{\"version\": \"1.0\", \"documents\": [@DOC@], @PAIRS@}")
        .r("MDOC", "{\"version\": \"1.0\", \"documents\": [], \"status\": 0}")
        .r("MDOC", any);
    g.r("DOCS", "@DOC@").r("DOCS", "@DOC@, @DOCS@");

    g.rw(
        6,
        "DOC",
        "{\"docType\": @DOCTYPE@, \"issuerSigned\": @ISSUERSIGNED@, \"deviceSigned\": @DEVICESIGNED@}",
    )
    .r("DOC", "{\"issuerSigned\": @ISSUERSIGNED@, \"deviceSigned\": @DEVICESIGNED@}")
    .r("DOC", "{\"docType\": @DOCTYPE@, \"deviceSigned\": @DEVICESIGNED@, \"issuerSigned\": @ISSUERSIGNED@}")
    .r("DOC", "{\"docType\": @DOCTYPE@, \"issuerSigned\": @ISSUERSIGNED@}")
    .r("DOC", "{\"docType\": @DOCTYPE@, \"issuerSigned\": @ISSUERSIGNED@, \"deviceSigned\": @DEVICESIGNED@, @PAIRS@}")
    .r("DOC", any);
    g.rw(4, "DOCTYPE", "\"org.iso.18013.5.1.mDL\"")
        .r("DOCTYPE", "\"@STR@\"")
        .r("DOCTYPE", any);

    g.rw(5, "ISSUERSIGNED", "{\"nameSpaces\": @NAMESPACES@, \"issuerAuth\": @ISSUERAUTH@}")
        .r("ISSUERSIGNED", "{\"issuerAuth\": @ISSUERAUTH@, \"nameSpaces\": @NAMESPACES@}")
        .r("ISSUERSIGNED", "{\"nameSpaces\": @NAMESPACES@, \"issuerAuth\": @ISSUERAUTH@, \"nameSpaces\": @NAMESPACES@}")
        .r("ISSUERSIGNED", "{\"nameSpaces\": @NAMESPACES@, \"issuerAuth\": @ISSUERAUTH@, \"issuerAuth\": @ISSUERAUTH@}")
        .r("ISSUERSIGNED", "{\"issuerAuth\": @ISSUERAUTH@}")
        .r("ISSUERSIGNED", any);

    g.rw(5, "NAMESPACES", "{@NSNAME@: [@ISITEMS@]}")
        .r("NAMESPACES", "{@NSNAME@: [@ISITEMS@], @NSNAME@: [@ISITEMS@]}")
        .r("NAMESPACES", "{@NSNAME@: []}")
        .r("NAMESPACES", "{@NSNAME@: @ITEM@}")
        .r("NAMESPACES", "{}")
        .r("NAMESPACES", any);
    g.rw(4, "NSNAME", "\"org.iso.18013.5.1\"")
        .r("NSNAME", "\"org.iso.18013.5.1.aamva\"")
        .r("NSNAME", "\"@STR@\"")
        .r("NSNAME", any);
    g.rw(2, "ISITEMS", "@ISITEM@").rw(2, "ISITEMS", "@ISITEM@, @ISITEMS@");

    g.rw(6, "ISITEM", "24(<<@ISMAP@>>)")
        .r("ISITEM", "24(<<@ISMAP@>>@LENOV@@ENC@)")
        .r("ISITEM", "24@ENC@(<<@ISMAP@>>)")
        .r("ISITEM", "24(<<@ISMAP@, @ITEM@>>)")
        .r("ISITEM", "24(@ITEM@)")
        .r("ISITEM", "<<@ISMAP@>>")
        .r("ISITEM", any);

    // IssuerSignedItem: all 24 field orders (the circuit records the
    // permutation), plus missing, extra and duplicated fields.
    let fields = ["@FDIGEST@", "@FRANDOM@", "@FID@", "@FVAL@"];
    for p in permutations4() {
        let body = p.iter().map(|&i| fields[i]).collect::<Vec<_>>().join(", ");
        g.r("ISMAP", &format!("{{{body}}}"));
        // Every ordering appears twice to outweigh the malformed variants below.
        g.r("ISMAP", &format!("{{{body}}}"));
    }
    g.r("ISMAP", "{@FDIGEST@, @FRANDOM@, @FID@}")
        .r("ISMAP", "{@FDIGEST@, @FRANDOM@, @FVAL@}")
        .r("ISMAP", "{@FDIGEST@, @FRANDOM@, @FID@, @FVAL@, @FVAL@}")
        .r("ISMAP", "{@FDIGEST@, @FDIGEST@, @FID@, @FVAL@}")
        .r("ISMAP", "{@FDIGEST@, @FRANDOM@, @FID@, @PAIRS@}")
        .r("ISMAP", "{@FDIGEST@, @FRANDOM@, @FID@, @FVAL@, @PAIRS@}")
        .r("ISMAP", any);
    g.r("FDIGEST", "\"digestID\": @DIGESTID@");
    g.r("FRANDOM", "\"random\": h'@H32@'")
        .r("FRANDOM", "\"random\": h'@H16@'")
        .r("FRANDOM", "\"random\": @ITEM@");
    g.r("FID", "\"elementIdentifier\": @ATTRNAME@");
    g.r("FVAL", "\"elementValue\": @ATTRVAL@");
    for d in ["0", "1", "2", "3"] {
        g.rw(2, "DIGESTID", d);
    }
    g.r("DIGESTID", "@NUM@@ENC@")
        .r("DIGESTID", "@NINT@")
        .r("DIGESTID", any);
    for a in ["age_over_18", "family_name", "birth_date", "issue_date", "height", "nym"] {
        g.rw(2, "ATTRNAME", &format!("\"{a}\""));
    }
    g.r("ATTRNAME", "\"@STR@\"").r("ATTRNAME", any);
    g.rw(2, "ATTRVAL", "true")
        .r("ATTRVAL", "false")
        .r("ATTRVAL", "\"Mustermann\"")
        .r("ATTRVAL", "1004(\"1971-09-01\")")
        .r("ATTRVAL", "175")
        .rw(2, "ATTRVAL", any);

    // COSE_Sign1 with the MSO as tag 24 inside the payload bstr. The circuit
    // requires `d8 18 59 LL LL` (a 2-byte length), hence `_1`.
    let auth = |mso: &str, sig: &str| format!("[@PROT@, @UNPROT@, <<{mso}>>, {sig}]");
    g.rw(6, "ISSUERAUTH", &auth("24(<<@MSO@>>_1)", "@SIG64@"))
        .r("ISSUERAUTH", &format!("18({})", auth("24(<<@MSO@>>_1)", "@SIG64@")))
        .r("ISSUERAUTH", &auth("24(<<@MSO@>>@LENOV@@ENC@)", "@SIG64@"))
        .r("ISSUERAUTH", &auth("24(<<@MSO@>>)", "@SIG64@"))
        .r("ISSUERAUTH", &auth("@ITEM@", "@SIG64@"))
        .r("ISSUERAUTH", "[@PROT@, @UNPROT@, @ITEM@, @SIG64@]")
        .r("ISSUERAUTH", "[@PROT@, @UNPROT@, <<24(<<@MSO@>>_1)>>]")
        .r("ISSUERAUTH", any);
    g.rw(4, "PROT", "<<{1: -7}>>").r("PROT", "@BSTR@");
    g.rw(3, "UNPROT", "{33: h'@HEX@'}")
        .r("UNPROT", "{}")
        .r("UNPROT", "@MAP@");
    g.rw(4, "SIG64", "h'@H64@'").r("SIG64", "@BSTR@");

    let mso_fields = [
        "\"version\": \"1.0\"",
        "\"digestAlgorithm\": \"SHA-256\"",
        "\"docType\": @DOCTYPE@",
        "\"valueDigests\": @VALUEDIGESTS@",
        "\"deviceKeyInfo\": @DEVKEYINFO@",
        "\"validityInfo\": @VALIDITY@",
    ];
    let canonical = mso_fields.join(", ");
    g.rw(8, "MSO", &format!("{{{canonical}}}"));
    let reordered = [5, 4, 3, 2, 1, 0]
        .iter()
        .map(|&i| mso_fields[i])
        .collect::<Vec<_>>()
        .join(", ");
    g.r("MSO", &format!("{{{reordered}}}"));
    for skip in 0..mso_fields.len() {
        let partial = mso_fields
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != skip)
            .map(|(_, f)| *f)
            .collect::<Vec<_>>()
            .join(", ");
        g.r("MSO", &format!("{{{partial}}}"));
    }
    g.r("MSO", &format!("{{{canonical}, {}}}", mso_fields[4]))
        .r("MSO", &format!("{{{canonical}, @PAIRS@}}"))
        .r("MSO", any);

    g.rw(5, "VALUEDIGESTS", "{@NSNAME@: {@DIGESTS@}}")
        .r("VALUEDIGESTS", "{@NSNAME@: {@DIGESTS@}, @NSNAME@: {@DIGESTS@}}")
        .r("VALUEDIGESTS", "{@NSNAME@: @ITEM@}")
        .r("VALUEDIGESTS", any);
    g.rw(2, "DIGESTS", "@DIGESTID@: h'@H32@'")
        .rw(2, "DIGESTS", "@DIGESTID@: h'@H32@', @DIGESTS@")
        .r("DIGESTS", "@DIGESTID@: @ITEM@");

    g.rw(5, "DEVKEYINFO", "{\"deviceKey\": @COSEKEY@}")
        .r("DEVKEYINFO", "{\"deviceKey\": @COSEKEY@, @PAIRS@}")
        .r("DEVKEYINFO", "{\"deviceKey\": @COSEKEY@, \"deviceKey\": @COSEKEY@}")
        .r("DEVKEYINFO", any);
    g.rw(5, "COSEKEY", "{1: 2, -1: 1, -2: h'@H32@', -3: h'@H32@'}")
        .r("COSEKEY", "{1: 2, -1: 1, -2: @BSTR@, -3: @BSTR@}")
        .r("COSEKEY", "{1: 2, -1: 1, -2: h'@H32@', -2: h'@H32@', -3: h'@H32@'}")
        .r("COSEKEY", "{1: 2, -1: 1, -2: h'@H32@'}")
        .r("COSEKEY", "{-3: h'@H32@', -2: h'@H32@'}")
        .r("COSEKEY", "@MAP@");

    g.rw(5, "VALIDITY", "{\"signed\": @TDATE@, \"validFrom\": @TDATE@, \"validUntil\": @TDATE@}")
        .r("VALIDITY", "{\"validFrom\": @TDATE@, \"validUntil\": @TDATE@}")
        .r("VALIDITY", "{\"signed\": @TDATE@, \"validFrom\": @TDATE@}")
        .r("VALIDITY", "{\"signed\": @TDATE@, \"validFrom\": @TDATE@, \"validFrom\": @TDATE@, \"validUntil\": @TDATE@}")
        .r("VALIDITY", any);
    g.rw(4, "TDATE", "0(\"2025-04-28T21:00:00Z\")")
        .r("TDATE", "0(\"@STR@\")")
        .r("TDATE", any);

    let devsig = "[<<{1: -7}>>, {}, null, @SIG64@]";
    g.rw(5, "DEVICESIGNED", &format!("{{\"nameSpaces\": 24(<<{{}}>>), \"deviceAuth\": {{\"deviceSignature\": @DEVSIG@}}}}"))
        .r("DEVICESIGNED", "{\"deviceAuth\": {\"deviceSignature\": @DEVSIG@}}")
        .r("DEVICESIGNED", "{\"nameSpaces\": 24(<<{}>>), \"deviceAuth\": {\"deviceMac\": @ITEM@}}")
        .r("DEVICESIGNED", "{\"nameSpaces\": 24(<<{}>>), \"deviceAuth\": {\"deviceSignature\": @DEVSIG@, \"deviceSignature\": @DEVSIG@}}")
        .r("DEVICESIGNED", any);
    g.rw(5, "DEVSIG", devsig)
        .r("DEVSIG", &format!("18({devsig})"))
        .r("DEVSIG", "[<<{1: -7}>>, {}, null]")
        .r("DEVSIG", any);

    add_cbor(&mut g);
    g
}

/// P-256 field elements as the circuit stores them (32 bytes, little-endian).
/// The reader rejects values >= p.
const P256_CONSTANTS: &[&str] = &[
    "0000000000000000000000000000000000000000000000000000000000000000", // 0
    "0100000000000000000000000000000000000000000000000000000000000000", // 1
    "0200000000000000000000000000000000000000000000000000000000000000", // 2
    "feffffffffffffffffffffff00000000000000000000000001000000ffffffff", // p - 1
    "ffffffffffffffffffffffff00000000000000000000000001000000ffffffff", // p
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", // 2^256 - 1
];

/// GF(2^128) elements (16 bytes, little-endian). Every value is valid.
const GF2_128_CONSTANTS: &[&str] = &[
    "00000000000000000000000000000000",
    "01000000000000000000000000000000",
    "02000000000000000000000000000000",
    "ffffffffffffffffffffffffffffffff",
];

/// Circuit archive and circuit grammar for the `circuit` target. It emits
/// [`crate::circasm`] text. The first byte selects the reader, as in the
/// target's bytes mode: 0 for an archive, 1 for a P-256 circuit, 2 for a
/// GF(2^128) circuit.
///
/// The shapes follow the readers in `core/proto`: LFA2 (header, entry table,
/// then the payloads, with the combined ID a SHA-256 over the entry IDs), LFA1
/// (an LFC1 P-256 circuit followed by an LFC1 GF(2^128) circuit), and LFC1 and
/// LFC2 circuits. The assembler computes counts, lengths, the combined ID and
/// in-bounds indices from labels, and wrong values (overrides, overlong
/// ULEB128s, swapped or missing payloads, indices past the end) appear next to
/// the right ones, at weights that let most generated circuits parse. Numbers
/// favor small values and the readers' limits.
///
/// Labels: `K` constants, `L` layers, and per LFC2 layer `D` deltas and `S`
/// segments. Each circuit sits in its own `C:( ... )` scope and each LFC2
/// layer in a `Y:( ... )` scope, so these names can repeat.
pub fn circuit() -> Grammar {
    let mut g = Grammar::new("INPUT");
    g.rw(4, "INPUT", "b0 @ARCHIVE@")
        .rw(3, "INPUT", "b1 @CIRCP@")
        .rw(3, "INPUT", "b2 @CIRCG@");

    // Archives. LFA1 is the two LFC1 circuits back to back.
    g.rw(6, "ARCHIVE", "@LFA2@")
        .rw(2, "ARCHIVE", "@LFC1P@ @LFC1G@")
        .r("ARCHIVE", "@LFC1P@ @LFC1G@ @JUNK@")
        .r("ARCHIVE", "@LFC1P@")
        .r("ARCHIVE", &costly("@JUNK@"));

    g.rw(
        8,
        "LFA2",
        "\"LFA2\" @AVER@ u@NUM@@PAD@ @CID@ @MSTR@ @MSTR@ @MSTR@ @MSTR@ @ENTRIES@",
    )
    .r("LFA2", &costly("\"LFA2\" @AVER@ u@NUM@@PAD@ @CID@ @MSTR@ @MSTR@ @MSTR@"))
    .r("LFA2", &costly("\"LFA2\" @AVER@"));
    g.rw(20, "AVER", "b1").r("AVER", "b@NUM@");
    // Missing labels are empty, so this is the right ID for 0 to 3 entries.
    g.rw(30, "CID", "sha(*I0 *I1 *I2)")
        .r("CID", "sha(*I1 *I0)")
        .r("CID", "sha(*I0)")
        .r("CID", "h'@H32@'")
        .r("CID", "h'@HEX@'");
    g.rw(20, "MSTR", "u<\"@STR@\">")
        .rw(10, "MSTR", "u<\"@META@\">")
        .r("MSTR", "u<\"\\xff@STR@\">")
        .r("MSTR", "u<\"@STR@\\xc3\">")
        .r("MSTR", "u!@NUM@<\"@STR@\">");
    for m in [
        "2026-07-15T00:00:00Z",
        "Google LLC",
        "rzkl-compiler v0.1.0",
        "mdoc ZK Circuit Archive",
    ] {
        g.r("META", m);
    }

    // The entry table, then the payloads in the same order. Each entry is a
    // group so that the table's count counts entries, not fields.
    g.rw(30, "ENTRIES", "u[@E0@ @E1@] @PL0@ @PL1@")
        .r("ENTRIES", "u[@E0@] @PL0@")
        .r("ENTRIES", "u[@E0@ @E1@ @E2@] @PL0@ @PL1@ @PL2@")
        .r("ENTRIES", &costly("u[]"))
        .r("ENTRIES", "u[@E0@ @E1@] @PL1@ @PL0@")
        .r("ENTRIES", "u!@NUM@[@E0@ @E1@] @PL0@ @PL1@")
        .r("ENTRIES", &costly("u[@E0@ @E1@] @PL0@"))
        .r("ENTRIES", "u[@E0@ @E1@] @PL0@ @PL1@ @JUNK@");
    g.r("E0", "(@NAME0@ I0:(@ID@) @PLEN0@)");
    g.r("E1", "(@NAME1@ I1:(@ID@) @PLEN1@)");
    g.r("E2", "(@ENAME@ I2:(@ID@) @PLEN2@)");
    g.rw(20, "NAME0", "u<\"sig\">").r("NAME0", "@ENAME@");
    g.rw(20, "NAME1", "u<\"hash\">").r("NAME1", "@ENAME@");
    g.r("ENAME", "u<\"sig\">")
        .r("ENAME", "u<\"hash\">")
        .r("ENAME", "u<\"@STR@\">")
        .r("ENAME", "u<\"sig\\x00\">")
        .r("ENAME", "u!@NUM@<\"sig\">");
    g.rw(20, "ID", "h'@H32@'").r("ID", "h'@HEX@'");
    for (i, other) in [(0, 1), (1, 0), (2, 0)] {
        let len = format!("PLEN{i}");
        g.rw(30, &len, &format!("u%P{i}"))
            .r(&len, &format!("u%P{i}_@SMALL@"))
            .r(&len, &format!("u%P{other}"))
            .r(&len, "u@NUM@");
    }
    g.rw(20, "PL0", "P0:(@CIRCP@)")
        .r("PL0", "P0:(@CIRCG@)")
        .r("PL0", &costly("P0:(@JUNK@)"));
    g.rw(20, "PL1", "P1:(@CIRCG@)")
        .r("PL1", "P1:(@CIRCP@)")
        .r("PL1", &costly("P1:(@JUNK@)"));
    g.r("PL2", "P2:(@CIRCP@)").r("PL2", "P2:(@CIRCG@)");

    // Circuits. CIRCP is the P-256 ("sig") circuit, CIRCG the GF(2^128)
    // ("hash") one; they differ in field ID and element size.
    for (f, fid) in [("P", "FIDP"), ("G", "FIDG")] {
        let circ = format!("CIRC{f}");
        g.rw(20, &circ, &format!("@LFC2{f}@"))
            .rw(8, &circ, &format!("@LFC1{f}@"))
            .r(&circ, &costly("@JUNK@"));
        g.r(
            &format!("LFC2{f}"),
            &format!("C:(@MAGIC2@ u@{fid}@@PAD@ @HDR2@ @KS2{f}@ L:(@LAYERS2@) @CIRCID@)"),
        );
        g.rw(16, &format!("KS2{f}"), &format!("u#K K:(@KS{f}@)"))
            .r(&format!("KS2{f}"), &format!("u@NUM@ K:(@KS{f}@)"));
        g.r(
            &format!("LFC1{f}"),
            &format!("C:(b1 t@{fid}@ @HDR1@ @KS1{f}@ L:(@LAYERS1@) @CIRCID@)"),
        );
        g.rw(16, &format!("KS1{f}"), &format!("t#K K:(@KS{f}@)"))
            .r(&format!("KS1{f}"), &format!("t@NUM@ K:(@KS{f}@)"));
        list(&mut g, &format!("KS{f}"), &format!("@K{f}@"));
    }
    g.rw(40, "FIDP", "1").r("FIDP", "4").r("FIDP", "@NUM@");
    g.rw(40, "FIDG", "4").r("FIDG", "1").r("FIDG", "@NUM@");
    // A circuit has several constants, so the invalid ones (wrong size, p and
    // above) sit a level deeper: about 1 in 60.
    g.rw(40, "KP", "h'@H32@'").r("KP", "@KPX@");
    for (i, c) in P256_CONSTANTS.iter().enumerate() {
        if i < 4 {
            g.rw(4, "KP", &format!("h'{c}'"));
        } else {
            g.r("KPX", &format!("h'{c}'"));
        }
    }
    g.r("KPX", "h'@HEX@'");
    g.rw(20, "KG", "h'@H16@'").r("KG", "h'@HEX@'");
    for c in GF2_128_CONSTANTS {
        g.rw(4, "KG", &format!("h'{c}'"));
    }
    g.rw(60, "MAGIC2", "\"LFC2\"").r("MAGIC2", "\"LFC\"").r("MAGIC2", "b1");
    g.rw(30, "CIRCID", "h'@H32@'")
        .r("CIRCID", &costly("h'@HEX@'"))
        .r("CIRCID", &costly(""));

    // Header after the field ID: noutput, ncopies, npublic_input,
    // subfield_boundary, ninput, layer count. LFC2 uses ULEB128 (at most 4
    // bytes), LFC1 3-byte little-endian.
    g.rw(16, "HDR2", "u@NOUT@@PAD@ u@NC@ u@NPUB@ u@NSUB@ u@NIN@ @NL2@")
        .r("HDR2", "u@NOUT@ u@NC@ u@NPUB@ u@NSUB@ u@NIN@@PAD@ u#L@PAD@");
    g.rw(20, "NL2", "u#L").r("NL2", "u@NUM@");
    g.r("HDR1", "t@NOUT@ t@NC@ t@NPUB@ t@NSUB@ t@NIN@ @NL1@");
    g.rw(20, "NL1", "t#L").r("NL1", "t@NUM@");

    // LFC2 layer: logw, nw, then the delta table, the segments (lists of
    // delta indices) and the tokens (segment indices).
    list(&mut g, "LAYERS2", "@LAYER2@");
    g.r("LAYER2", "Y:(u@LOGW@ u@NW@ @DTABLE@ @STABLE@ @TTABLE@)");
    g.rw(30, "DTABLE", "u#D D:(@DELTAS@)").r("DTABLE", "u@NUM@ D:(@DELTAS@)");
    g.rw(30, "STABLE", "u#S S:(@SEGS@)").r("STABLE", "u@NUM@ S:(@SEGS@)");
    g.rw(30, "TTABLE", "u[@TOKS@]").r("TTABLE", "u!@NUM@[@TOKS@]");
    list(&mut g, "DELTAS", "@DELTA@");
    g.r("DELTA", "(z@SDX@ z@SDX@ z@SDX@ u@KIDX@)");
    list(&mut g, "SEGS", "@SEG@");
    g.rw(20, "SEG", "u[@DIDXS@]").r("SEG", "u!@NUM@[@DIDXS@]");
    list(&mut g, "DIDXS", "u@DIDX@");
    list(&mut g, "TOKS", "u@SIDX@");
    // Indices into constants, deltas and segments: in bounds, one past the
    // end, or anything. A circuit has dozens of indices, so the bad ones sit
    // a level deeper (about 1 in 140).
    for (nt, label) in [("KIDX", "K"), ("DIDX", "D"), ("SIDX", "S")] {
        let good = format!("@IDX@~{label}");
        let rare = format!("{nt}X");
        g.rw(30, nt, &good).r(nt, &format!("@{rare}@"));
        g.rw(7, &rare, &good)
            .r(&rare, &format!("#{label}"))
            .r(&rare, "@NUM@");
    }

    // LFC1 layer: logw, nw, then 12-byte terms (three deltas and a constant
    // index).
    list(&mut g, "LAYERS1", "@LAYER1@");
    g.rw(20, "LAYER1", "(t@LOGW@ t@NW@ t[@TERMS1@])")
        .r("LAYER1", "(t@LOGW@ t@NW@ t!@NUM@[@TERMS1@])");
    list(&mut g, "TERMS1", "@TERM1@");
    g.r("TERM1", "(s@SDX@ s@SDX@ s@SDX@ t@KIDX@)");

    // Numbers. Small values dominate, so that indices usually land in bounds
    // and dimensions stay cheap. BIG holds format and reader limits: ULEB128
    // width boundaries, 2^24 for LFC1, MAX_WIRES (5M), MAX_LAYERS (10k),
    // MAX_TERMS (20M), the 28-bit LFC2 cap, and 2^56 - 1 (the largest value
    // read_uleb128 accepts).
    g.rw(30, "NOUT", "1");
    for v in ["2", "3", "4", "8", "@DIGNZ@@DIGS@"] {
        g.rw(2, "NOUT", v);
    }
    g.r("NOUT", "0").r("NOUT", "@BIG@");
    g.rw(40, "NC", "1").r("NC", "@NUM@");
    // The reader requires npublic_input <= ninput; disjoint ranges keep that
    // in the common case.
    g.rw(4, "NPUB", "0").rw(2, "NPUB", "1").rw(2, "NPUB", "2").r("NPUB", "@NUM@");
    g.rw(12, "NIN", "@DIGNZ@@DIG@").rw(4, "NIN", "@DIGNZ@").r("NIN", "@NUM@");
    for nt in ["NSUB", "NW"] {
        g.rw(12, nt, "@SMALL@").r(nt, "@NUM@");
    }
    for v in 0..=6 {
        g.rw(10, "LOGW", &v.to_string());
    }
    for v in ["8", "16", "19", "40", "@BADLOGW@"] {
        g.r("LOGW", v);
    }
    for v in ["41", "63", "64", "@BIG@"] {
        g.r("BADLOGW", v);
    }
    g.rw(10, "IDX", "0").rw(4, "IDX", "1").rw(2, "IDX", "2");
    g.r("IDX", "3").r("IDX", "@SMALL@").r("IDX", "@NUM@");
    g.rw(6, "SD", "0").rw(4, "SD", "1").rw(4, "SD", "-1");
    g.rw(2, "SD", "2").rw(2, "SD", "-2").rw(2, "SD", "@SMALL@").rw(2, "SD", "-@SMALL@");
    g.r("SD", "@DIGNZ@@DIG@@DIG@").r("SD", "-@DIGNZ@@DIG@@DIG@");
    // Deltas wrap mod 2^32 (LFC2) or 2^24 (LFC1); big LFC2 deltas don't fit
    // the reader's 28-bit ULEB128. There are three deltas per term, so these
    // are rare.
    g.rw(100, "SDX", "@SD@").r("SDX", "@BIGSD@");
    for v in [
        "8388607", "8388608", "16777215", "134217727", "134217728", "2147483647",
        "-2147483648", "4294967295", "-@DIGNZ@@DIGS@", "@DIGNZ@@DIGS@",
    ] {
        g.r("BIGSD", v);
    }
    for v in 0..=8 {
        g.r("SMALL", &v.to_string());
    }
    g.rw(12, "NUM", "@SMALL@").rw(2, "NUM", "@DIGNZ@@DIGS@").rw(2, "NUM", "@BIG@");
    for v in [
        "127", "128", "255", "256", "16383", "16384", "65535", "65536", "10000", "10001",
        "4999999", "5000000", "5000001", "16777215", "16777216", "20000000", "20000001",
        "268435455", "268435456", "4294967295", "72057594037927935",
    ] {
        g.r("BIG", v);
    }
    g.r("DIGS", "").r("DIGS", "@DIG@@DIGS@");
    for d in 0..10 {
        g.r("DIG", &d.to_string());
        if d > 0 {
            g.r("DIGNZ", &d.to_string());
        }
    }
    g.rw(100, "PAD", "").r("PAD", "_2").r("PAD", "_4").r("PAD", "_5");

    g.r("JUNK", "h'@HEX@'");
    g.r("NOP", " ");
    g.r("HEX", "").rw(2, "HEX", "@HB@@HEX@").r("HEX", "@H32@");
    g.regex("HB", "[0-9a-f]{2}");
    g.regex("H16", "[0-9a-f]{32}");
    g.regex("H32", "[0-9a-f]{64}");
    g.r("STR", "").rw(3, "STR", "@CH@@STR@");
    g.regex("CH", "[a-zA-Z0-9_.:\\- ]");
    g
}

/// Nautilus only picks alternatives that fit a subtree's remaining size
/// budget, and budgets run low deep in the tree, so generation keeps falling
/// back to each nonterminal's smallest alternative. Padding a rare near-miss
/// with no-op nodes makes it larger than any well-formed alternative, so the
/// fallback stays well-formed.
fn costly(template: &str) -> String {
    format!("{template}{}", "@NOP@".repeat(64))
}

/// `nt` is a list of `item`: rarely empty (an empty delta or segment table
/// puts every index into it out of bounds), otherwise one item plus a
/// geometric tail (2.5 items on average).
fn list(g: &mut Grammar, nt: &str, item: &str) {
    let more = format!("{nt}MORE");
    g.r(nt, &costly("")).rw(30, nt, &format!("{item} @{more}@"));
    g.rw(2, &more, "").rw(3, &more, &format!("{item} @{more}@"));
}

fn permutations4() -> Vec<[usize; 4]> {
    let mut out = Vec::new();
    for a in 0..4 {
        for b in 0..4 {
            for c in 0..4 {
                for d in 0..4 {
                    let p = [a, b, c, d];
                    let mut seen = [false; 4];
                    if p.iter().all(|&x| !std::mem::replace(&mut seen[x], true)) {
                        out.push(p);
                    }
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use libafl::generators::nautilus::NautilusGenerator;
    use libafl::generators::Generator;
    use libafl::inputs::NautilusInput;
    use libafl::state::NopState;

    #[test]
    fn templates_escape_braces() {
        assert_eq!(compile_template("{@A@: 1}"), b"\\{{A}: 1\\}");
        assert_eq!(compile_template("\\x@HD@"), b"\\\\x{HD}");
    }

    fn generated_inputs_assemble(g: Grammar, max_len: usize) -> usize {
        let ctx = g.context(max_len);
        let mut gen = NautilusGenerator::new(&ctx);
        let mut state: NopState<NautilusInput> = NopState::new();
        let mut ok = 0;
        for _ in 0..20000 {
            let input = gen.generate(&mut state).unwrap();
            let mut text = Vec::new();
            input.unparse(&ctx, &mut text);
            let asm = crate::edn::assemble(&text);
            assert!(
                asm.is_some(),
                "grammar produced unassemblable text: {}",
                String::from_utf8_lossy(&text)
            );
            ok += 1;
        }
        ok
    }

    #[test]
    fn cbor_grammar_always_assembles() {
        generated_inputs_assemble(cbor(), 200);
    }

    #[test]
    fn mdoc_grammar_always_assembles() {
        generated_inputs_assemble(mdoc(), 1000);
    }

    #[test]
    fn circuit_grammar_always_assembles() {
        let ctx = circuit().context(1000);
        let mut gen = NautilusGenerator::new(&ctx);
        let mut state: NopState<NautilusInput> = NopState::new();
        for _ in 0..20000 {
            let input = gen.generate(&mut state).unwrap();
            let mut text = Vec::new();
            input.unparse(&ctx, &mut text);
            assert!(
                crate::circasm::assemble(&text).is_some(),
                "grammar produced unassemblable text: {}",
                String::from_utf8_lossy(&text)
            );
        }
    }

    #[test]
    fn circuit_constants_are_field_boundaries() {
        use core_algebra::SerializableField;
        let p256 = runtime_algebra::p256::P256Field::new();
        let ok: Vec<bool> = P256_CONSTANTS
            .iter()
            .map(|c| p256.bytes_to_element(&crate::circasm::assemble(format!("h'{c}'").as_bytes()).unwrap()).is_ok())
            .collect();
        // 0, 1, 2 and p - 1 are elements; p and 2^256 - 1 are not.
        assert_eq!(ok, [true, true, true, true, false, false]);
    }

    /// False if an LFA2 archive declares a payload longer than the input.
    fn lfa2_payloads_fit(data: &[u8]) -> bool {
        fn uleb(d: &mut &[u8]) -> Option<usize> {
            let mut v = 0usize;
            for shift in (0..56).step_by(7) {
                let (&b, rest) = d.split_first()?;
                *d = rest;
                v |= usize::from(b & 0x7f) << shift;
                if b & 0x80 == 0 {
                    return Some(v);
                }
            }
            None
        }
        fn skip(d: &mut &[u8], n: usize) -> Option<()> {
            *d = d.get(n..)?;
            Some(())
        }
        let walk = || -> Option<bool> {
            let mut d = data.strip_prefix(b"LFA2")?;
            skip(&mut d, 1)?;
            uleb(&mut d)?;
            skip(&mut d, 32)?;
            for _ in 0..4 {
                let n = uleb(&mut d)?;
                skip(&mut d, n)?;
            }
            let entries = uleb(&mut d)?.min(10_000);
            for _ in 0..entries {
                let n = uleb(&mut d)?;
                skip(&mut d, n + 32)?;
                if uleb(&mut d)? > data.len() {
                    return Some(false);
                }
            }
            Some(true)
        };
        walk().unwrap_or(true)
    }

    /// Generated inputs must get past the readers' header checks often enough
    /// to be worth fuzzing with: the point of the grammar is to reach what
    /// happens after a circuit parses.
    #[test]
    fn circuit_grammar_reaches_past_parsing() {
        use core_proto::{archive::CircuitArchive, reader::CircuitReader, FieldID};
        let p256 = runtime_algebra::p256::P256Field::new();
        let gf2 = runtime_algebra::gf2_128::Gf2_128Field::new();
        let ctx = circuit().context(1000);
        let mut gen = NautilusGenerator::new(&ctx);
        let mut state: NopState<NautilusInput> = NopState::new();
        // ceil_log2 panics on a zero output count (FINDINGS.md #1), and the
        // grammar generates zero on purpose. Those are caught below; keep
        // them out of the test output.
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if !info.to_string().contains("log2 of zero") {
                prev(info);
            }
        }));
        // [archive, P-256 circuit, GF(2^128) circuit]: (generated, parsed).
        let mut seen = [(0usize, 0usize); 3];
        let mut archive_circuits = 0;
        for _ in 0..5000 {
            let input = gen.generate(&mut state).unwrap();
            let mut text = Vec::new();
            input.unparse(&ctx, &mut text);
            let bytes = crate::circasm::assemble(&text).unwrap();
            let (&sel, rest) = bytes.split_first().unwrap();
            // FINDINGS.md #3: the archive reader allocates whatever payload
            // length it is given, and an allocation failure aborts. Skip
            // those inputs; the grammar generates them on purpose.
            if sel == 0 && !lfa2_payloads_fit(rest) {
                continue;
            }
            let ok = std::panic::catch_unwind(|| match sel {
                0 => CircuitArchive::from_bytes(rest).map(|a| {
                    let sig = a.get("sig").map(|e| {
                        CircuitReader::new(&p256, FieldID::P256).from_bytes(&e.payload, false).is_ok()
                    });
                    let hash = a.get("hash").map(|e| {
                        CircuitReader::new(&gf2, FieldID::Gf2_128).from_bytes(&e.payload, false).is_ok()
                    });
                    sig == Some(true) && hash == Some(true)
                }),
                1 => CircuitReader::new(&p256, FieldID::P256).from_bytes(rest, false).map(|_| false),
                _ => CircuitReader::new(&gf2, FieldID::Gf2_128).from_bytes(rest, false).map(|_| false),
            });
            let Ok(res) = ok else { continue };
            let s = &mut seen[usize::from(sel)];
            s.0 += 1;
            if let Ok(both) = res {
                s.1 += 1;
                archive_circuits += usize::from(both);
            }
        }
        eprintln!(
            "(generated, parsed): archive {:?} (both circuits parse in {archive_circuits}), p256 {:?}, gf2 {:?}",
            seen[0], seen[1], seen[2]
        );
        // Percent that must parse, with margin below what the grammar gets.
        for (parsed_min, (n, parsed)) in [25, 30, 30].iter().zip(seen) {
            assert!(parsed * 100 >= n * parsed_min, "only {parsed} of {n} parsed");
        }
        assert!(
            archive_circuits * 100 >= seen[0].0 * 10,
            "archives whose circuits parse: {archive_circuits} of {}",
            seen[0].0
        );
    }
}
