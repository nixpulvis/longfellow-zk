//! Nautilus grammars that emit the EDN-like notation from [`crate::edn`].
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
}
