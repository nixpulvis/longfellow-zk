//! A small assembler for the circuit archive (LFA1/LFA2) and circuit
//! (LFC1/LFC2) binary formats.
//!
//! The `circuit` grammar emits this text instead of raw bytes. The formats are
//! mostly ULEB128 or 3-byte counts followed by that many items, and several
//! values come before the data they describe: a circuit's layer count sits in
//! the header ahead of the constants, an LFA2 archive lists every payload
//! length before the first payload, and its combined ID is a SHA-256 over the
//! entry IDs. Indices into the constants, deltas and segments have to stay
//! below those lists' lengths. A context-free grammar can't compute any of
//! these, so the grammar names the data with labels and this assembler fills
//! in counts, lengths, hashes and in-bounds indices. Every derived value can
//! be overridden to produce near-miss inputs.
//!
//! This module is not instrumented (see `scripts/sancov-rustc.sh`), so it does
//! not add coverage of its own to grammar runs.
//!
//! Syntax (items are separated by whitespace):
//!
//! ```text
//! item   := h'HEX'                   raw bytes
//!         | "CHARS"                  raw bytes, with \xNN, \" and \\ escapes
//!         | b NUM                    one byte (mod 256)
//!         | u VAL pad?               ULEB128; u5_3 pads to 3 bytes (overlong)
//!         | t VAL                    3-byte little-endian (mod 2^24), LFC1's size_t
//!         | z INT                    LFC2 delta: zigzag of the low 32 bits, as ULEB128
//!         | s INT                    LFC1 delta: 2|d| + (d < 0), as 3 bytes
//!         | ( items )                group: one element of the enclosing list
//!         | NAME:( items )           labeled group, emitted in place
//!         | P [ items ]              count of elements, then the elements
//!         | P !NUM [ items ]         same, with a declared (possibly wrong) count
//!         | P < items >              byte length, then the bytes
//!         | P !NUM < items >         same, with a declared (possibly wrong) length
//!         | * NAME                   copy of a labeled group's bytes
//!         | sha( items )             SHA-256 of the assembled items (32 bytes)
//! VAL    := NUM                      a number
//!         | #NAME                    a label's element count
//!         | %NAME                    a label's byte length
//!         | NUM~NAME                 NUM mod the label's element count (NUM if 0)
//! P      := u | t                    prefix encoding for counts and lengths
//! pad    := _NUM                     minimum ULEB128 width in bytes (max 10)
//! NAME   := [A-Z][A-Z0-9]*
//! ```
//!
//! Labels are scoped: each labeled group's body is a scope, and a reference
//! resolves to the nearest definition in its own scope or an enclosing one,
//! before or after the reference. So two circuits in one archive can both name
//! their layers `L`. A reference to an undefined label is an empty group
//! (count 0, length 0, no bytes); a label referring to itself sees an empty
//! group too. Numbers saturate instead of overflowing. As a result every
//! syntactically valid input assembles.

use std::collections::HashMap;

use sha2::{Digest, Sha256};

const MAX_DEPTH: usize = 256;
const MAX_PAD: u64 = 10;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Pfx {
    Uleb,
    U24,
}

#[derive(Debug)]
enum Val {
    Num(u64),
    /// Element count of a label, resolved from the given scope.
    Count(String, usize),
    /// Byte length of a label, resolved from the given scope.
    Len(String, usize),
    /// A number reduced mod a label's element count.
    Index(u64, String, usize),
}

#[derive(Debug)]
enum Node {
    Bytes(Vec<u8>),
    Uleb(Val, u64),
    U24(Val),
    Zigzag(i64),
    SignMag(i64),
    Group(Vec<Node>),
    /// Index into the label arena.
    Label(usize),
    List(Pfx, Option<u64>, Vec<Node>),
    Sized(Pfx, Option<u64>, Vec<Node>),
    Copy(String, usize),
    Sha(Vec<Node>),
}

struct Scope {
    parent: Option<usize>,
    names: HashMap<String, usize>,
}

struct P<'a> {
    s: &'a [u8],
    i: usize,
    depth: usize,
    scopes: Vec<Scope>,
    scope: usize,
    labels: Vec<Vec<Node>>,
}

type R<T> = Option<T>;

impl<'a> P<'a> {
    fn ws(&mut self) {
        while self.i < self.s.len() && matches!(self.s[self.i], b' ' | b'\n' | b'\t' | b'\r') {
            self.i += 1;
        }
    }
    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }
    fn eat(&mut self, c: u8) -> bool {
        if self.peek() == Some(c) {
            self.i += 1;
            true
        } else {
            false
        }
    }
    fn eat_str(&mut self, lit: &[u8]) -> bool {
        if self.s[self.i..].starts_with(lit) {
            self.i += lit.len();
            true
        } else {
            false
        }
    }
    fn expect(&mut self, c: u8) -> R<()> {
        self.eat(c).then_some(())
    }

    fn digits(&mut self) -> R<u64> {
        let start = self.i;
        let mut v: u64 = 0;
        while let Some(c @ b'0'..=b'9') = self.peek() {
            v = v.saturating_mul(10).saturating_add(u64::from(c - b'0'));
            self.i += 1;
        }
        (self.i > start).then_some(v)
    }

    fn signed(&mut self) -> R<i64> {
        let neg = self.eat(b'-');
        let v = self.digits()?.min(i64::MAX as u64) as i64;
        Some(if neg { -v } else { v })
    }

    fn name(&mut self) -> R<String> {
        let start = self.i;
        if !matches!(self.peek(), Some(b'A'..=b'Z')) {
            return None;
        }
        while matches!(self.peek(), Some(b'A'..=b'Z' | b'0'..=b'9')) {
            self.i += 1;
        }
        Some(String::from_utf8_lossy(&self.s[start..self.i]).into_owned())
    }

    fn val(&mut self) -> R<Val> {
        if self.eat(b'#') {
            Some(Val::Count(self.name()?, self.scope))
        } else if self.eat(b'%') {
            Some(Val::Len(self.name()?, self.scope))
        } else {
            let n = self.digits()?;
            if self.eat(b'~') {
                Some(Val::Index(n, self.name()?, self.scope))
            } else {
                Some(Val::Num(n))
            }
        }
    }

    fn hex(&mut self) -> R<Vec<u8>> {
        let mut out = Vec::new();
        loop {
            match self.peek() {
                Some(b'\'') => {
                    self.i += 1;
                    return Some(out);
                }
                Some(_) => {
                    let hi = hexval(self.peek()?)?;
                    self.i += 1;
                    let lo = hexval(self.peek()?)?;
                    self.i += 1;
                    out.push(hi << 4 | lo);
                }
                None => return None,
            }
        }
    }

    fn text(&mut self) -> R<Vec<u8>> {
        let mut out = Vec::new();
        loop {
            let c = self.peek()?;
            self.i += 1;
            match c {
                b'"' => return Some(out),
                b'\\' => {
                    let e = self.peek()?;
                    self.i += 1;
                    match e {
                        b'"' | b'\\' => out.push(e),
                        b'x' => {
                            let hi = hexval(self.peek()?)?;
                            self.i += 1;
                            let lo = hexval(self.peek()?)?;
                            self.i += 1;
                            out.push(hi << 4 | lo);
                        }
                        _ => return None,
                    }
                }
                _ => out.push(c),
            }
        }
    }

    /// Items up to (and consuming) `close`.
    fn items_until(&mut self, close: &[u8]) -> R<Vec<Node>> {
        let mut items = Vec::new();
        loop {
            self.ws();
            if self.eat_str(close) {
                return Some(items);
            }
            items.push(self.item()?);
        }
    }

    /// After a `u` or `t`: a value, or a counted / length-prefixed body.
    fn prefixed(&mut self, pfx: Pfx) -> R<Node> {
        let declared = if self.eat(b'!') { Some(self.digits()?) } else { None };
        if self.eat(b'[') {
            return Some(Node::List(pfx, declared, self.items_until(b"]")?));
        }
        if self.eat(b'<') {
            return Some(Node::Sized(pfx, declared, self.items_until(b">")?));
        }
        if declared.is_some() {
            return None;
        }
        let v = self.val()?;
        match pfx {
            Pfx::Uleb => {
                let pad = if self.eat(b'_') { self.digits()?.min(MAX_PAD) } else { 0 };
                Some(Node::Uleb(v, pad))
            }
            Pfx::U24 => Some(Node::U24(v)),
        }
    }

    fn item(&mut self) -> R<Node> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return None;
        }
        self.ws();
        let node = match self.peek()? {
            b'"' => {
                self.i += 1;
                Node::Bytes(self.text()?)
            }
            b'(' => {
                self.i += 1;
                Node::Group(self.items_until(b")")?)
            }
            b'*' => {
                self.i += 1;
                Node::Copy(self.name()?, self.scope)
            }
            b'A'..=b'Z' => {
                let name = self.name()?;
                self.expect(b':')?;
                self.expect(b'(')?;
                let outer = self.scope;
                self.scopes.push(Scope {
                    parent: Some(outer),
                    names: HashMap::new(),
                });
                self.scope = self.scopes.len() - 1;
                let body = self.items_until(b")");
                self.scope = outer;
                let id = self.labels.len();
                self.labels.push(body?);
                self.scopes[outer].names.entry(name).or_insert(id);
                Node::Label(id)
            }
            _ => {
                if self.eat_str(b"h'") {
                    Node::Bytes(self.hex()?)
                } else if self.eat_str(b"sha(") {
                    Node::Sha(self.items_until(b")")?)
                } else if self.eat(b'b') {
                    Node::Bytes(vec![self.digits()? as u8])
                } else if self.eat(b'u') {
                    self.prefixed(Pfx::Uleb)?
                } else if self.eat(b't') {
                    self.prefixed(Pfx::U24)?
                } else if self.eat(b'z') {
                    Node::Zigzag(self.signed()?)
                } else if self.eat(b's') {
                    Node::SignMag(self.signed()?)
                } else {
                    return None;
                }
            }
        };
        self.depth -= 1;
        Some(node)
    }
}

/// Second pass: resolves labels and writes bytes.
struct Asm {
    scopes: Vec<Scope>,
    labels: Vec<Vec<Node>>,
    /// Assembled bytes per label; `None` while the label is being assembled,
    /// so a self-reference sees an empty group.
    done: HashMap<usize, Option<Vec<u8>>>,
}

impl Asm {
    fn resolve(&self, name: &str, mut scope: usize) -> Option<usize> {
        loop {
            if let Some(&id) = self.scopes[scope].names.get(name) {
                return Some(id);
            }
            scope = self.scopes[scope].parent?;
        }
    }

    fn label_bytes(&mut self, id: usize) -> Vec<u8> {
        match self.done.get(&id) {
            Some(Some(b)) => return b.clone(),
            Some(None) => return Vec::new(),
            None => {}
        }
        self.done.insert(id, None);
        let body = std::mem::take(&mut self.labels[id]);
        let mut out = Vec::new();
        for n in &body {
            self.emit(n, &mut out);
        }
        self.labels[id] = body;
        self.done.insert(id, Some(out.clone()));
        out
    }

    fn value(&mut self, v: &Val) -> u64 {
        match v {
            Val::Num(n) => *n,
            Val::Count(name, scope) => self
                .resolve(name, *scope)
                .map_or(0, |id| self.labels[id].len() as u64),
            Val::Len(name, scope) => self
                .resolve(name, *scope)
                .map_or(0, |id| self.label_bytes(id).len() as u64),
            Val::Index(n, name, scope) => {
                let count = self
                    .resolve(name, *scope)
                    .map_or(0, |id| self.labels[id].len() as u64);
                if count == 0 {
                    *n
                } else {
                    n % count
                }
            }
        }
    }

    fn emit(&mut self, n: &Node, out: &mut Vec<u8>) {
        match n {
            Node::Bytes(b) => out.extend_from_slice(b),
            Node::Uleb(v, pad) => {
                let v = self.value(v);
                uleb(out, v, *pad);
            }
            Node::U24(v) => {
                let v = self.value(v);
                u24(out, v);
            }
            Node::Zigzag(d) => {
                let d = *d as u32;
                uleb(out, u64::from((d << 1) ^ ((d as i32 >> 31) as u32)), 0);
            }
            Node::SignMag(d) => {
                let v = d.unsigned_abs().wrapping_mul(2) + u64::from(*d < 0);
                u24(out, v);
            }
            Node::Group(items) => {
                for i in items {
                    self.emit(i, out);
                }
            }
            Node::Label(id) => {
                let b = self.label_bytes(*id);
                out.extend_from_slice(&b);
            }
            Node::List(pfx, declared, items) => {
                prefix(out, *pfx, declared.unwrap_or(items.len() as u64));
                for i in items {
                    self.emit(i, out);
                }
            }
            Node::Sized(pfx, declared, items) => {
                let mut body = Vec::new();
                for i in items {
                    self.emit(i, &mut body);
                }
                prefix(out, *pfx, declared.unwrap_or(body.len() as u64));
                out.extend_from_slice(&body);
            }
            Node::Copy(name, scope) => {
                if let Some(id) = self.resolve(name, *scope) {
                    let b = self.label_bytes(id);
                    out.extend_from_slice(&b);
                }
            }
            Node::Sha(items) => {
                let mut body = Vec::new();
                for i in items {
                    self.emit(i, &mut body);
                }
                out.extend_from_slice(&Sha256::digest(&body));
            }
        }
    }
}

fn prefix(out: &mut Vec<u8>, pfx: Pfx, v: u64) {
    match pfx {
        Pfx::Uleb => uleb(out, v, 0),
        Pfx::U24 => u24(out, v),
    }
}

/// ULEB128 of `v`, padded with continuation bytes to at least `pad` bytes.
fn uleb(out: &mut Vec<u8>, mut v: u64, pad: u64) {
    let mut n = 0;
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        n += 1;
        if v == 0 && n >= pad {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

fn u24(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&(v as u32).to_le_bytes()[..3]);
}

fn hexval(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Assemble a sequence of items into bytes. Returns `None` on a syntax error.
pub fn assemble(src: &[u8]) -> Option<Vec<u8>> {
    let mut p = P {
        s: src,
        i: 0,
        depth: 0,
        scopes: vec![Scope {
            parent: None,
            names: HashMap::new(),
        }],
        scope: 0,
        labels: Vec::new(),
    };
    let mut items = Vec::new();
    loop {
        p.ws();
        if p.i == src.len() {
            break;
        }
        items.push(p.item()?);
    }
    let mut asm = Asm {
        scopes: p.scopes,
        labels: p.labels,
        done: HashMap::new(),
    };
    let mut out = Vec::with_capacity(src.len());
    for n in &items {
        asm.emit(n, &mut out);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::assemble;

    fn a(s: &str) -> Vec<u8> {
        assemble(s.as_bytes()).unwrap_or_else(|| panic!("failed to assemble {s}"))
    }

    #[test]
    fn scalars() {
        assert_eq!(a(""), b"");
        assert_eq!(a("b1 b257"), [1, 1]);
        assert_eq!(a("u0 u127 u128"), [0x00, 0x7f, 0x80, 0x01]);
        assert_eq!(a("u300"), [0xac, 0x02]);
        assert_eq!(a("u5_3"), [0x85, 0x80, 0x00]);
        assert_eq!(a("u0_2"), [0x80, 0x00]);
        assert_eq!(a("u300_1"), [0xac, 0x02]); // too narrow: minimal width
        assert_eq!(a("t1 t16777217"), [1, 0, 0, 1, 0, 0]);
        assert_eq!(a("h'0aFF' \"LFC2\""), [0x0a, 0xff, b'L', b'F', b'C', b'2']);
        assert_eq!(a("\"\\xff\\\"\""), [0xff, b'"']);
    }

    #[test]
    fn deltas() {
        // LFC2: zigzag, as the writer's zigzag_encode_delta.
        assert_eq!(a("z0 z1 z-1 z2 z-2"), [0, 2, 1, 4, 3]);
        assert_eq!(a("z64"), [0x80, 0x01]);
        // LFC1: sign-magnitude, as the writer's serialize_index.
        assert_eq!(a("s0 s3 s-3"), [0, 0, 0, 6, 0, 0, 7, 0, 0]);
    }

    #[test]
    fn lists_and_lengths() {
        assert_eq!(a("u[]"), [0]);
        assert_eq!(a("u[u7 u8]"), [2, 7, 8]);
        assert_eq!(a("u[(u1 u2) (u3 u4)]"), [2, 1, 2, 3, 4]);
        assert_eq!(a("t[b9]"), [1, 0, 0, 9]);
        assert_eq!(a("u!5[b9]"), [5, 9]);
        assert_eq!(a("u<\"sig\">"), [3, b's', b'i', b'g']);
        assert_eq!(a("u!9<b1>"), [9, 1]);
        assert_eq!(a("t<b1 b2>"), [2, 0, 0, 1, 2]);
    }

    #[test]
    fn labels() {
        // Forward references to a count and a length.
        assert_eq!(a("u#L u%L L:(b1 b2 (b3 b4))"), [3, 4, 1, 2, 3, 4]);
        assert_eq!(a("t#L L:(b1)"), [1, 0, 0, 1]);
        // Copies and hashes see the assembled bytes.
        assert_eq!(a("*A A:(u300)"), [0xac, 0x02, 0xac, 0x02]);
        let h = a("sha(*A *B) A:(b1) B:(b2)");
        assert_eq!(&h[..32], &a("sha(b1 b2)")[..]);
        // Indices reduced mod a count.
        assert_eq!(a("u7~L t7~L u1~L L:(b0 b0 b0)"), [1, 1, 0, 0, 1, 0, 0, 0]);
        // Undefined labels are empty.
        assert_eq!(a("u#X u%X *X u7~X"), [0, 0, 7]);
        assert_eq!(a("sha(*X)"), a("sha()"));
        // Self-reference sees an empty group.
        assert_eq!(a("A:(u%A b7)"), [0, 7]);
        // First definition wins within a scope.
        assert_eq!(a("u%A A:(b1) A:(b1 b2)"), [1, 1, 1, 2]);
    }

    #[test]
    fn label_scopes() {
        // Each labeled body is its own scope; lookups go outward.
        assert_eq!(
            a("P0:(u#L L:(b1)) P1:(u#L L:(b1 b2)) u#L"),
            [1, 1, 2, 1, 2, 0]
        );
        assert_eq!(a("L:(b1 b2 b3) P0:(u#L)"), [1, 2, 3, 3]);
        // A label inside a plain group or list belongs to the enclosing scope.
        assert_eq!(a("u[(I0:(b5))] *I0"), [1, 5, 5]);
    }

    // The tests below check the assembler against the real formats: a
    // hand-written input must parse, and writing the parsed value back must
    // give the same bytes.

    fn one() -> String {
        format!("01{}", "00".repeat(31))
    }

    #[test]
    fn lfc2_round_trip() {
        use core_proto::{reader::CircuitReader, writer::CircuitWriter, FieldID};
        let f = runtime_algebra::p256::P256Field::new();
        let src = format!(
            "C:(\"LFC2\" u1 u2 u1 u1 u0 u3 u#L u[h'{one}' h'{zero}']
              L:((u1 u2 u[(z2 z0 z1 u0) (z-1 z1 z0 u1)] u[u[u0 u1] u[u1]] u[u0 u1 u0])
                 (u2 u3 u[(z0 z0 z0 u0)] u[u[u0]] u[u0]))
              h'{id}')",
            one = one(),
            zero = "00".repeat(32),
            id = "aa".repeat(32),
        );
        let bytes = a(&src);
        let (c, rest) = CircuitReader::new(&f, FieldID::P256)
            .from_bytes(&bytes, false)
            .expect("assembled LFC2 parses");
        assert!(rest.is_empty());
        assert_eq!(c.raw.layers.len(), 2);
        assert_eq!(CircuitWriter::new(&f, FieldID::P256).to_bytes_lfc2(&c), bytes);
    }

    #[test]
    fn lfc1_round_trip() {
        use core_proto::{reader::CircuitReader, writer::CircuitWriter, FieldID};
        let f = runtime_algebra::gf2_128::Gf2_128Field::new();
        let src = format!(
            "C:(b1 t4 t2 t1 t1 t0 t3 t#L t[h'{one}' h'{two}']
              L:((t1 t2 t[(s2 s0 s1 t0) (s-1 s1 s0 t1)])
                 (t2 t3 t[(s0 s0 s0 t0)]))
              h'{id}')",
            one = format!("01{}", "00".repeat(15)),
            two = format!("02{}", "00".repeat(15)),
            id = "aa".repeat(32),
        );
        let bytes = a(&src);
        let (c, rest) = CircuitReader::new(&f, FieldID::Gf2_128)
            .from_bytes(&bytes, false)
            .expect("assembled LFC1 parses");
        assert!(rest.is_empty());
        assert_eq!(c.raw.layers.len(), 2);
        assert_eq!(CircuitWriter::new(&f, FieldID::Gf2_128).to_bytes_lfc1(&c), bytes);
    }

    #[test]
    fn lfa2_round_trip() {
        use core_proto::archive::CircuitArchive;
        let src = format!(
            "\"LFA2\" b1 u6 sha(*I0 *I1 *I2)
             u<\"2026-07-15T00:00:00Z\"> u<\"Google LLC\"> u<\"tool\"> u<\"\">
             u[(u<\"sig\"> I0:(h'{id0}') u%P0) (u<\"hash\"> I1:(h'{id1}') u%P1)]
             P0:(h'0102') P1:(h'030405')",
            id0 = "11".repeat(32),
            id1 = "22".repeat(32),
        );
        let bytes = a(&src);
        let archive = CircuitArchive::from_bytes(&bytes).expect("assembled LFA2 parses");
        assert_eq!(archive.get("hash").unwrap().payload, [3, 4, 5]);
        assert_eq!(archive.to_bytes_lfa2(), bytes);
    }

    #[test]
    fn rejects_garbage() {
        assert!(assemble(b"u").is_none());
        assert!(assemble(b"u!3 5").is_none());
        assert!(assemble(b"h'0'").is_none());
        assert!(assemble(b"u[1").is_none());
        assert!(assemble(b"L(b1)").is_none());
        assert!(assemble(b"nope").is_none());
    }
}
