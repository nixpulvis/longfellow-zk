//! A small assembler for an EDN-like CBOR notation (RFC 8949 §8 diagnostic
//! notation, plus a few fuzzing extensions).
//!
//! The Nautilus grammars emit this text instead of raw CBOR. CBOR prefixes
//! byte strings with their length, and a context-free grammar cannot compute
//! the length of embedded CBOR (`24(<< ... >>)` is everywhere in mdoc), so the
//! grammar emits structure and this assembler fills in every length.
//!
//! This module is not instrumented (see `scripts/sancov-rustc.sh`), so it does
//! not add coverage of its own to grammar runs.
//!
//! Syntax:
//!
//! ```text
//! item    := int | bytes | text | array | map | tag | embed | simple | float | raw
//! int     := '-'? DIGITS enc?                -5, 24_1
//! bytes   := "h'" HEX* "'" len? enc?         h'0102', h''!5
//! text    := '"' CHARS '"' len? enc?         "abc", "\xff" (invalid UTF-8 allowed)
//! array   := '[' opt? items? ']'             [1, 2], [_ 1, 2], [!3 1]
//! map     := '{' opt? pairs? '}'             {"a": 1}, {_1 }
//! tag     := DIGITS enc? '(' item ')'        24(<<1>>)
//! embed   := '<<' items? '>>' len? enc?      a bstr holding the encoded items
//! simple  := true | false | null | undefined | 'simple(' DIGITS ')'
//! float   := "fh'" HEX4 "'" | "ff'" HEX8 "'" | "fd'" HEX16 "'"
//! raw     := "raw'" HEX* "'"                 bytes emitted verbatim
//! enc     := '_i' | '_0' | '_1' | '_2' | '_3' head width: inline/1/2/4/8 bytes
//! opt     := '_ ' (indefinite) | '!' DIGITS ' ' (count override) | enc ' '
//! len     := '!' DIGITS                      declared length override
//! ```
//!
//! An encoding indicator that cannot hold the value falls back to the minimal
//! width, so every syntactically valid input assembles.

const MAX_DEPTH: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Enc {
    Imm,
    W1,
    W2,
    W4,
    W8,
}

/// Encode a CBOR head for `major` and argument `val`.
fn head(out: &mut Vec<u8>, major: u8, val: u64, enc: Option<Enc>) {
    let m = major << 5;
    let minimal = if val < 24 {
        Enc::Imm
    } else if val <= 0xff {
        Enc::W1
    } else if val <= 0xffff {
        Enc::W2
    } else if val <= 0xffff_ffff {
        Enc::W4
    } else {
        Enc::W8
    };
    let fits = |e: Enc| match e {
        Enc::Imm => val < 24,
        Enc::W1 => val <= 0xff,
        Enc::W2 => val <= 0xffff,
        Enc::W4 => val <= 0xffff_ffff,
        Enc::W8 => true,
    };
    let e = match enc {
        Some(e) if fits(e) => e,
        _ => minimal,
    };
    match e {
        Enc::Imm => out.push(m | val as u8),
        Enc::W1 => {
            out.push(m | 24);
            out.push(val as u8);
        }
        Enc::W2 => {
            out.push(m | 25);
            out.extend_from_slice(&(val as u16).to_be_bytes());
        }
        Enc::W4 => {
            out.push(m | 26);
            out.extend_from_slice(&(val as u32).to_be_bytes());
        }
        Enc::W8 => {
            out.push(m | 27);
            out.extend_from_slice(&val.to_be_bytes());
        }
    }
}

struct P<'a> {
    s: &'a [u8],
    i: usize,
    depth: usize,
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
            v = v.checked_mul(10)?.checked_add(u64::from(c - b'0'))?;
            self.i += 1;
        }
        (self.i > start).then_some(v)
    }

    /// Parse an optional `_i`/`_0`..`_3` encoding indicator.
    fn enc(&mut self) -> R<Option<Enc>> {
        if self.peek() != Some(b'_') {
            return Some(None);
        }
        let e = match self.s.get(self.i + 1) {
            Some(b'i') => Enc::Imm,
            Some(b'0') => Enc::W1,
            Some(b'1') => Enc::W2,
            Some(b'2') => Enc::W4,
            Some(b'3') => Enc::W8,
            _ => return Some(None),
        };
        self.i += 2;
        Some(Some(e))
    }

    /// Parse an optional `!N` length override.
    fn len_override(&mut self) -> R<Option<u64>> {
        if self.eat(b'!') {
            Some(Some(self.digits()?))
        } else {
            Some(None)
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

    /// Container options after `[` or `{`: indefinite, count override, enc.
    fn container_opt(&mut self) -> R<(bool, Option<u64>, Option<Enc>)> {
        self.ws();
        if self.peek() == Some(b'_') && matches!(self.s.get(self.i + 1), Some(b' ' | b']' | b'}'))
        {
            self.i += 1;
            return Some((true, None, None));
        }
        if self.eat(b'!') {
            let n = self.digits()?;
            return Some((false, Some(n), None));
        }
        let e = self.enc()?;
        Some((false, None, e))
    }

    fn items_until(&mut self, close: u8, out: &mut Vec<u8>) -> R<u64> {
        let mut n = 0;
        self.ws();
        if self.eat(close) {
            return Some(0);
        }
        loop {
            self.item(out)?;
            n += 1;
            self.ws();
            if self.eat(close) {
                return Some(n);
            }
            self.expect(b',')?;
        }
    }

    fn item(&mut self, out: &mut Vec<u8>) -> R<()> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return None;
        }
        self.ws();
        let c = self.peek()?;
        match c {
            b'-' => {
                self.i += 1;
                let n = self.digits()?;
                let e = self.enc()?;
                head(out, 1, n.checked_sub(1)?, e);
            }
            b'0'..=b'9' => {
                let n = self.digits()?;
                let e = self.enc()?;
                if self.eat(b'(') {
                    head(out, 6, n, e);
                    self.item(out)?;
                    self.ws();
                    self.expect(b')')?;
                } else {
                    head(out, 0, n, e);
                }
            }
            b'"' => {
                self.i += 1;
                let t = self.text()?;
                let len = self.len_override()?;
                let e = self.enc()?;
                head(out, 3, len.unwrap_or(t.len() as u64), e);
                out.extend_from_slice(&t);
            }
            b'[' | b'{' => {
                self.i += 1;
                let (major, close) = if c == b'[' { (4, b']') } else { (5, b'}') };
                let (indef, count, e) = self.container_opt()?;
                let mut body = Vec::new();
                let n = if major == 4 {
                    self.items_until(close, &mut body)?
                } else {
                    self.pairs_until(close, &mut body)?
                };
                if indef {
                    out.push(major << 5 | 31);
                    out.extend_from_slice(&body);
                    out.push(0xff);
                } else {
                    head(out, major, count.unwrap_or(n), e);
                    out.extend_from_slice(&body);
                }
            }
            b'<' => {
                if !self.eat_str(b"<<") {
                    return None;
                }
                let mut body = Vec::new();
                self.ws();
                if !self.eat_str(b">>") {
                    loop {
                        self.item(&mut body)?;
                        self.ws();
                        if self.eat_str(b">>") {
                            break;
                        }
                        self.expect(b',')?;
                    }
                }
                let len = self.len_override()?;
                let e = self.enc()?;
                head(out, 2, len.unwrap_or(body.len() as u64), e);
                out.extend_from_slice(&body);
            }
            _ => {
                if self.eat_str(b"h'") {
                    let b = self.hex()?;
                    let len = self.len_override()?;
                    let e = self.enc()?;
                    head(out, 2, len.unwrap_or(b.len() as u64), e);
                    out.extend_from_slice(&b);
                } else if self.eat_str(b"raw'") {
                    out.extend_from_slice(&self.hex()?);
                } else if self.eat_str(b"fh'") {
                    let b = self.hex()?;
                    (b.len() == 2).then_some(())?;
                    out.push(0xf9);
                    out.extend_from_slice(&b);
                } else if self.eat_str(b"ff'") {
                    let b = self.hex()?;
                    (b.len() == 4).then_some(())?;
                    out.push(0xfa);
                    out.extend_from_slice(&b);
                } else if self.eat_str(b"fd'") {
                    let b = self.hex()?;
                    (b.len() == 8).then_some(())?;
                    out.push(0xfb);
                    out.extend_from_slice(&b);
                } else if self.eat_str(b"true") {
                    out.push(0xf5);
                } else if self.eat_str(b"false") {
                    out.push(0xf4);
                } else if self.eat_str(b"null") {
                    out.push(0xf6);
                } else if self.eat_str(b"undefined") {
                    out.push(0xf7);
                } else if self.eat_str(b"simple(") {
                    // Wraps mod 256 so every generated value assembles.
                    let n = (self.digits()? & 0xff) as u8;
                    self.expect(b')')?;
                    if n < 24 {
                        out.push(0xe0 | n);
                    } else {
                        out.push(0xf8);
                        out.push(n);
                    }
                } else {
                    return None;
                }
            }
        }
        self.depth -= 1;
        Some(())
    }

    fn pairs_until(&mut self, close: u8, out: &mut Vec<u8>) -> R<u64> {
        let mut n = 0;
        self.ws();
        if self.eat(close) {
            return Some(0);
        }
        loop {
            self.item(out)?;
            self.ws();
            self.expect(b':')?;
            self.item(out)?;
            n += 1;
            self.ws();
            if self.eat(close) {
                return Some(n);
            }
            self.expect(b',')?;
        }
    }
}

fn hexval(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Assemble one item (or a comma-separated sequence, concatenated) into CBOR.
/// Returns `None` on a syntax error.
pub fn assemble(src: &[u8]) -> Option<Vec<u8>> {
    let mut p = P {
        s: src,
        i: 0,
        depth: 0,
    };
    let mut out = Vec::with_capacity(src.len());
    loop {
        p.item(&mut out)?;
        p.ws();
        if p.i == src.len() {
            return Some(out);
        }
        p.expect(b',')?;
    }
}

#[cfg(test)]
mod tests {
    use super::assemble;

    fn a(s: &str) -> Vec<u8> {
        assemble(s.as_bytes()).unwrap_or_else(|| panic!("failed to assemble {s}"))
    }

    #[test]
    fn scalars() {
        assert_eq!(a("0"), [0x00]);
        assert_eq!(a("23"), [0x17]);
        assert_eq!(a("24"), [0x18, 24]);
        assert_eq!(a("-1"), [0x20]);
        assert_eq!(a("1_1"), [0x19, 0, 1]);
        assert_eq!(a("1_3"), [0x1b, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(a("300_0"), [0x19, 0x01, 0x2c]); // _0 cannot hold 300
        assert_eq!(a("true"), [0xf5]);
        assert_eq!(a("simple(32)"), [0xf8, 32]);
        assert_eq!(a("fh'3c00'"), [0xf9, 0x3c, 0x00]);
    }

    #[test]
    fn strings() {
        assert_eq!(a("h'0102'"), [0x42, 1, 2]);
        assert_eq!(a("h'01'!5"), [0x45, 1]);
        assert_eq!(a("\"ab\""), [0x62, b'a', b'b']);
        assert_eq!(a("\"\\xff\""), [0x61, 0xff]);
        assert_eq!(a("\"a\"_0"), [0x78, 1, b'a']);
    }

    #[test]
    fn containers() {
        assert_eq!(a("[]"), [0x80]);
        assert_eq!(a("[1, 2]"), [0x82, 1, 2]);
        assert_eq!(a("[_ 1, 2]"), [0x9f, 1, 2, 0xff]);
        assert_eq!(a("[!3 1]"), [0x83, 1]);
        assert_eq!(a("{\"a\": 1}"), [0xa1, 0x61, b'a', 1]);
        assert_eq!(a("{_0 }"), [0xb8, 0]);
    }

    #[test]
    fn tags_and_embedding() {
        assert_eq!(a("24(<<{}>>)"), [0xd8, 0x18, 0x41, 0xa0]);
        assert_eq!(a("<<1, 2>>"), [0x42, 1, 2]);
        assert_eq!(a("<<1>>_1"), [0x59, 0, 1, 1]);
        assert_eq!(a("raw'ff00'"), [0xff, 0x00]);
    }

    #[test]
    fn rejects_garbage() {
        assert!(assemble(b"[1,").is_none());
        assert!(assemble(b"h'0'").is_none());
        assert!(assemble(b"nope").is_none());
    }
}
