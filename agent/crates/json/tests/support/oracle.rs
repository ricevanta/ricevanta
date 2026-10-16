//! Independent, permissive test-only JSON reader for the shared fixture files.
//!
//! It deliberately shares no code with `ricevanta-json`: the vector file is
//! larger than the production input limit, and `schema-cases.json` holds
//! values the strict profile rejects. Every node records its byte span so a
//! test can hand the exact source bytes of an instance to the code under test.
//! Malformed fixture files panic, which fails the test that loads them.

// Each integration target uses a different subset of these helpers.
#![allow(dead_code)]

#[derive(Debug)]
pub enum Json {
    Null,
    Bool(bool),
    /// Number text exactly as written.
    Number(String),
    String(String),
    Array(Vec<Node>),
    Object(Vec<(String, Node)>),
}

#[derive(Debug)]
pub struct Node {
    pub value: Json,
    pub start: usize,
    pub end: usize,
}

impl Node {
    pub fn get(&self, key: &str) -> &Node {
        self.find(key)
            .unwrap_or_else(|| panic!("fixture member {key:?} missing"))
    }

    pub fn find(&self, key: &str) -> Option<&Node> {
        match &self.value {
            Json::Object(members) => members.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => panic!("fixture value is not an object"),
        }
    }

    pub fn str(&self) -> &str {
        match &self.value {
            Json::String(s) => s,
            other => panic!("fixture value is not a string: {other:?}"),
        }
    }

    pub fn bool(&self) -> bool {
        match &self.value {
            Json::Bool(b) => *b,
            other => panic!("fixture value is not a boolean: {other:?}"),
        }
    }

    pub fn items(&self) -> &[Node] {
        match &self.value {
            Json::Array(items) => items,
            other => panic!("fixture value is not an array: {other:?}"),
        }
    }

    pub fn raw<'a>(&self, source: &'a [u8]) -> &'a [u8] {
        &source[self.start..self.end]
    }
}

pub fn parse(source: &[u8]) -> Node {
    let mut reader = Reader { s: source, i: 0 };
    reader.ws();
    let node = reader.value();
    reader.ws();
    assert_eq!(reader.i, source.len(), "fixture has trailing bytes");
    node
}

pub fn hex(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2), "odd hex length");
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("fixture hex"))
        .collect()
}

struct Reader<'a> {
    s: &'a [u8],
    i: usize,
}

impl Reader<'_> {
    fn ws(&mut self) {
        while self.i < self.s.len() && matches!(self.s[self.i], b' ' | b'\t' | b'\n' | b'\r') {
            self.i += 1;
        }
    }

    fn eat(&mut self, byte: u8) {
        assert_eq!(self.s[self.i], byte, "fixture syntax at {}", self.i);
        self.i += 1;
    }

    fn value(&mut self) -> Node {
        let start = self.i;
        let value = match self.s[self.i] {
            b'{' => {
                self.i += 1;
                let mut members = Vec::new();
                self.ws();
                if self.s[self.i] == b'}' {
                    self.i += 1;
                } else {
                    loop {
                        self.ws();
                        let key = self.string();
                        self.ws();
                        self.eat(b':');
                        self.ws();
                        members.push((key, self.value()));
                        self.ws();
                        if self.s[self.i] == b',' {
                            self.i += 1;
                        } else {
                            self.eat(b'}');
                            break;
                        }
                    }
                }
                Json::Object(members)
            }
            b'[' => {
                self.i += 1;
                let mut items = Vec::new();
                self.ws();
                if self.s[self.i] == b']' {
                    self.i += 1;
                } else {
                    loop {
                        self.ws();
                        items.push(self.value());
                        self.ws();
                        if self.s[self.i] == b',' {
                            self.i += 1;
                        } else {
                            self.eat(b']');
                            break;
                        }
                    }
                }
                Json::Array(items)
            }
            b'"' => Json::String(self.string()),
            b't' => self.literal(b"true", Json::Bool(true)),
            b'f' => self.literal(b"false", Json::Bool(false)),
            b'n' => self.literal(b"null", Json::Null),
            _ => {
                while self.i < self.s.len()
                    && matches!(
                        self.s[self.i],
                        b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9'
                    )
                {
                    self.i += 1;
                }
                assert!(self.i > start, "fixture syntax at {start}");
                Json::Number(String::from_utf8(self.s[start..self.i].to_vec()).unwrap())
            }
        };
        Node {
            value,
            start,
            end: self.i,
        }
    }

    fn literal(&mut self, word: &[u8], value: Json) -> Json {
        assert_eq!(&self.s[self.i..self.i + word.len()], word);
        self.i += word.len();
        value
    }

    fn string(&mut self) -> String {
        self.eat(b'"');
        let mut out = Vec::new();
        loop {
            let byte = self.s[self.i];
            self.i += 1;
            match byte {
                b'"' => break,
                b'\\' => {
                    let escape = self.s[self.i];
                    self.i += 1;
                    match escape {
                        b'"' => out.push(b'"'),
                        b'\\' => out.push(b'\\'),
                        b'/' => out.push(b'/'),
                        b'n' => out.push(b'\n'),
                        b't' => out.push(b'\t'),
                        b'r' => out.push(b'\r'),
                        b'b' => out.push(8),
                        b'f' => out.push(12),
                        b'u' => {
                            let text = std::str::from_utf8(&self.s[self.i..self.i + 4]).unwrap();
                            let unit = u32::from_str_radix(text, 16).unwrap();
                            self.i += 4;
                            let c = char::from_u32(unit).expect("fixture uses no surrogates");
                            out.extend_from_slice(c.to_string().as_bytes());
                        }
                        other => panic!("fixture escape {other}"),
                    }
                }
                other => out.push(other),
            }
        }
        String::from_utf8(out).expect("fixture string is UTF-8")
    }
}
