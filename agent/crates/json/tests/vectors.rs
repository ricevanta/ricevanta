//! Shared vectors from `schemas/agent/json/v1/vectors.json` and focused
//! profile cases. Tests match error variants, never display strings.

#[path = "support/oracle.rs"]
mod oracle;

use ricevanta_json::{Error, MAX_DEPTH, MAX_INPUT_BYTES, Value, encode, parse};
use std::collections::BTreeMap;

const VECTORS: &[u8] = include_bytes!("../../../../schemas/agent/json/v1/vectors.json");

fn variant_is(token: &str, error: &Error) -> bool {
    matches!(
        (token, error),
        ("Utf8", Error::Utf8 { .. })
            | ("ByteOrderMark", Error::ByteOrderMark { .. })
            | ("TooLarge", Error::TooLarge { .. })
            | ("TooDeep", Error::TooDeep { .. })
            | ("DuplicateKey", Error::DuplicateKey { .. })
            | ("Syntax", Error::Syntax { .. })
            | ("NumberFormat", Error::NumberFormat { .. })
            | ("NumberRange", Error::NumberRange { .. })
            | ("Trailing", Error::Trailing { .. })
            | ("Surrogate", Error::Surrogate { .. })
            | ("Control", Error::Control { .. })
    )
}

#[test]
fn shared_vectors() {
    let root = oracle::parse(VECTORS);
    assert_eq!(root.get("format").str(), "ricevanta-json-v1");
    let cases = root.get("cases").items();
    assert!(!cases.is_empty());
    let (mut accepted, mut rejected) = (0, 0);
    for case in cases {
        let name = case.get("name").str();
        let input = oracle::hex(case.get("input_hex").str());
        let expected = case.get("expected");
        match expected.get("result").str() {
            "accept" => {
                let value = parse(&input).unwrap_or_else(|e| panic!("{name}: rejected {e:?}"));
                let canonical = oracle::hex(expected.get("canonical_hex").str());
                assert_eq!(
                    encode(&value).as_bytes(),
                    canonical,
                    "{name}: canonical bytes"
                );
                assert_eq!(parse(&canonical).as_ref(), Ok(&value), "{name}: re-parse");
                accepted += 1;
            }
            "reject" => {
                let token = expected.get("error").str();
                let error = parse(&input).expect_err(name);
                assert!(
                    variant_is(token, &error),
                    "{name}: want {token}, got {error:?}"
                );
                rejected += 1;
            }
            other => panic!("{name}: unknown result {other}"),
        }
    }
    assert!(accepted > 0 && rejected > 0);
}

#[test]
fn every_error_token_is_a_variant() {
    for (token, error) in [
        ("Utf8", Error::Utf8 { offset: 0 }),
        ("ByteOrderMark", Error::ByteOrderMark { offset: 0 }),
        ("TooLarge", Error::TooLarge { offset: 0 }),
        ("TooDeep", Error::TooDeep { offset: 0 }),
        ("DuplicateKey", Error::DuplicateKey { offset: 0 }),
        ("Syntax", Error::Syntax { offset: 0 }),
        ("NumberFormat", Error::NumberFormat { offset: 0 }),
        ("NumberRange", Error::NumberRange { offset: 0 }),
        ("Trailing", Error::Trailing { offset: 0 }),
        ("Surrogate", Error::Surrogate { offset: 0 }),
        ("Control", Error::Control { offset: 0 }),
    ] {
        assert!(variant_is(token, &error));
        assert_eq!(error.name(), token);
        assert_eq!(error.offset(), 0);
    }
}

#[test]
fn offsets_name_the_offending_byte() {
    assert_eq!(
        parse(b"{\"a\":1,\"a\":2}"),
        Err(Error::DuplicateKey { offset: 7 })
    );
    assert_eq!(parse(b"[1.5]"), Err(Error::NumberFormat { offset: 2 }));
    assert_eq!(parse(b"{} x"), Err(Error::Trailing { offset: 3 }));
    assert_eq!(
        parse(b"[[[[[[[[[1]]]]]]]]]"),
        Err(Error::TooDeep { offset: 8 })
    );
    assert_eq!(parse(b"\"a\xffb\""), Err(Error::Utf8 { offset: 2 }));
    assert_eq!(parse(b"\"a\x01\""), Err(Error::Control { offset: 2 }));
    assert_eq!(
        parse(b"\xef\xbb\xbf1"),
        Err(Error::ByteOrderMark { offset: 0 })
    );
    assert_eq!(parse(b""), Err(Error::Syntax { offset: 0 }));
    assert_eq!(
        parse(b"[9223372036854775808]"),
        Err(Error::NumberRange { offset: 1 })
    );
}

#[test]
fn size_limit_is_exact_and_checked_first() {
    let mut fits = vec![b'"'];
    fits.resize(MAX_INPUT_BYTES - 1, b'a');
    fits.push(b'"');
    assert_eq!(fits.len(), MAX_INPUT_BYTES);
    assert!(parse(&fits).is_ok());
    // One byte more is too large even though the extra byte is also a BOM
    // fragment and invalid UTF-8: size is checked before anything else.
    let mut over = b"\xef\xbb\xbf".to_vec();
    over.resize(MAX_INPUT_BYTES + 1, 0xff);
    assert_eq!(
        parse(&over),
        Err(Error::TooLarge {
            offset: MAX_INPUT_BYTES
        })
    );
    // Byte-order mark precedes UTF-8 validation.
    assert_eq!(
        parse(b"\xef\xbb\xbf\xff"),
        Err(Error::ByteOrderMark { offset: 0 })
    );
}

#[test]
fn depth_limit_counts_objects_and_arrays() {
    assert_eq!(MAX_DEPTH, 8);
    let ok = br#"{"a":[{"b":[{"c":[{"d":[1]}]}]}]}"#;
    assert!(parse(ok).is_ok());
    let deep = br#"{"a":[{"b":[{"c":[{"d":[{}]}]}]}]}"#;
    assert!(matches!(parse(deep), Err(Error::TooDeep { .. })));
}

#[test]
fn strings_and_surrogates() {
    assert_eq!(
        parse(br#""\ud83d\ude00""#),
        Ok(Value::String("\u{1f600}".to_owned()))
    );
    for bad in [
        &br#""\udc00""#[..],
        br#""\ud83d""#,
        br#""\ud83dx""#,
        br#""\ud83d\n""#,
        br#""\ud83d\u0041""#,
    ] {
        assert!(
            matches!(parse(bad), Err(Error::Surrogate { .. })),
            "{bad:?}"
        );
    }
    for bad in [&br#""\x""#[..], br#""\u12g4""#, br#""\u12"#, b"\"abc"] {
        assert!(matches!(parse(bad), Err(Error::Syntax { .. })), "{bad:?}");
    }
    // Keys are compared after unescaping.
    assert!(matches!(
        parse(br#"{"a":1,"\u0061":2}"#),
        Err(Error::DuplicateKey { .. })
    ));
    assert_eq!(
        parse(br#""\/\b\f\r""#),
        Ok(Value::String("/\u{8}\u{c}\r".to_owned()))
    );
}

#[test]
fn numbers() {
    assert_eq!(parse(b"-9223372036854775808"), Ok(Value::Integer(i64::MIN)));
    assert_eq!(parse(b"-0"), Ok(Value::Integer(0)));
    for bad in [&b"-"[..], b"-a", b"01", b"-01", b"+1", b".5", b"0x1"] {
        let result = parse(bad);
        assert!(
            matches!(result, Err(Error::Syntax { .. } | Error::Trailing { .. })),
            "{bad:?}: {result:?}"
        );
    }
    for bad in [&b"1."[..], b"1e", b"0.0", b"1E5", b"-1.0"] {
        assert!(
            matches!(parse(bad), Err(Error::NumberFormat { .. })),
            "{bad:?}"
        );
    }
    assert!(matches!(
        parse(b"-9223372036854775809"),
        Err(Error::NumberRange { .. })
    ));
    assert!(matches!(
        parse(b"99999999999999999999999"),
        Err(Error::NumberRange { .. })
    ));
    for bad in [&b"Infinity"[..], b"-Infinity", b"nul", b"tru", b"True"] {
        assert!(matches!(parse(bad), Err(Error::Syntax { .. })), "{bad:?}");
    }
}

#[test]
fn canonical_writer() {
    let mut object = BTreeMap::new();
    object.insert("z".to_owned(), Value::Null);
    object.insert("é".to_owned(), Value::Bool(true));
    object.insert("A".to_owned(), Value::Integer(-1));
    object.insert(
        "s".to_owned(),
        Value::String("q\"b\\/\u{0}\u{8}\u{9}\u{a}\u{c}\u{d}\u{1f}\u{7f}é".to_owned()),
    );
    object.insert(
        "a".to_owned(),
        Value::Array(vec![Value::Object(BTreeMap::new()), Value::Array(vec![])]),
    );
    let value = Value::Object(object);
    let text = encode(&value);
    assert_eq!(
        text,
        "{\"A\":-1,\"a\":[{},[]],\"s\":\"q\\\"b\\\\/\\u0000\\b\\t\\n\\f\\r\\u001f\u{7f}é\",\"z\":null,\"é\":true}"
    );
    assert_eq!(parse(text.as_bytes()), Ok(value));
}

#[test]
fn accessors() {
    let value = parse(br#"{"n":5,"s":"x","o":{"b":false},"a":[null]}"#).unwrap();
    assert_eq!(value.get("n").and_then(Value::as_i64), Some(5));
    assert_eq!(value.get("s").and_then(Value::as_str), Some("x"));
    assert_eq!(
        value
            .get("o")
            .and_then(|o| o.get("b"))
            .and_then(Value::as_bool),
        Some(false)
    );
    assert!(value.get("missing").is_none());
    assert!(value.as_object().is_some());
    assert_eq!(
        value.get("a").and_then(Value::as_array).map(<[Value]>::len),
        Some(1)
    );
    assert!(Value::Null.get("n").is_none());
}
