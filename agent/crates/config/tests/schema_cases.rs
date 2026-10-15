//! The loader agrees with `config.schema.json` on every shared case, and the
//! shared example is the complete Linux service default.

#[path = "../../json/tests/support/oracle.rs"]
mod oracle;

use ricevanta_config::{AgentConfig, Error, LoadOptions, Mode, Os, load, validate_document};

const CASES: &[u8] = include_bytes!("../../../../schemas/agent/config/v1/schema-cases.json");
const EXAMPLE: &[u8] = include_bytes!("../../../../schemas/agent/config/v1/example.json");

/// Expected first violation per invalid case, decided here from the schema
/// rather than read from the loader.
fn expected_violation(id: &str, error: &Error) -> bool {
    match id {
        "missing-schema" => matches!(error, Error::Missing { pointer } if pointer == "/schema"),
        "wrong-schema-token" => {
            matches!(error, Error::InvalidValue { pointer } if pointer == "/schema")
        }
        "unknown-top-level-key" => {
            matches!(error, Error::UnknownKey { pointer } if pointer == "/server_url")
        }
        "interval-below-minimum" => {
            matches!(error, Error::OutOfBounds { pointer } if pointer == "/health/interval_ms")
        }
        "timeout-above-maximum" => {
            matches!(error, Error::OutOfBounds { pointer } if pointer == "/shutdown/timeout_ms")
        }
        "level-as-integer" => {
            matches!(error, Error::WrongType { pointer } if pointer == "/log/level")
        }
        "relative-path" => {
            matches!(error, Error::InvalidValue { pointer } if pointer == "/paths/state_dir")
        }
        // The strict reader rejects a fraction before any member is typed.
        "fractional-interval" => matches!(
            error,
            Error::Json(ricevanta_json::Error::NumberFormat { .. })
        ),
        other => panic!("schema case {other} has no expected violation in this test"),
    }
}

#[test]
fn schema_cases_agree() {
    let root = oracle::parse(CASES);
    assert_eq!(root.get("schema").str(), "config.schema.json");
    let cases = root.get("cases").items();
    assert!(!cases.is_empty());
    for case in cases {
        let id = case.get("id").str();
        let instance = case.get("instance").raw(CASES);
        let verdict = validate_document(instance);
        if case.get("valid").bool() {
            assert!(verdict.is_ok(), "{id}: rejected {verdict:?}");
        } else {
            let error = verdict.expect_err(id);
            assert!(expected_violation(id, &error), "{id}: got {error:?}");
            assert!(error.pointer().is_some() || matches!(error, Error::Json(_)));
        }
    }
}

#[test]
fn example_is_the_linux_service_default() {
    let defaults = AgentConfig::default_for(Os::Linux, Mode::Service, None).unwrap();
    let options = LoadOptions::new(Os::Linux, Mode::Service);
    let loaded = load(Some(&mut &EXAMPLE[..]), &options).unwrap();
    assert_eq!(loaded, defaults);
    assert_eq!(load(None, &options).unwrap(), defaults);
    let example = ricevanta_json::parse(EXAMPLE).unwrap();
    assert_eq!(defaults.to_value(), example);
}
