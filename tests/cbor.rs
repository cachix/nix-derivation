use std::io;

use minicbor::{Decoder, Encoder, data::Type};
use nix_derivation::{Derivation, DerivationBuilder, Error, StoreDir, StructuredAttrs, cbor};

const PATH: &str = "c015dhfh5l0lp6wxyvdn7bmwhbbr6hr9-dep.drv";

// Hand-encoded RFC 8949 fixture. In particular, "z" sorts before "aa" in
// encoded-key order, and both environment values are byte strings.
const GOLDEN: &[u8] = b"\xa8\x63env\xa2\x61z\x41\x00\x62aa\x41\xff\x64args\x81\x61a\x64name\x61n\x66inputs\xa2\x64drvs\xa0\x64srcs\x80\x66system\x61s\x67builder\x61b\x67outputs\xa0\x67version\x01";
const ATERM: &[u8] = b"Derive([],[],[],\"s\",\"b\",[\"a\"],[(\"aa\",\"\xff\"),(\"z\",\"\x00\")])";

// A mutable fixture tree for constructing malformed documents. All CBOR
// encoding and decoding is handled by minicbor; this covers only fixture types.
#[derive(Clone, Debug, PartialEq)]
enum Value {
    Null,
    Bool(bool),
    Unsigned(u64),
    Text(String),
    Bytes(Vec<u8>),
    Array(Vec<Value>),
    Map(Vec<(Value, Value)>),
}

impl Value {
    fn as_map_mut(&mut self) -> Option<&mut Vec<(Value, Value)>> {
        match self {
            Self::Map(entries) => Some(entries),
            _ => None,
        }
    }

    fn as_text(&self) -> Option<&str> {
        match self {
            Self::Text(text) => Some(text),
            _ => None,
        }
    }

    fn read(decoder: &mut Decoder<'_>) -> Self {
        match decoder.datatype().unwrap() {
            Type::Null => {
                decoder.null().unwrap();
                Self::Null
            }
            Type::Bool => Self::Bool(decoder.bool().unwrap()),
            Type::U8 | Type::U16 | Type::U32 | Type::U64 => Self::Unsigned(decoder.u64().unwrap()),
            Type::String => Self::Text(decoder.str().unwrap().to_owned()),
            Type::Bytes => Self::Bytes(decoder.bytes().unwrap().to_vec()),
            Type::Array => Self::Array(
                (0..decoder.array().unwrap().unwrap())
                    .map(|_| Self::read(decoder))
                    .collect(),
            ),
            Type::Map => Self::Map(
                (0..decoder.map().unwrap().unwrap())
                    .map(|_| (Self::read(decoder), Self::read(decoder)))
                    .collect(),
            ),
            other => panic!("unexpected fixture type: {other}"),
        }
    }

    fn write(&self, encoder: &mut Encoder<Vec<u8>>) {
        match self {
            Self::Null => {
                encoder.null().unwrap();
            }
            Self::Bool(value) => {
                encoder.bool(*value).unwrap();
            }
            Self::Unsigned(value) => {
                encoder.u64(*value).unwrap();
            }
            Self::Text(value) => {
                encoder.str(value).unwrap();
            }
            Self::Bytes(value) => {
                encoder.bytes(value).unwrap();
            }
            Self::Array(values) => {
                encoder.array(values.len() as u64).unwrap();
                for value in values {
                    value.write(encoder);
                }
            }
            Self::Map(entries) => {
                encoder.map(entries.len() as u64).unwrap();
                for (key, value) in entries {
                    key.write(encoder);
                    value.write(encoder);
                }
            }
        }
    }
}

impl From<&str> for Value {
    fn from(value: &str) -> Self {
        Self::Text(value.to_owned())
    }
}

impl From<String> for Value {
    fn from(value: String) -> Self {
        Self::Text(value)
    }
}

impl From<bool> for Value {
    fn from(value: bool) -> Self {
        Self::Bool(value)
    }
}

impl From<u64> for Value {
    fn from(value: u64) -> Self {
        Self::Unsigned(value)
    }
}

fn decode(bytes: &[u8]) -> Value {
    let mut decoder = Decoder::new(bytes);
    let value = Value::read(&mut decoder);
    assert_eq!(decoder.position(), bytes.len());
    value
}

fn encode(value: &Value) -> Vec<u8> {
    let mut encoder = Encoder::new(Vec::new());
    value.write(&mut encoder);
    encoder.into_writer()
}

fn object(fields: impl IntoIterator<Item = (&'static str, Value)>) -> Value {
    Value::Map(
        fields
            .into_iter()
            .map(|(key, value)| (key.into(), value))
            .collect(),
    )
}

fn field<'a>(value: &'a mut Value, key: &str) -> &'a mut Value {
    &mut value
        .as_map_mut()
        .unwrap()
        .iter_mut()
        .find(|(k, _)| k.as_text() == Some(key))
        .unwrap()
        .1
}

fn check_round_trip(drv: &Derivation) {
    let bytes = drv.to_cbor_bytes().unwrap();
    let reparsed = Derivation::from_cbor_bytes_in(&bytes, drv.store_dir().clone()).unwrap();
    assert_eq!(reparsed, *drv);
    assert_eq!(reparsed.to_aterm_bytes(), drv.to_aterm_bytes());
    assert_eq!(reparsed.to_cbor_bytes().unwrap(), bytes);
    assert_eq!(reparsed.drv_path(), drv.drv_path());
    assert_eq!(
        reparsed.hash_input_derivation_modulo(|_| [0x42; 32]),
        drv.hash_input_derivation_modulo(|_| [0x42; 32]),
    );
    assert_eq!(
        reparsed.hash_output_path_modulo(|_| [0x42; 32]),
        drv.hash_output_path_modulo(|_| [0x42; 32]),
    );
    // Inspect the actual wire types and encoded map-key order with minicbor.
    let value = decode(&bytes);
    assert_eq!(encode(&value), bytes);
    assert_map_order(&value);
    assert_eq!(
        cbor::from_slice_in(&encode(&value), drv.store_dir().clone()).unwrap(),
        *drv
    );
}

fn assert_map_order(value: &Value) {
    match value {
        Value::Map(entries) => {
            let keys: Vec<_> = entries.iter().map(|(key, _)| encode(key)).collect();
            assert!(keys.windows(2).all(|pair| pair[0] < pair[1]));
            for (_, value) in entries {
                assert_map_order(value);
            }
        }
        Value::Array(values) => {
            for value in values {
                assert_map_order(value);
            }
        }
        _ => {}
    }
}

#[test]
fn hand_encoded_fixture_and_streaming_writer() {
    let drv = Derivation::from_aterm_bytes(ATERM, "n").unwrap();
    assert_eq!(drv.to_cbor_bytes().unwrap(), GOLDEN);
    assert_eq!(cbor::from_slice(GOLDEN).unwrap(), drv);
    assert_eq!(cbor::from_slice(GOLDEN).unwrap().to_aterm_bytes(), ATERM);
    let mut streamed = Vec::new();
    drv.write_cbor(&mut streamed).unwrap();
    assert_eq!(streamed, GOLDEN);
    check_round_trip(&drv);
}

#[test]
fn nix_corpus_retains_canonical_aterms_and_hashes() {
    for (name, bytes) in [
        (
            "bench-structured-attrs",
            include_bytes!("../benches/corpus/structured-attrs.drv").as_slice(),
        ),
        (
            "bench-many-inputs",
            include_bytes!("../benches/corpus/many-inputs.drv").as_slice(),
        ),
        (
            "bench-fixed-output",
            include_bytes!("../benches/corpus/fixed-output.drv").as_slice(),
        ),
        (
            "bench-escapes",
            include_bytes!("../benches/corpus/escapes.drv").as_slice(),
        ),
        (
            "dyn-dep-derivation",
            include_bytes!("../benches/corpus/dynamic-derivation.drv").as_slice(),
        ),
    ] {
        let bytes = bytes.strip_suffix(b"\n").unwrap_or(bytes);
        check_round_trip(&Derivation::from_aterm_bytes(bytes, name).unwrap());
    }
}

#[test]
fn every_byte_and_non_normalized_unicode_survive() {
    let bytes: Vec<u8> = (0..=255).collect();
    let drv = DerivationBuilder::new("binary", "x86_64-linux", "/bin/sh")
        .input_addressed_output("out")
        .argument("e\u{301}")
        .environment("e\u{301}", bytes.clone())
        .environment("é", b"different")
        .environment("text", b"hello")
        .environment("empty", b"")
        .build()
        .unwrap()
        .into_derivation();
    assert!(matches!(
        drv.to_json_bytes(),
        Err(Error::InvalidUtf8 { .. })
    ));
    check_round_trip(&drv);
    let mut wire = decode(&drv.to_cbor_bytes().unwrap());
    let env = field(&mut wire, "env");
    assert_eq!(field(env, "e\u{301}"), &Value::Bytes(bytes));
    assert_eq!(field(env, "text"), &Value::Bytes(b"hello".to_vec()));
    assert_eq!(field(env, "empty"), &Value::Bytes(Vec::new()));
}

#[test]
fn structured_attributes_keep_nix_number_and_string_semantics() {
    let attrs = StructuredAttrs::from_json_bytes(
        br#"{ "zero": -0.0, "int": 1, "float": 1.0, "big": 18446744073709551615, "tiny": 1e-100, "text": "e\u0301", "nested": [null, true, {}] }"#,
    ).unwrap();
    let canonical = attrs.canonical_json().to_vec();
    let drv = DerivationBuilder::new("attrs", "x86_64-linux", "/bin/sh")
        .input_addressed_output("out")
        .structured_attrs(attrs)
        .build()
        .unwrap()
        .into_derivation();
    check_round_trip(&drv);
    let mut wire = decode(&drv.to_cbor_bytes().unwrap());
    assert_eq!(
        field(&mut wire, "structuredAttrs"),
        &Value::Bytes(canonical)
    );
}

#[test]
fn encoded_key_order_and_length_boundaries_are_deterministic() {
    let mut wire = decode(GOLDEN);
    let keys = [
        String::new(),
        "z".into(),
        "aa".into(),
        "é".into(),
        "zzz".into(),
        "a".repeat(23),
        "a".repeat(24),
        "a".repeat(255),
        "a".repeat(256),
    ];
    *field(&mut wire, "env") = Value::Map(
        keys.into_iter()
            .rev()
            .map(|key| {
                let bytes = vec![0xff; key.len()];
                (key.into(), Value::Bytes(bytes))
            })
            .collect(),
    );
    let drv = cbor::from_slice(&encode(&wire)).unwrap();
    check_round_trip(&drv);
}

#[test]
fn custom_store_round_trips_out_of_band() {
    let fixture = include_bytes!("fixtures/json-v4/input-addressed.json");
    let store_dir = StoreDir::new("/custom/store").unwrap();
    let drv = Derivation::from_json_bytes_in(fixture, store_dir.clone()).unwrap();
    check_round_trip(&drv);
    assert_eq!(
        cbor::from_slice_in(&drv.to_cbor_bytes().unwrap(), store_dir).unwrap(),
        drv
    );
}

#[test]
fn all_output_variants_and_hash_algorithms_round_trip() {
    let mut wire = decode(GOLDEN);
    let mut outputs = vec![
        (Value::Text("input".into()), object([("path", PATH.into())])),
        (Value::Text("deferred".into()), object([])),
    ];
    for algorithm in ["md5", "sha1", "sha256", "sha512", "blake3"] {
        for method in ["flat", "nar", "git", "text"] {
            // Nix permits only SHA-256 with the text method.
            if method == "text" && algorithm != "sha256" {
                continue;
            }
            for impure in [false, true] {
                let mut value = object([("method", method.into()), ("hashAlgo", algorithm.into())]);
                if impure {
                    value
                        .as_map_mut()
                        .unwrap()
                        .push(("impure".into(), true.into()));
                }
                outputs.push((format!("{method}-{algorithm}-{impure}").into(), value));
            }
            let hash =
                nix_derivation::hash_bytes(algorithm.parse().unwrap(), b"test").to_sri_string();
            let ca = nix_derivation::CAHash::from_parts(
                method.parse().unwrap(),
                algorithm.parse().unwrap(),
                nix_derivation::hash_bytes(algorithm.parse().unwrap(), b"test").digest_as_bytes(),
            );
            if ca.is_ok() {
                outputs.push((
                    format!("fixed-{method}-{algorithm}").into(),
                    object([("method", method.into()), ("hash", hash.into())]),
                ));
            }
        }
    }
    *field(&mut wire, "outputs") = Value::Map(outputs);
    check_round_trip(&cbor::from_slice(&encode(&wire)).unwrap());
}

fn dynamic_wire(depth: usize) -> Value {
    let mut input = object([
        ("outputs", Value::Array(vec!["out".into()])),
        ("dynamicOutputs", object([])),
    ]);
    for _ in 0..depth {
        input = object([
            ("outputs", Value::Array(Vec::new())),
            ("dynamicOutputs", object([("out", input)])),
        ]);
    }
    let mut wire = decode(GOLDEN);
    *field(field(&mut wire, "inputs"), "drvs") = object([(PATH, input)]);
    wire
}

#[test]
fn maximum_dynamic_depth_round_trips_and_excess_is_rejected() {
    let depth = nix_derivation::MAX_DYNAMIC_INPUT_DEPTH;
    let drv = cbor::from_slice(&encode(&dynamic_wire(depth))).unwrap();
    assert_eq!(
        drv.input_derivations().values().next().unwrap().max_depth(),
        depth
    );
    check_round_trip(&drv);
    assert!(matches!(
        cbor::from_slice(&encode(&dynamic_wire(depth + 1))),
        Err(Error::Cbor(_))
    ));
}

#[test]
fn map_order_and_non_minimal_version_are_normalized() {
    let mut wire = decode(GOLDEN);
    wire.as_map_mut().unwrap().reverse();
    field(&mut wire, "env").as_map_mut().unwrap().reverse();
    assert_eq!(
        cbor::from_slice(&encode(&wire))
            .unwrap()
            .to_cbor_bytes()
            .unwrap(),
        GOLDEN
    );
    let mut bytes = GOLDEN[..GOLDEN.len() - 1].to_vec();
    bytes.extend_from_slice(&[0x18, 0x01]);
    assert_eq!(
        cbor::from_slice(&bytes).unwrap().to_cbor_bytes().unwrap(),
        GOLDEN
    );
}

#[test]
fn rejects_wrong_versions_missing_unknown_and_duplicate_fields() {
    let mut wire = decode(GOLDEN);
    *field(&mut wire, "version") = 4u64.into();
    assert!(matches!(
        cbor::from_slice(&encode(&wire)),
        Err(Error::UnsupportedCborVersion {
            found: 4,
            expected: 1
        })
    ));
    for index in 0..8 {
        let mut wire = decode(GOLDEN);
        wire.as_map_mut().unwrap().remove(index);
        assert!(cbor::from_slice(&encode(&wire)).is_err());
    }
    let mut wire = decode(GOLDEN);
    wire.as_map_mut()
        .unwrap()
        .push(("unknown".into(), 0u64.into()));
    assert!(cbor::from_slice(&encode(&wire)).is_err());
    for container in [None, Some("env"), Some("inputs")] {
        let mut wire = decode(GOLDEN);
        let map = match container {
            None => &mut wire,
            Some(key) => field(&mut wire, key),
        }
        .as_map_mut()
        .unwrap();
        map.push(map[0].clone());
        assert!(cbor::from_slice(&encode(&wire)).is_err());
    }
}

#[test]
fn rejects_wrong_types_and_malformed_structured_attributes() {
    for key in [
        "env", "args", "name", "inputs", "system", "builder", "outputs", "version",
    ] {
        let mut wire = decode(GOLDEN);
        *field(&mut wire, key) = Value::Null;
        assert!(cbor::from_slice(&encode(&wire)).is_err(), "{key}");
    }
    for value in [
        "text".into(),
        Value::Array(vec![255u64.into()]),
        Value::Null,
    ] {
        let mut wire = decode(GOLDEN);
        *field(field(&mut wire, "env"), "aa") = value;
        assert!(cbor::from_slice(&encode(&wire)).is_err());
    }
    for attrs in [
        object([]),
        Value::Null,
        Value::Bytes(b"[]".to_vec()),
        Value::Bytes(vec![0xff]),
    ] {
        let mut wire = decode(GOLDEN);
        wire.as_map_mut()
            .unwrap()
            .push(("structuredAttrs".into(), attrs));
        assert!(cbor::from_slice(&encode(&wire)).is_err());
    }
    let mut invalid_utf8 = GOLDEN.to_vec();
    let offset = invalid_utf8
        .windows(5)
        .position(|s| s == b"\x64name")
        .unwrap()
        + 6;
    invalid_utf8[offset] = 0xff;
    assert!(cbor::from_slice(&invalid_utf8).is_err());
}

#[test]
fn rejects_invalid_outputs_paths_and_duplicate_sets() {
    for output in [
        object([
            ("impure", false.into()),
            ("method", "nar".into()),
            ("hashAlgo", "sha256".into()),
        ]),
        object([("path", "bad-path".into())]),
        object([
            ("method", "bad-method".into()),
            ("hashAlgo", "sha256".into()),
        ]),
        object([("hash", "bad-hash".into()), ("method", "nar".into())]),
        object([("unknown", "field".into())]),
        object([("method", "nar".into())]),
        object([("path", PATH.into()), ("hashAlgo", "sha256".into())]),
    ] {
        let mut wire = decode(GOLDEN);
        *field(&mut wire, "outputs") = object([("out", output)]);
        assert!(cbor::from_slice(&encode(&wire)).is_err());
    }
    let mut wire = decode(GOLDEN);
    *field(field(&mut wire, "inputs"), "srcs") = Value::Array(vec![PATH.into(), PATH.into()]);
    assert!(cbor::from_slice(&encode(&wire)).is_err());
    let mut wire = dynamic_wire(0);
    let input = field(field(field(&mut wire, "inputs"), "drvs"), PATH);
    *field(input, "outputs") = Value::Array(vec!["out".into(), "out".into()]);
    assert!(cbor::from_slice(&encode(&wire)).is_err());
}

#[test]
fn rejects_truncation_trailing_data_tags_and_indefinite_lengths() {
    for end in 0..GOLDEN.len() {
        assert!(cbor::from_slice(&GOLDEN[..end]).is_err(), "prefix {end}");
    }
    let mut trailing = GOLDEN.to_vec();
    trailing.push(0);
    assert!(cbor::from_slice(&trailing).is_err());
    let mut tagged = vec![0xd9, 0xd9, 0xf7];
    tagged.extend_from_slice(GOLDEN);
    assert!(cbor::from_slice(&tagged).is_err());
    let mut indefinite = GOLDEN.to_vec();
    indefinite[0] = 0xbf;
    indefinite.push(0xff);
    assert!(cbor::from_slice(&indefinite).is_err());
    let mut enormous = vec![0xbb];
    enormous.extend_from_slice(&u64::MAX.to_be_bytes());
    assert!(cbor::from_slice(&enormous).is_err());
}

#[test]
fn arbitrary_and_mutated_input_never_panics_and_successes_round_trip() {
    for index in 0..GOLDEN.len() {
        for byte in 0..=255 {
            let mut bytes = GOLDEN.to_vec();
            bytes[index] = byte;
            if let Ok(drv) = cbor::from_slice(&bytes) {
                let canonical = drv.to_cbor_bytes().unwrap();
                assert_eq!(cbor::from_slice(&canonical).unwrap(), drv);
            }
        }
    }
    let mut state = 0x1234_5678u32;
    for length in 0..256 {
        let bytes: Vec<_> = (0..length)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                state as u8
            })
            .collect();
        let _ = cbor::from_slice(&bytes);
    }
}

#[test]
fn writer_errors_propagate() {
    struct Broken;
    impl io::Write for Broken {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("broken writer"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let error = cbor::from_slice(GOLDEN)
        .unwrap()
        .write_cbor(&mut Broken)
        .unwrap_err();
    assert!(matches!(error, Error::Cbor(_)));
    assert!(error.to_string().contains("broken writer"));
}
