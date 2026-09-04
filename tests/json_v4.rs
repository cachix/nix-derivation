use nix_derivation::{Derivation, DerivationBuilder, Error, Output, StoreDir, json};
use serde_json::{Value, json};

const SIMPLE: &str = r#"
{
  "args": ["bar", "baz"],
  "builder": "foo",
  "env": {"BIG_BAD": "WOLF"},
  "inputs": {
    "drvs": {
      "c015dhfh5l0lp6wxyvdn7bmwhbbr6hr9-dep2.drv": {
        "dynamicOutputs": {},
        "outputs": ["cat", "dog"]
      }
    },
    "srcs": ["c015dhfh5l0lp6wxyvdn7bmwhbbr6hr9-dep1"]
  },
  "name": "simple-derivation",
  "outputs": {},
  "system": "wasm-sel4",
  "version": 4
}
"#;

// Captured from `nix derivation show` with Nix 2.34.8.
const NIX_GENERATED_INPUT_ADDRESSED: &[u8] =
    include_bytes!("fixtures/json-v4/input-addressed.json");
const NIX_GENERATED_FIXED_OUTPUT: &[u8] = include_bytes!("fixtures/json-v4/fixed-output.json");

#[test]
fn nix_generated_fixtures_round_trip() {
    for fixture in [NIX_GENERATED_INPUT_ADDRESSED, NIX_GENERATED_FIXED_OUTPUT] {
        let expected: Value = serde_json::from_slice(fixture).unwrap();
        let derivation = json::from_slice(fixture).unwrap();
        assert_eq!(json::to_value(&derivation).unwrap(), expected);
        assert_eq!(
            json::from_slice(&derivation.to_json_bytes().unwrap()).unwrap(),
            derivation
        );
    }
}

#[test]
fn simple_nix_fixture_round_trips() {
    let derivation = Derivation::from_json_bytes(SIMPLE.as_bytes()).unwrap();
    assert_eq!(derivation.name(), "simple-derivation");
    assert_eq!(derivation.arguments(), ["bar", "baz"]);
    assert_eq!(derivation.input_sources().len(), 1);
    assert_eq!(derivation.input_derivations().len(), 1);

    let expected: Value = serde_json::from_str(SIMPLE).unwrap();
    assert_eq!(json::to_value(&derivation).unwrap(), expected);
    let reparsed = Derivation::from_json_bytes(&derivation.to_json_bytes().unwrap()).unwrap();
    assert_eq!(reparsed, derivation);
}

#[test]
fn recursive_dynamic_inputs_round_trip() {
    let encoded = json!({
        "args": [],
        "builder": "foo",
        "env": {},
        "inputs": {
            "drvs": {
                "c015dhfh5l0lp6wxyvdn7bmwhbbr6hr9-dep2.drv": {
                    "dynamicOutputs": {
                        "cat": {
                            "dynamicOutputs": {
                                "kitten": {
                                    "dynamicOutputs": {},
                                    "outputs": ["out"]
                                }
                            },
                            "outputs": ["kitten"]
                        }
                    },
                    "outputs": ["cat", "dog"]
                }
            },
            "srcs": []
        },
        "name": "dynamic",
        "outputs": {},
        "system": "x86_64-linux",
        "version": 4
    });
    let bytes = serde_json::to_vec(&encoded).unwrap();
    let derivation = json::from_slice(&bytes).unwrap();
    let input = derivation.input_derivations().values().next().unwrap();
    assert_eq!(input.max_depth(), 2);
    assert_eq!(json::to_value(&derivation).unwrap(), encoded);
}

#[test]
fn deepest_supported_dynamic_input_round_trips() {
    let mut input = json!({"dynamicOutputs": {}, "outputs": ["out"]});
    for depth in (0..nix_derivation::MAX_DYNAMIC_INPUT_DEPTH).rev() {
        input = json!({
            "dynamicOutputs": {format!("edge-{depth}"): input},
            "outputs": []
        });
    }
    let encoded = json!({
        "args": [],
        "builder": "foo",
        "env": {},
        "inputs": {
            "drvs": {"c015dhfh5l0lp6wxyvdn7bmwhbbr6hr9-dep2.drv": input},
            "srcs": []
        },
        "name": "deep-dynamic",
        "outputs": {},
        "system": "x86_64-linux",
        "version": 4
    });
    let derivation = json::from_slice(&serde_json::to_vec(&encoded).unwrap()).unwrap();
    let input = derivation.input_derivations().values().next().unwrap();
    assert_eq!(input.max_depth(), nix_derivation::MAX_DYNAMIC_INPUT_DEPTH);
    assert_eq!(json::to_value(&derivation).unwrap(), encoded);
}

#[test]
fn excessive_dynamic_input_depth_is_rejected() {
    let mut input = json!({"dynamicOutputs": {}, "outputs": ["out"]});
    for depth in (0..=nix_derivation::MAX_DYNAMIC_INPUT_DEPTH).rev() {
        input = json!({
            "dynamicOutputs": {format!("edge-{depth}"): input},
            "outputs": []
        });
    }
    let encoded = json!({
        "args": [],
        "builder": "foo",
        "env": {},
        "inputs": {
            "drvs": {"c015dhfh5l0lp6wxyvdn7bmwhbbr6hr9-dep2.drv": input},
            "srcs": []
        },
        "name": "too-deep",
        "outputs": {},
        "system": "x86_64-linux",
        "version": 4
    });
    assert!(matches!(
        json::from_slice(&serde_json::to_vec(&encoded).unwrap()),
        Err(Error::InvalidDerivation(_))
    ));
}

#[test]
fn every_output_shape_matches_nix_json() {
    let encoded = json!({
        "args": [],
        "builder": "foo",
        "env": {},
        "inputs": {"drvs": {}, "srcs": []},
        "name": "outputs",
        "outputs": {
            "input": {"path": "c015dhfh5l0lp6wxyvdn7bmwhbbr6hr9-output"},
            "flat": {
                "hash": "sha256-iUUXyRY8iW7DGirb0zwGgf1fRbLA7wimTJKgP7l/OQ8=",
                "method": "flat"
            },
            "nar": {
                "hash": "sha256-iUUXyRY8iW7DGirb0zwGgf1fRbLA7wimTJKgP7l/OQ8=",
                "method": "nar"
            },
            "text": {
                "hash": "sha256-iUUXyRY8iW7DGirb0zwGgf1fRbLA7wimTJKgP7l/OQ8=",
                "method": "text"
            },
            "blake3": {
                "hash": "blake3-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                "method": "nar"
            },
            "floating": {"hashAlgo": "sha256", "method": "nar"},
            "deferred": {},
            "impure": {"hashAlgo": "sha256", "impure": true, "method": "nar"}
        },
        "system": "x86_64-linux",
        "version": 4
    });
    let derivation = json::from_slice(&serde_json::to_vec(&encoded).unwrap()).unwrap();
    assert!(matches!(
        derivation.outputs()["input"],
        Output::InputAddressed { .. }
    ));
    assert!(matches!(derivation.outputs()["flat"], Output::Fixed { .. }));
    assert!(matches!(
        derivation.outputs()["floating"],
        Output::Floating { .. }
    ));
    assert!(matches!(derivation.outputs()["deferred"], Output::Deferred));
    assert!(matches!(
        derivation.outputs()["impure"],
        Output::Impure { .. }
    ));
    assert_eq!(json::to_value(&derivation).unwrap(), encoded);
}

#[test]
fn structured_attributes_remain_separate_from_env() {
    let encoded = json!({
        "args": [],
        "builder": "foo",
        "env": {"plain": "value"},
        "inputs": {"drvs": {}, "srcs": []},
        "name": "structured",
        "outputs": {},
        "structuredAttrs": {"z": 1, "nested": {"enabled": true}},
        "system": "x86_64-linux",
        "version": 4
    });
    let derivation = json::from_slice(&serde_json::to_vec(&encoded).unwrap()).unwrap();
    assert!(!derivation.environment().contains_key("__json"));
    assert_eq!(
        derivation.structured_attrs().unwrap().get("z"),
        Some(&json!(1))
    );
    assert_eq!(json::to_value(&derivation).unwrap(), encoded);
}

#[test]
fn structured_float_rendering_matches_nix_inside_full_json() {
    let encoded = json!({
        "args": [],
        "builder": "foo",
        "env": {},
        "inputs": {"drvs": {}, "srcs": []},
        "name": "floats",
        "outputs": {},
        "structuredAttrs": {
            "five": 1e-5,
            "fixed": 1e-4,
            "large": 1e20,
            "negativeZero": -0.0,
            "seven": 1e-7,
            "whole": 10000000.0
        },
        "system": "x86_64-linux",
        "version": 4
    });
    let derivation = json::from_slice(&serde_json::to_vec(&encoded).unwrap()).unwrap();
    let rendered = String::from_utf8(derivation.to_json_bytes().unwrap()).unwrap();
    assert!(rendered.contains(
        r#""structuredAttrs":{"five":1e-05,"fixed":0.0001,"large":1e+20,"negativeZero":-0.0,"seven":1e-07,"whole":10000000.0}"#
    ));
}

#[test]
fn custom_store_is_retained_while_json_paths_stay_as_basenames() {
    let store_dir = StoreDir::new("/gnu/store").unwrap();
    let derivation = json::from_slice_in(SIMPLE.as_bytes(), store_dir.clone()).unwrap();
    assert_eq!(derivation.store_dir(), &store_dir);
    assert_eq!(
        json::to_value(&derivation).unwrap(),
        serde_json::from_str::<Value>(SIMPLE).unwrap()
    );
}

#[test]
fn present_null_structured_attributes_are_rejected() {
    let mut encoded: Value = serde_json::from_str(SIMPLE).unwrap();
    encoded["structuredAttrs"] = Value::Null;
    assert!(matches!(
        json::from_slice(&serde_json::to_vec(&encoded).unwrap()),
        Err(Error::StructuredAttrs(_))
    ));
}

#[test]
fn rejects_wrong_version_and_noncanonical_store_paths() {
    let mut wrong_version: Value = serde_json::from_str(SIMPLE).unwrap();
    wrong_version["version"] = json!(3);
    assert!(matches!(
        json::from_slice(&serde_json::to_vec(&wrong_version).unwrap()),
        Err(Error::UnsupportedJsonVersion {
            found: 3,
            expected: 4
        })
    ));

    let mut absolute: Value = serde_json::from_str(SIMPLE).unwrap();
    absolute["inputs"]["srcs"] = json!(["/nix/store/c015dhfh5l0lp6wxyvdn7bmwhbbr6hr9-dep1"]);
    assert!(json::from_slice(&serde_json::to_vec(&absolute).unwrap()).is_err());
}

#[test]
fn rejects_unsupported_version_before_decoding_v4_fields() {
    let mut older: Value = serde_json::from_str(SIMPLE).unwrap();
    older["version"] = json!(3);
    older.as_object_mut().unwrap().remove("inputs");

    assert!(matches!(
        json::from_slice(&serde_json::to_vec(&older).unwrap()),
        Err(Error::UnsupportedJsonVersion {
            found: 3,
            expected: 4
        })
    ));
}

#[test]
fn fixed_output_hashes_must_use_sri_encoding() {
    let mut encoded: Value = serde_json::from_str(SIMPLE).unwrap();
    for hash in [
        "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        "sha256:0000000000000000000000000000000000000000000000000000",
        "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    ] {
        encoded["outputs"]["out"] = json!({"hash": hash, "method": "flat"});
        assert!(matches!(
            json::from_slice(&serde_json::to_vec(&encoded).unwrap()),
            Err(Error::InvalidHash(_))
        ));
    }
}

#[test]
fn malformed_required_fields_and_output_shapes_are_rejected() {
    let base: Value = serde_json::from_str(SIMPLE).unwrap();

    for field in [
        "version", "name", "outputs", "inputs", "system", "builder", "args", "env",
    ] {
        let mut encoded = base.clone();
        encoded.as_object_mut().unwrap().remove(field);
        assert!(
            json::from_slice(&serde_json::to_vec(&encoded).unwrap()).is_err(),
            "missing field {field:?} was accepted"
        );
    }

    for (field, invalid) in [
        ("version", json!("4")),
        ("name", json!(4)),
        ("outputs", json!([])),
        ("inputs", json!([])),
        ("system", json!(null)),
        ("builder", json!([])),
        ("args", json!([1])),
        ("env", json!({"key": 1})),
    ] {
        let mut encoded = base.clone();
        encoded[field] = invalid;
        assert!(
            json::from_slice(&serde_json::to_vec(&encoded).unwrap()).is_err(),
            "invalid field {field:?} was accepted"
        );
    }

    let invalid_outputs = [
        json!({"path": 1}),
        json!({"hash": "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}),
        json!({"hash": "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "method": "unknown"}),
        json!({"hashAlgo": "unknown", "method": "nar"}),
        json!({"hashAlgo": "sha256", "method": "nar", "extra": true}),
        json!({"impure": true, "hashAlgo": "sha256"}),
    ];
    for output in invalid_outputs {
        let mut encoded = base.clone();
        encoded["outputs"]["out"] = output.clone();
        assert!(
            json::from_slice(&serde_json::to_vec(&encoded).unwrap()).is_err(),
            "invalid output {output} was accepted"
        );
    }

    for missing in ["outputs", "dynamicOutputs"] {
        let mut encoded = base.clone();
        encoded["inputs"]["drvs"]["c015dhfh5l0lp6wxyvdn7bmwhbbr6hr9-dep2.drv"]
            .as_object_mut()
            .unwrap()
            .remove(missing);
        assert!(
            json::from_slice(&serde_json::to_vec(&encoded).unwrap()).is_err(),
            "input derivation missing {missing:?} was accepted"
        );
    }

    for malformed in [b"null".as_slice(), b"[]", b"{}", b"{", b"{} null"] {
        assert!(
            json::from_slice(malformed).is_err(),
            "malformed top-level JSON was accepted: {}",
            String::from_utf8_lossy(malformed)
        );
    }
}

#[test]
fn impure_marker_matches_nix_presence_semantics() {
    let mut encoded: Value = serde_json::from_str(SIMPLE).unwrap();
    encoded["outputs"]["out"] = json!({"hashAlgo": "sha256", "impure": false, "method": "nar"});

    let derivation = json::from_slice(&serde_json::to_vec(&encoded).unwrap()).unwrap();
    assert!(matches!(derivation.outputs()["out"], Output::Impure { .. }));
    assert_eq!(
        json::to_value(&derivation).unwrap()["outputs"]["out"]["impure"],
        true
    );
}

#[test]
fn json_serialization_rejects_non_utf8_environment_values() {
    let derivation = DerivationBuilder::new("binary-env", "x86_64-linux", "/bin/sh")
        .input_addressed_output("out")
        .environment("binary", vec![0xff])
        .build()
        .unwrap();
    assert!(matches!(
        derivation.to_json_bytes(),
        Err(Error::InvalidUtf8 { .. })
    ));
}
