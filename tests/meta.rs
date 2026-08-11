use nix_derivation::{
    Derivation, DerivationBuilder, DerivationMeta, Error, InputDerivationHash, Output,
    StructuredAttrs,
};

const DUMMY_OUTPUT: &str = "/nix/store/00000000000000000000000000000000-meta-test";

fn input_addressed_output() -> Output {
    Output::InputAddressed {
        path: DUMMY_OUTPUT.parse().unwrap(),
    }
}

fn meta(json: &[u8]) -> DerivationMeta {
    DerivationMeta::from_json_bytes(json).unwrap()
}

fn build_with_meta(json: &[u8]) -> nix_derivation::ValidatedDerivation {
    DerivationBuilder::new("meta-test", "x86_64-linux", "/bin/sh")
        .output("out", input_addressed_output())
        .argument("-c")
        .argument("echo hello > $out")
        .meta(meta(json))
        .build()
        .unwrap()
}

fn aterm_with_json(json: &str) -> Vec<u8> {
    let escaped = json.replace('\\', "\\\\").replace('"', "\\\"");
    format!(
        "Derive([(\"out\",\"{DUMMY_OUTPUT}\",\"\",\"\")],[],[],\"x86_64-linux\",\"/bin/sh\",[],[(\"__json\",\"{escaped}\"),(\"out\",\"{DUMMY_OUTPUT}\")])"
    )
    .into_bytes()
}

#[test]
fn metadata_changes_drv_identity_but_not_output_or_input_modulo() {
    let first = build_with_meta(br#"{"description":"First variant","version":"1.0"}"#);
    let second = build_with_meta(
        br#"{"description":"Second variant","maintainer":"someone","version":"2.0"}"#,
    );

    assert_eq!(first.resolved_outputs(), second.resolved_outputs());
    assert_ne!(first.drv_path(), second.drv_path());
    assert_eq!(
        first
            .hash_input_derivation_modulo(|_| -> InputDerivationHash { unreachable!() })
            .unwrap(),
        second
            .hash_input_derivation_modulo(|_| -> InputDerivationHash { unreachable!() })
            .unwrap()
    );
}

#[test]
fn metadata_is_reinjected_for_aterm_but_not_exposed_to_builders() {
    let derivation = build_with_meta(br#"{"description":"private builder metadata"}"#);
    let encoded = derivation.to_aterm_bytes();
    let encoded_text = String::from_utf8(encoded.clone()).unwrap();
    assert!(encoded_text.contains(r#"\"__meta\":{\"description\":\"private builder metadata\"}"#));
    assert!(encoded_text.contains(r#"\"requiredSystemFeatures\":[\"derivation-meta\"]"#));

    let files = derivation.structured_attrs_files().unwrap().unwrap();
    let builder_json = String::from_utf8(files.json).unwrap();
    assert!(!builder_json.contains("__meta"));
    assert!(!builder_json.contains("derivation-meta"));

    let reparsed = Derivation::from_aterm_bytes(&encoded, derivation.name()).unwrap();
    assert_eq!(
        reparsed.meta().unwrap().get("description").unwrap(),
        "private builder metadata"
    );
    assert!(reparsed.structured_attrs().unwrap().is_empty());
    assert_eq!(reparsed.to_aterm_bytes(), encoded);
}

#[test]
fn filtering_only_derivation_meta_matches_absent_required_features() {
    let baseline = DerivationBuilder::new("meta-test", "x86_64-linux", "/bin/sh")
        .output("out", input_addressed_output())
        .argument("-c")
        .argument("echo hello > $out")
        .structured_attrs(StructuredAttrs::from_json_bytes(b"{}").unwrap())
        .build()
        .unwrap();
    let with_meta = build_with_meta(br#"{"description":"ignored by quotient"}"#);

    assert_eq!(baseline.resolved_outputs(), with_meta.resolved_outputs());
}

#[test]
fn meta_without_system_feature_is_not_filtered_and_is_not_valid_build_input() {
    let invalid = Derivation::from_aterm_bytes(
        &aterm_with_json(r#"{"__meta":{"description":"not opted in"}}"#),
        "meta-test",
    )
    .unwrap();
    assert!(invalid.meta().is_none());
    assert!(invalid.structured_attrs().unwrap().get("__meta").is_some());
    assert!(matches!(
        invalid.validate(),
        Err(Error::InvalidDerivation(_))
    ));

    let filtered = build_with_meta(br#"{"description":"not opted in"}"#);
    let invalid_hash = invalid
        .hash_output_path_modulo(|_| -> [u8; 32] { unreachable!() })
        .unwrap()
        .into_ready()
        .unwrap();
    let filtered_hash = filtered
        .hash_output_path_modulo(|_| -> [u8; 32] { unreachable!() })
        .unwrap()
        .into_ready()
        .unwrap();
    assert_ne!(invalid_hash, filtered_hash);
}

#[test]
fn traditional_meta_environment_variable_remains_ordinary_input() {
    let build = |value: &'static [u8]| {
        DerivationBuilder::new("traditional-meta", "x86_64-linux", "/bin/sh")
            .output("out", input_addressed_output())
            .environment("__meta", value)
            .build()
            .unwrap()
    };
    let first = build(b"first");
    let second = build(b"second");
    assert!(first.meta().is_none());
    assert_eq!(first.environment()["__meta"], b"first");
    assert_ne!(first.resolved_outputs(), second.resolved_outputs());
}

#[test]
fn meta_requires_a_strictly_sorted_feature_list() {
    let unsorted = aterm_with_json(
        r#"{"__meta":{},"requiredSystemFeatures":["derivation-meta","benchmark"]}"#,
    );
    assert!(matches!(
        Derivation::from_aterm_bytes(&unsorted, "meta-test"),
        Err(Error::StructuredAttrs(_))
    ));

    let unrelated = aterm_with_json(r#"{"requiredSystemFeatures":["z","a"]}"#);
    Derivation::from_aterm_bytes(&unrelated, "meta-test").unwrap();
}

#[test]
fn empty_metadata_round_trips() {
    let derivation = build_with_meta(b"{}");
    assert!(derivation.meta().unwrap().is_empty());
    let reparsed =
        Derivation::from_aterm_bytes(&derivation.to_aterm_bytes(), derivation.name()).unwrap();
    assert!(reparsed.meta().unwrap().is_empty());
}

#[test]
fn proposed_nix_meta_aterm_fixture_round_trips_semantically() {
    let bytes = br#"Derive([("out","/nix/store/c015dhfh5l0lp6wxyvdn7bmwhbbr6hr9-meta-derivation","","")],[],["/nix/store/c015dhfh5l0lp6wxyvdn7bmwhbbr6hr9-dep1"],"x86_64-linux","/bin/sh",["-c","echo hello > $out"],[("__json","{\"__meta\":{\"description\":\"A test derivation\",\"maintainer\":\"test@example.com\",\"version\":\"1.0\"},\"requiredSystemFeatures\":[\"derivation-meta\"]}"),("out","/nix/store/c015dhfh5l0lp6wxyvdn7bmwhbbr6hr9-meta-derivation")])"#;
    let derivation = Derivation::from_aterm_bytes(bytes, "meta-derivation").unwrap();
    assert_eq!(
        derivation.meta().unwrap().get("maintainer").unwrap(),
        "test@example.com"
    );
    assert!(derivation.structured_attrs().unwrap().is_empty());
    assert_eq!(derivation.to_aterm_bytes(), bytes);
}
