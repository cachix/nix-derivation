use nix_derivation::Derivation;

fn fixture_bytes(bytes: &'static [u8]) -> &'static [u8] {
    bytes.strip_suffix(b"\n").unwrap_or(bytes)
}

fn parse_fixture(bytes: &'static [u8], name: &str) -> Derivation {
    let derivation = Derivation::from_aterm_bytes(fixture_bytes(bytes), name).unwrap();
    let canonical = derivation.to_aterm_bytes();
    assert_eq!(canonical, fixture_bytes(bytes));

    let reparsed = Derivation::from_aterm_bytes(&canonical, name).unwrap();
    assert_eq!(reparsed.to_aterm_bytes(), canonical);
    derivation
}

#[test]
fn nix_generated_structured_attrs_round_trip() {
    let derivation = parse_fixture(
        include_bytes!("../benches/corpus/structured-attrs.drv"),
        "bench-structured-attrs",
    );

    derivation.validate().unwrap();
    let attrs = derivation.structured_attrs().unwrap();
    assert_eq!(attrs.get("flags").unwrap()["enabled"], true);
    let keys: Vec<_> = attrs.iter().map(|(key, _)| key).collect();
    assert!(keys.windows(2).all(|pair| pair[0] < pair[1]));
    assert!(
        attrs
            .raw_json()
            .windows(b"matrix".len())
            .any(|w| w == b"matrix")
    );
    assert!(
        attrs
            .canonical_json()
            .windows(b"matrix".len())
            .any(|w| w == b"matrix")
    );
    let files = derivation.structured_attrs_files().unwrap().unwrap();
    assert!(files.json.windows(b"matrix".len()).any(|w| w == b"matrix"));
}

#[test]
fn nix_generated_many_inputs_round_trip() {
    let derivation = parse_fixture(
        include_bytes!("../benches/corpus/many-inputs.drv"),
        "bench-many-inputs",
    );

    derivation.validate().unwrap();
    assert_eq!(derivation.input_sources().len(), 128);
    derivation
        .hash_derivation_modulo(true, |_| [0x42; 32])
        .unwrap();
}

#[test]
fn nix_generated_fixed_output_round_trips_and_hashes() {
    let derivation = parse_fixture(
        include_bytes!("../benches/corpus/fixed-output.drv"),
        "bench-fixed-output",
    );

    derivation.validate().unwrap();
    assert!(derivation.is_fixed_output().unwrap());
    derivation
        .hash_derivation_modulo(true, |_| panic!("fixed output has no input derivations"))
        .unwrap();
}

#[test]
fn nix_generated_escaped_strings_round_trip_exactly() {
    let derivation = parse_fixture(
        include_bytes!("../benches/corpus/escapes.drv"),
        "bench-escapes",
    );

    derivation.validate().unwrap();
    let arguments = derivation.arguments();
    assert!(arguments.iter().any(|arg| arg.contains('λ')));
    assert!(arguments.iter().any(|arg| arg.contains('\t')));
    assert!(arguments.iter().any(|arg| arg.contains('\r')));
    assert!(arguments.iter().any(|arg| arg.contains('\n')));
}

#[test]
fn nix_dynamic_characterization_fixture_round_trips() {
    let derivation = parse_fixture(
        include_bytes!("../benches/corpus/dynamic-derivation.drv"),
        "dyn-dep-derivation",
    );

    assert_eq!(derivation.input_derivations().len(), 1);
    let input = derivation.input_derivations().values().next().unwrap();
    assert_eq!(input.max_depth(), 1);
    assert_eq!(input.walk().count(), 3);
    assert!(derivation.validate().is_err());
}
