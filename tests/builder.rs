use nix_derivation::{
    DerivationBuilder, Error, InputDerivation, Output, StorePath, StructuredAttrs,
    ValidatedDerivation,
};

const OUTPUT_PATH: &str = "/nix/store/00000000000000000000000000000000-example";
const NIX_BUILDER_OUTPUT: &str = "/nix/store/j4vdph5j6dn2hj3lc810ks94hwa3q36z-example";
const NIX_NO_ARGS_OUTPUT: &str = "/nix/store/lfqgy7hz7qah9142l43r0a96xnnjmxqy-example";
const INPUT_DRV: &str = "/nix/store/11111111111111111111111111111111-input.drv";

fn output() -> Output {
    Output::InputAddressed {
        path: OUTPUT_PATH.parse().unwrap(),
    }
}

#[test]
fn builder_produces_canonical_aterm() {
    let derivation = DerivationBuilder::new("example", "x86_64-linux", "/bin/sh")
        .output("out", output())
        .argument("-c")
        .argument("printf built > $out")
        .environment("out", OUTPUT_PATH.as_bytes())
        .build()
        .unwrap();

    assert_eq!(derivation.name(), "example");
    assert!(!derivation.is_fixed_output());
    assert_eq!(
        derivation.to_aterm_bytes(),
        format!(
            "Derive([(\"out\",\"{NIX_BUILDER_OUTPUT}\",\"\",\"\")],[],[],\"x86_64-linux\",\"/bin/sh\",[\"-c\",\"printf built > $out\"],[(\"out\",\"{NIX_BUILDER_OUTPUT}\")])"
        )
        .as_bytes()
    );
}

#[test]
fn parsed_derivation_can_be_edited_without_cloning() {
    let original = DerivationBuilder::new("example", "x86_64-linux", "/bin/sh")
        .output("out", output())
        .build()
        .unwrap()
        .into_derivation();
    let mut builder = original.into_builder();
    builder.arguments_mut().push("--verbose".to_owned());
    builder
        .environment_mut()
        .insert("mode".to_owned(), b"release".to_vec());

    let edited = builder.build().unwrap();
    assert_eq!(edited.arguments(), ["--verbose"]);
    assert_eq!(edited.environment()["mode"], b"release");
}

#[test]
fn structured_json_is_a_typed_builder_input() {
    let attrs =
        StructuredAttrs::from_json_bytes(br#" { "z": 1, "flags": { "enabled": true } } "#).unwrap();
    let derivation = DerivationBuilder::new("structured", "x86_64-linux", "/bin/sh")
        .output("out", output())
        .structured_attrs(attrs)
        .build()
        .unwrap();

    let attrs = derivation.structured_attrs().unwrap();
    assert_eq!(attrs.get("flags").unwrap()["enabled"], true);
    assert_eq!(
        attrs.canonical_json(),
        br#"{"flags":{"enabled":true},"z":1}"#
    );
    let files = derivation.structured_attrs_files().unwrap().unwrap();
    assert!(files.json.windows(7).any(|window| window == b"outputs"));
}

#[test]
fn dynamic_inputs_are_constructible_and_walkable() {
    let nested = InputDerivation::new(["dev"])
        .with_dynamic_output("nested", InputDerivation::new(["out"]))
        .unwrap();
    let input = InputDerivation::new(["out"])
        .with_dynamic_output("generated", nested)
        .unwrap();
    let derivation = DerivationBuilder::new("dynamic", "x86_64-linux", "/bin/sh")
        .output("out", output())
        .input_derivation(INPUT_DRV.parse().unwrap(), input)
        .build_with_input_hashes(|_| [0x42; 32])
        .unwrap();

    let input = derivation.input_derivations().values().next().unwrap();
    assert_eq!(input.max_depth(), 2);
    assert_eq!(input.walk().count(), 3);
    assert!(
        derivation
            .to_aterm_bytes()
            .starts_with(b"DrvWithVersion(\"xp-dyn-drv\",")
    );
}

#[test]
fn builder_rejects_invalid_states() {
    assert!(matches!(
        DerivationBuilder::new("missing-output", "x86_64-linux", "/bin/sh").build(),
        Err(Error::InvalidDerivation(_))
    ));
    assert!(matches!(
        DerivationBuilder::new("bad/name", "x86_64-linux", "/bin/sh")
            .output("out", output())
            .build(),
        Err(Error::InvalidDerivation(_))
    ));
    assert!(matches!(
        DerivationBuilder::new("reserved", "x86_64-linux", "/bin/sh")
            .output("out", output())
            .environment("__json", b"{}")
            .build(),
        Err(Error::InvalidDerivation(_))
    ));
    assert!(matches!(
        DerivationBuilder::new("needs-input-hash", "x86_64-linux", "/bin/sh")
            .output("out", output())
            .input_derivation(INPUT_DRV.parse().unwrap(), InputDerivation::new(["out"]),)
            .build(),
        Err(Error::InvalidDerivation(_))
    ));
}

#[test]
fn dynamic_input_construction_enforces_the_parser_limit() {
    let mut input = InputDerivation::new(["out"]);
    for depth in 0..256 {
        input = InputDerivation::new(["out"])
            .with_dynamic_output(format!("level-{depth}"), input)
            .unwrap();
    }
    assert_eq!(input.max_depth(), 256);
    let overflow = InputDerivation::new(["out"]).with_dynamic_output("overflow", input.clone());
    assert!(matches!(overflow, Err(Error::InvalidDerivation(_))));

    DerivationBuilder::new("deep", "x86_64-linux", "/bin/sh")
        .output("out", output())
        .input_derivation(INPUT_DRV.parse().unwrap(), input)
        .build_with_input_hashes(|_| [0x42; 32])
        .unwrap();
}

#[test]
fn validated_parser_rejects_characterization_only_derivations() {
    let bytes = include_bytes!("../benches/corpus/dynamic-derivation.drv");
    assert!(matches!(
        ValidatedDerivation::from_aterm_bytes(bytes, "dyn-dep-derivation"),
        Err(Error::InvalidDerivation(_))
    ));
}

#[test]
fn validated_wrapper_makes_derived_views_infallible() {
    let derivation = DerivationBuilder::new("example", "x86_64-linux", "/bin/sh")
        .output("out", output())
        .build()
        .unwrap();
    let outputs = derivation.resolved_outputs();
    assert_eq!(
        outputs["out"].path.as_ref().unwrap().to_absolute_path(),
        NIX_NO_ARGS_OUTPUT
    );
    let drv_path: StorePath = derivation.drv_path();
    assert!(drv_path.is_derivation());

    let reparsed =
        ValidatedDerivation::from_aterm_bytes(&derivation.to_aterm_bytes(), derivation.name())
            .unwrap();
    assert_eq!(reparsed, derivation);
}
