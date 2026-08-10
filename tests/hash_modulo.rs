use std::cell::Cell;

use nix_derivation::{
    Derivation, DerivationBuilder, DerivationModuloHash, Error, InputDerivation,
    InputDerivationHash, Output, OutputPathHash, StorePath,
};

const DUMMY_OUTPUT: &str = "/nix/store/00000000000000000000000000000000-parent";
const INPUT_A: &str = "/nix/store/00000000000000000000000000000000-a.drv";
const INPUT_B: &str = "/nix/store/11111111111111111111111111111111-b.drv";

fn input_addressed_output() -> Output {
    Output::InputAddressed {
        path: DUMMY_OUTPUT.parse().unwrap(),
    }
}

#[test]
fn modulo_hash_is_a_typed_round_trippable_digest() {
    let bytes = [0x12; 32];
    let hash = DerivationModuloHash::new(bytes);
    assert_eq!(hash.as_bytes(), &bytes);
    assert_eq!(hash.into_bytes(), bytes);
    assert_eq!(hash.to_string(), "12".repeat(32));

    let regular = InputDerivationHash::regular(bytes);
    assert_eq!(regular.regular_hash(), Some(&hash));
    assert_eq!(regular.fixed_output_hash(), None);

    let fixed = InputDerivationHash::fixed_output(bytes);
    assert_eq!(fixed.fixed_output_hash(), Some(&hash));
    assert_eq!(fixed.regular_hash(), None);

    let ready = OutputPathHash::ready(bytes);
    assert_eq!(ready.as_ready(), Some(&hash));
    assert_eq!(ready.into_ready(), Some(hash));
}

#[test]
fn fixed_output_hashes_are_named_and_rewritten_as_out_inputs() {
    let bytes = include_bytes!("../benches/corpus/fixed-output.drv");
    let fixed = Derivation::from_aterm_bytes(
        bytes.strip_suffix(b"\n").unwrap_or(bytes),
        "bench-fixed-output",
    )
    .unwrap();
    let modulo = fixed
        .hash_input_derivation_modulo(|_| -> [u8; 32] { unreachable!() })
        .unwrap();
    assert!(modulo.fixed_output_hash().is_some());

    let fixed_path: StorePath = fixed.drv_path().unwrap();
    let parent = DerivationBuilder::new("parent", "x86_64-linux", "/bin/sh")
        .output("out", input_addressed_output())
        .input_derivation(fixed_path, InputDerivation::new(["out"]))
        .build_with_input_hashes(|_| modulo)
        .unwrap();
    assert!(parent.resolved_outputs()["out"].path.is_some());
}

#[test]
fn fixed_input_rejects_a_non_out_requested_output() {
    let error = DerivationBuilder::new("parent", "x86_64-linux", "/bin/sh")
        .output("out", input_addressed_output())
        .input_derivation(INPUT_A.parse().unwrap(), InputDerivation::new(["dev"]))
        .build_with_input_hashes(|_| InputDerivationHash::fixed_output([1; 32]))
        .unwrap_err();
    assert!(matches!(error, Error::InvalidDerivation(_)));
}

#[test]
fn later_input_replaces_requested_outputs_for_equal_regular_hashes() {
    let two_paths = DerivationBuilder::new("parent", "x86_64-linux", "/bin/sh")
        .output("out", input_addressed_output())
        .input_derivation(INPUT_A.parse().unwrap(), InputDerivation::new(["dev"]))
        .input_derivation(INPUT_B.parse().unwrap(), InputDerivation::new(["out"]))
        .build_with_input_hashes(|_| [7; 32])
        .unwrap();
    let one_path = DerivationBuilder::new("parent", "x86_64-linux", "/bin/sh")
        .output("out", input_addressed_output())
        .input_derivation(INPUT_A.parse().unwrap(), InputDerivation::new(["out"]))
        .build_with_input_hashes(|_| [7; 32])
        .unwrap();
    assert_eq!(two_paths.resolved_outputs(), one_path.resolved_outputs());
}

#[test]
fn fixed_input_replaces_requested_outputs_for_a_colliding_hash() {
    let collision = [7; 32];
    let regular_then_fixed = DerivationBuilder::new("parent", "x86_64-linux", "/bin/sh")
        .output("out", input_addressed_output())
        .input_derivation(INPUT_A.parse().unwrap(), InputDerivation::new(["dev"]))
        .input_derivation(INPUT_B.parse().unwrap(), InputDerivation::new(["out"]))
        .build_with_input_hashes(|path| {
            if path.to_absolute_path() == INPUT_A {
                InputDerivationHash::regular(collision)
            } else {
                InputDerivationHash::fixed_output(collision)
            }
        })
        .unwrap();
    let fixed_only = DerivationBuilder::new("parent", "x86_64-linux", "/bin/sh")
        .output("out", input_addressed_output())
        .input_derivation(INPUT_B.parse().unwrap(), InputDerivation::new(["out"]))
        .build_with_input_hashes(|_| InputDerivationHash::fixed_output(collision))
        .unwrap();
    assert_eq!(
        regular_then_fixed.resolved_outputs(),
        fixed_only.resolved_outputs()
    );
}

#[test]
fn deferred_and_dynamic_inputs_stop_hashing_before_lookup() {
    let parent = DerivationBuilder::new("parent", "x86_64-linux", "/bin/sh")
        .output("out", input_addressed_output())
        .input_derivation(INPUT_A.parse().unwrap(), InputDerivation::new(["out"]))
        .build_with_input_hashes(|_| [1; 32])
        .unwrap()
        .into_derivation();
    assert_eq!(
        parent
            .hash_output_path_modulo(|_| InputDerivationHash::Deferred)
            .unwrap(),
        OutputPathHash::Deferred
    );

    let dynamic = DerivationBuilder::new("dynamic", "x86_64-linux", "/bin/sh")
        .output("out", Output::Deferred)
        .input_derivation(
            INPUT_A.parse().unwrap(),
            InputDerivation::new(Vec::<String>::new())
                .with_dynamic_output("generated", InputDerivation::new(["out"]))
                .unwrap(),
        )
        .build()
        .unwrap();
    let calls = Cell::new(0);
    let modulo = dynamic
        .hash_input_derivation_modulo(|_| {
            calls.set(calls.get() + 1);
            [1; 32]
        })
        .unwrap();
    assert_eq!(modulo, InputDerivationHash::Deferred);
    assert_eq!(calls.get(), 0);
}

#[test]
fn builder_fills_resolvable_deferred_outputs() {
    let without_inputs = DerivationBuilder::new("deferred", "x86_64-linux", "/bin/sh")
        .output("out", Output::Deferred)
        .build()
        .unwrap();
    assert!(matches!(
        without_inputs.outputs()["out"],
        Output::InputAddressed { .. }
    ));
    assert_eq!(
        without_inputs.environment()["out"],
        without_inputs.resolved_outputs()["out"]
            .path
            .as_ref()
            .unwrap()
            .to_absolute_path()
            .as_bytes()
    );

    let with_input = DerivationBuilder::new("deferred-input", "x86_64-linux", "/bin/sh")
        .output("out", Output::Deferred)
        .input_derivation(INPUT_A.parse().unwrap(), InputDerivation::new(["out"]))
        .build_with_input_hashes(|_| [3; 32])
        .unwrap();
    assert!(matches!(
        with_input.outputs()["out"],
        Output::InputAddressed { .. }
    ));
}

#[test]
fn non_input_addressed_outputs_have_no_output_path_modulo() {
    let bytes = include_bytes!("../benches/corpus/fixed-output.drv");
    let fixed = Derivation::from_aterm_bytes(
        bytes.strip_suffix(b"\n").unwrap_or(bytes),
        "bench-fixed-output",
    )
    .unwrap();
    assert!(matches!(
        fixed.hash_output_path_modulo(|_| -> [u8; 32] { unreachable!() }),
        Err(Error::InvalidDerivation(_))
    ));
}
