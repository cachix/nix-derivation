use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};

use crate::{
    CAHash, ContentAddressMethod, Derivation, Error, HashAlgorithm, NixHash, Output,
    store_path::{self, StorePath},
    write,
};
use sha2::{Digest as _, Sha256};

const PATH: &str = "/nix/store/00000000000000000000000000000000-example";

fn aterm(output: &str, environment: &str) -> Vec<u8> {
    format!("Derive([{output}],[],[],\"x86_64-linux\",\"/bin/sh\",[\"-c\"],[{environment}])")
        .into_bytes()
}

#[test]
fn parses_and_round_trips_every_modern_output_variant() {
    let fixed_ca = CAHash::Nar(NixHash::Sha256([0; 32]));
    let fixed_path = store_path::build_ca_path("example", &fixed_ca, std::iter::empty(), false)
        .unwrap()
        .to_absolute_path();
    let cases = [
        (
            format!("(\"out\",\"{PATH}\",\"\",\"\")"),
            Output::InputAddressed {
                path: StorePath::from_absolute_path(PATH.as_bytes()).unwrap(),
            },
        ),
        (
            "(\"out\",\"\",\"r:sha256\",\"\")".to_owned(),
            Output::Floating {
                method: ContentAddressMethod::Nar,
                hash_algorithm: HashAlgorithm::Sha256,
            },
        ),
        ("(\"out\",\"\",\"\",\"\")".to_owned(), Output::Deferred),
        (
            "(\"out\",\"\",\"text:sha256\",\"impure\")".to_owned(),
            Output::Impure {
                method: ContentAddressMethod::Text,
                hash_algorithm: HashAlgorithm::Sha256,
            },
        ),
        (
            format!(
                "(\"out\",\"{fixed_path}\",\"r:sha256\",\"{}\")",
                "00".repeat(32)
            ),
            Output::Fixed { ca: fixed_ca },
        ),
    ];

    for (encoded_output, expected) in cases {
        let bytes = aterm(&encoded_output, "");
        let derivation = Derivation::from_aterm_bytes(&bytes, "example").unwrap();
        assert_eq!(derivation.outputs()["out"], expected);
        assert_eq!(derivation.to_aterm_bytes(), bytes);
    }
}

#[test]
fn fixed_git_outputs_round_trip_and_hash() {
    let ca = CAHash::Git(NixHash::Sha1([0; 20]));
    let path = store_path::build_ca_path("git-fixed", &ca, std::iter::empty(), false)
        .unwrap()
        .to_absolute_path();
    assert_eq!(
        path,
        "/nix/store/9jpyi4pgclb53mq0wd8p36anb1xda4s3-git-fixed"
    );
    let bytes = aterm(
        &format!("(\"out\",\"{path}\",\"git:sha1\",\"{}\")", "00".repeat(20)),
        "",
    );
    let derivation = Derivation::from_aterm_bytes(&bytes, "git-fixed").unwrap();
    assert_eq!(derivation.outputs()["out"], Output::Fixed { ca });
    assert_eq!(derivation.to_aterm_bytes(), bytes);
    assert!(derivation.is_fixed_output().unwrap());
    assert_eq!(
        derivation
            .hash_derivation_modulo(false, |_| unreachable!())
            .unwrap(),
        [
            132, 204, 128, 229, 240, 164, 219, 206, 53, 1, 70, 167, 89, 75, 229, 226, 115, 21, 230,
            102, 250, 15, 32, 16, 104, 151, 253, 113, 62, 183, 11, 85,
        ]
    );
}

#[test]
fn environment_values_are_arbitrary_bytes() {
    let mut bytes = aterm(&format!("(\"out\",\"{PATH}\",\"\",\"\")"), "");
    let insertion = bytes.len() - 2;
    bytes.splice(insertion..insertion, b"(\"raw\",\"\xff\")".iter().copied());

    let derivation = Derivation::from_aterm_bytes(&bytes, "example").unwrap();
    assert_eq!(derivation.environment().get("raw").unwrap(), &vec![0xff]);
    assert_eq!(derivation.to_aterm_bytes(), bytes);
}

#[test]
fn every_byte_value_survives_canonical_escaping() {
    let mut derivation = Derivation::from_aterm_bytes(
        &aterm(&format!("(\"out\",\"{PATH}\",\"\",\"\")"), ""),
        "example",
    )
    .unwrap();
    let all_bytes: Vec<u8> = (0..=u8::MAX).collect();
    derivation
        .environment
        .insert("all-bytes".to_owned(), all_bytes.clone());

    let encoded = derivation.to_aterm_bytes();
    let reparsed = Derivation::from_aterm_bytes(&encoded, "example").unwrap();
    assert_eq!(reparsed.environment["all-bytes"], all_bytes);
    assert_eq!(reparsed.to_aterm_bytes(), encoded);
}

#[test]
fn writer_matches_nix_field_specific_escape_policy() {
    let input = "/nix/store/00000000000000000000000000000000-input.drv";
    let bytes = format!(
        "Derive([(\"out\",\"{PATH}\",\"\",\"\")],[(\"{input}\",[\"out\"])],[],\"system\",\"builder\",[\"argument\"],[])"
    );
    let mut derivation = Derivation::from_aterm_bytes(bytes.as_bytes(), "example").unwrap();
    let output = derivation.outputs.remove("out").unwrap();
    derivation
        .outputs
        .insert("quote\"output".to_owned(), output);
    derivation
        .input_derivations
        .values_mut()
        .next()
        .unwrap()
        .outputs = BTreeSet::from(["slash\\output".to_owned()]);
    derivation.system = "sys\ntem".to_owned();
    derivation.builder = "builder\\path".to_owned();
    derivation.arguments = vec!["tab\targument".to_owned()];

    let encoded = derivation.to_aterm_bytes();
    let expected = format!(
        "Derive([(\"quote\"output\",\"{PATH}\",\"\",\"\")],[(\"{input}\",[\"slash\\output\"])],[],\"sys\ntem\",\"builder\\\\path\",[\"tab\\targument\"],[])"
    );
    assert_eq!(encoded, expected.as_bytes());
}

#[test]
fn masked_serialization_clears_output_path_and_environment_value() {
    let bytes = aterm(
        &format!("(\"out\",\"{PATH}\",\"\",\"\")"),
        &format!("(\"out\",\"{PATH}\"),(\"z\",\"kept\")"),
    );
    let derivation = Derivation::from_aterm_bytes(&bytes, "example").unwrap();
    let mut masked = Vec::new();
    write::serialize(&derivation, &mut masked, true, Some(&BTreeMap::new())).unwrap();
    assert_eq!(
        masked,
        aterm(
            "(\"out\",\"\",\"\",\"\")",
            "(\"out\",\"\"),(\"z\",\"kept\")"
        )
    );
}

#[test]
fn actual_input_hash_collisions_union_output_names() {
    let input_a = "/nix/store/00000000000000000000000000000000-a.drv";
    let input_b = "/nix/store/00000000000000000000000000000000-b.drv";
    let bytes = format!(
        "Derive([(\"out\",\"{PATH}\",\"\",\"\")],[(\"{input_a}\",[\"dev\"]),(\"{input_b}\",[\"out\"])],[],\"x86_64-linux\",\"/bin/sh\",[],[])"
    );
    let derivation = Derivation::from_aterm_bytes(bytes.as_bytes(), "example").unwrap();
    let hash = [0x12; 32];
    let mut actual = BTreeMap::new();
    actual.insert(hash, BTreeSet::from(["dev".to_owned(), "out".to_owned()]));
    let mut serialized = Vec::new();
    write::serialize(&derivation, &mut serialized, false, Some(&actual)).unwrap();
    assert!(
        String::from_utf8(serialized)
            .unwrap()
            .contains(&format!("(\"{}\",[\"dev\",\"out\"])", "12".repeat(32)))
    );
}

#[test]
fn dynamic_only_roots_do_not_add_empty_actual_inputs() {
    let input_path = "/nix/store/00000000000000000000000000000000-input.drv";
    let bytes = format!(
        "DrvWithVersion(\"xp-dyn-drv\",[(\"out\",\"{PATH}\",\"\",\"\")],[(\"{input_path}\",([],[(\"generated\",[\"out\"])]))],[],\"x86_64-linux\",\"/bin/sh\",[],[(\"out\",\"{PATH}\")])"
    );
    // Keep the expected term explicit: Nix retains the versioned wrapper but
    // serializes no actualInputs entry for a root with no direct outputs.
    let expected = "DrvWithVersion(\"xp-dyn-drv\",[(\"out\",\"\",\"\",\"\")],[],[],\"x86_64-linux\",\"/bin/sh\",[],[(\"out\",\"\")])";
    let derivation = Derivation::from_aterm_bytes(bytes.as_bytes(), "example").unwrap();
    let calls = Cell::new(0);
    let actual = derivation
        .hash_derivation_modulo(true, |_| {
            calls.set(calls.get() + 1);
            [0x42; 32]
        })
        .unwrap();
    assert_eq!(calls.get(), 1, "Nix still resolves the dynamic-only root");
    let expected_hash: [u8; 32] = Sha256::digest(expected.as_bytes()).into();
    assert_eq!(actual, expected_hash);
}

#[test]
fn fallible_hash_resolver_reports_the_input_path() {
    let input = "/nix/store/00000000000000000000000000000000-input.drv";
    let bytes = format!(
        "Derive([(\"out\",\"{PATH}\",\"\",\"\")],[(\"{input}\",[\"out\"])],[],\"x86_64-linux\",\"/bin/sh\",[],[])"
    );
    let derivation = Derivation::from_aterm_bytes(bytes.as_bytes(), "example").unwrap();

    let error = derivation
        .try_hash_derivation_modulo(true, |_| Err("not found"))
        .unwrap_err();
    assert_eq!(
        error,
        crate::HashDerivationError::Resolve {
            path: StorePath::from_absolute_path(input.as_bytes()).unwrap(),
            error: "not found",
        }
    );
}

#[test]
fn structured_attrs_match_nix_shell_shape() {
    let placeholder = store_path::hash_placeholder("out");
    let json = format!(
        r#"{{"array":[1,true,null],"assoc":{{"b":false,"x":"y"}},"bad key":"ignored","message":"it's","token":"prefix-{placeholder}-suffix"}}"#
    );
    let escaped_json = json.replace('"', "\\\"");
    let bytes = aterm(
        &format!("(\"out\",\"{PATH}\",\"\",\"\")"),
        &format!("(\"__json\",\"{escaped_json}\")"),
    );
    let derivation = Derivation::from_aterm_bytes(&bytes, "example").unwrap();
    assert!(!derivation.environment().contains_key("__json"));
    let files = derivation.structured_attrs_files().unwrap().unwrap();
    assert_eq!(
        files.json,
        format!(
            r#"{{"array":[1,true,null],"assoc":{{"b":false,"x":"y"}},"bad key":"ignored","message":"it's","outputs":{{"out":"{PATH}"}},"token":"prefix-{PATH}-suffix"}}"#
        )
        .as_bytes()
    );
    assert_eq!(
        files.shell,
        format!(
            "declare -a array=(1 1 '' )\ndeclare -A assoc=(['b']= ['x']='y' )\ndeclare message='it'\\''s'\ndeclare -A outputs=(['out']='{PATH}' )\ndeclare token='prefix-{PATH}-suffix'\n"
        )
        .as_bytes()
    );

    let scratch: StorePath = "/nix/store/11111111111111111111111111111111-example-scratch"
        .parse()
        .unwrap();
    let scratch_files = derivation
        .structured_attrs_files_with_output_paths(&BTreeMap::from([(
            "out".to_owned(),
            scratch.clone(),
        )]))
        .unwrap()
        .unwrap();
    assert!(
        scratch_files
            .json
            .windows(scratch.to_absolute_path().len())
            .any(|window| window == scratch.to_absolute_path().as_bytes())
    );
    assert!(
        !scratch_files
            .json
            .windows(store_path::hash_placeholder("out").len())
            .any(|window| window == store_path::hash_placeholder("out").as_bytes())
    );
}

#[test]
fn invalid_structured_attrs_are_rejected_during_parsing() {
    for encoded in ["not-json", "[]", r#"{"x":1e400}"#] {
        let escaped = encoded.replace('"', "\\\"");
        let bytes = aterm(
            &format!("(\"out\",\"{PATH}\",\"\",\"\")"),
            &format!("(\"__json\",\"{escaped}\")"),
        );
        assert!(matches!(
            Derivation::from_aterm_bytes(&bytes, "example"),
            Err(Error::StructuredAttrs(_))
        ));
    }
}

#[test]
fn structured_float_formatting_matches_nix_json_dump() {
    let nix_json = r#"{"five":1e-05,"fixed":0.0001,"large":1e+20,"negativeZero":-0.0,"seven":1e-07,"whole":10000000.0}"#;
    let attrs = crate::StructuredAttrs::from_json_bytes(
        br#"{"fixed":0.0001,"large":1e20,"negativeZero":-0.0,"seven":1e-7,"five":1e-5,"whole":1e7}"#,
    )
    .unwrap();
    assert_eq!(attrs.canonical_json(), nix_json.as_bytes());

    let bytes = aterm(
        &format!("(\"out\",\"{PATH}\",\"\",\"\")"),
        &format!("(\"__json\",\"{}\")", nix_json.replace('"', "\\\"")),
    );
    let derivation = Derivation::from_aterm_bytes(&bytes, "example").unwrap();
    assert_eq!(derivation.to_aterm_bytes(), bytes);
}

#[test]
fn rejects_trailing_bytes_and_unknown_or_misplaced_dynamic_syntax() {
    let mut trailing = aterm(&format!("(\"out\",\"{PATH}\",\"\",\"\")"), "");
    trailing.push(b'\n');
    assert!(matches!(
        Derivation::from_aterm_bytes(&trailing, "example"),
        Err(Error::Parse { .. })
    ));
    assert!(matches!(
        Derivation::from_aterm_bytes(
            b"DrvWithVersion(\"future\",[],[],[],\"x\",\"b\",[],[])",
            "x"
        ),
        Err(Error::Parse { .. })
    ));
    let input = "/nix/store/00000000000000000000000000000000-input.drv";
    let traditional_with_dynamic_node =
        format!("Derive([],[(\"{input}\",([\"out\"],[]))],[],\"x\",\"b\",[],[])");
    assert!(matches!(
        Derivation::from_aterm_bytes(traditional_with_dynamic_node.as_bytes(), "x"),
        Err(Error::Parse { .. })
    ));
}

#[test]
fn recursive_dynamic_inputs_match_nix_234_aterm_grammar() {
    let input = "/nix/store/00000000000000000000000000000000-dep2.drv";
    let bytes = format!(
        "DrvWithVersion(\"xp-dyn-drv\",[],[(\"{input}\",([\"cat\",\"dog\"],[(\"cat\",[\"kitten\"]),(\"goose\",([\"gosling\"],[(\"egg\",[\"out\"])]))]))],[],\"wasm-sel4\",\"foo\",[\"bar\",\"baz\"],[(\"BIG_BAD\",\"WOLF\")])"
    );
    let derivation = Derivation::from_aterm_bytes(bytes.as_bytes(), "dyn").unwrap();
    assert_eq!(derivation.to_aterm_bytes(), bytes.as_bytes());

    let node =
        &derivation.input_derivations()[&StorePath::from_absolute_path(input.as_bytes()).unwrap()];
    assert_eq!(
        node.outputs(),
        &BTreeSet::from(["cat".to_owned(), "dog".to_owned()])
    );
    assert!(
        node.dynamic_outputs()["goose"]
            .dynamic_outputs()
            .contains_key("egg")
    );
    assert_eq!(node.max_depth(), 2);
    assert_eq!(node.walk().count(), 4);
    assert!(matches!(
        derivation.validate(),
        Err(Error::InvalidDerivation(_))
    ));
}

#[test]
fn versioned_form_is_downgraded_when_no_dynamic_node_is_needed() {
    let input = "/nix/store/00000000000000000000000000000000-input.drv";
    let versioned =
        format!("DrvWithVersion(\"xp-dyn-drv\",[],[(\"{input}\",[\"out\"])],[],\"x\",\"b\",[],[])");
    let canonical = versioned.replacen("DrvWithVersion(\"xp-dyn-drv\",", "Derive(", 1);
    let derivation = Derivation::from_aterm_bytes(versioned.as_bytes(), "x").unwrap();
    assert_eq!(derivation.to_aterm_bytes(), canonical.as_bytes());
}

#[test]
fn excessive_dynamic_nesting_is_rejected_without_overflowing_the_stack() {
    let input = "/nix/store/00000000000000000000000000000000-input.drv";
    let mut node = "[\"out\"]".to_owned();
    for _ in 0..300 {
        node = format!("([\"out\"],[(\"next\",{node})])");
    }
    let bytes =
        format!("DrvWithVersion(\"xp-dyn-drv\",[],[(\"{input}\",{node})],[],\"x\",\"b\",[],[])");
    assert!(matches!(
        Derivation::from_aterm_bytes(bytes.as_bytes(), "deep"),
        Err(Error::Parse { .. })
    ));
}

#[test]
fn deepest_supported_dynamic_input_round_trips_and_walks() {
    let input = "/nix/store/00000000000000000000000000000000-input.drv";
    let mut node = "[\"out\"]".to_owned();
    for level in 0..256 {
        node = format!("([\"out\"],[(\"level-{level:03}\",{node})])");
    }
    let bytes = format!(
        "DrvWithVersion(\"xp-dyn-drv\",[(\"out\",\"\",\"r:sha256\",\"\")],[(\"{input}\",{node})],[],\"x86_64-linux\",\"/bin/sh\",[],[])"
    );

    let derivation = Derivation::from_aterm_bytes(bytes.as_bytes(), "deep").unwrap();
    derivation.validate().unwrap();
    assert_eq!(derivation.to_aterm_bytes(), bytes.as_bytes());

    let input = derivation.input_derivations().values().next().unwrap();
    assert_eq!(input.max_depth(), 256);
    assert_eq!(input.walk().count(), 257);
    let deepest = input.walk().last().unwrap();
    assert_eq!(deepest.depth(), 256);
    assert_eq!(deepest.dynamic_output(), Some("level-000"));
    assert_eq!(
        deepest.input().outputs(),
        &BTreeSet::from(["out".to_owned()])
    );
}

#[test]
fn parser_matches_nix_duplicate_insertion_semantics() {
    let path_a = PATH;
    let path_b = "/nix/store/11111111111111111111111111111111-second";
    let input = "/nix/store/00000000000000000000000000000000-input.drv";
    let bytes = format!(
        "Derive([(\"out\",\"{path_a}\",\"\",\"\"),(\"out\",\"{path_b}\",\"\",\"\")],[(\"{input}\",[\"dev\"]),(\"{input}\",[\"out\",\"out\"])],[\"{path_a}\",\"{path_a}\"],\"x\",\"b\",[],[(\"k\",\"first\"),(\"k\",\"last\")])"
    );
    let derivation = Derivation::from_aterm_bytes(bytes.as_bytes(), "x").unwrap();
    assert_eq!(
        derivation.outputs()["out"],
        Output::InputAddressed {
            path: StorePath::from_absolute_path(path_a.as_bytes()).unwrap()
        }
    );
    assert_eq!(
        derivation.input_derivations()[&StorePath::from_absolute_path(input.as_bytes()).unwrap()]
            .outputs(),
        &BTreeSet::from(["out".to_owned()])
    );
    assert_eq!(derivation.environment["k"], b"last");
    assert_eq!(derivation.input_sources.len(), 1);
}

#[test]
fn structured_attrs_are_canonicalized_like_nix_json_dump() {
    let json = r#" { "z" : 1, "a" : { "y" : true, "b" : null } } "#;
    let bytes = aterm(
        &format!("(\"out\",\"{PATH}\",\"\",\"\")"),
        &format!("(\"__json\",\"{}\")", json.replace('"', "\\\"")),
    );
    let derivation = Derivation::from_aterm_bytes(&bytes, "example").unwrap();
    let encoded = String::from_utf8(derivation.to_aterm_bytes()).unwrap();
    assert!(encoded.contains(r#"("__json","{\"a\":{\"b\":null,\"y\":true},\"z\":1}")"#));
}

#[test]
fn structured_attrs_remain_sorted_between_environment_entries() {
    let bytes = aterm(
        &format!("(\"out\",\"{PATH}\",\"\",\"\")"),
        r#"("z","last"),("__json","{\"b\":1,\"a\":2}"),("A","first")"#,
    );
    let derivation = Derivation::from_aterm_bytes(&bytes, "example").unwrap();
    let cloned_before_canonicalization = derivation.clone();
    let encoded = String::from_utf8(derivation.to_aterm_bytes()).unwrap();
    let first = encoded.find(r#"("A","first")"#).unwrap();
    let structured = encoded.find(r#"("__json","{\"a\":2,\"b\":1}")"#).unwrap();
    let last = encoded.find(r#"("z","last")"#).unwrap();
    assert!(first < structured && structured < last);
    assert_eq!(derivation, cloned_before_canonicalization);
}

#[test]
fn validation_rejects_invalid_output_type_combinations() {
    let cases = [
        "Derive([],[],[],\"x\",\"b\",[],[])".to_owned(),
        format!(
            "Derive([(\"a\",\"{PATH}\",\"\",\"\"),(\"b\",\"\",\"\",\"\")],[],[],\"x\",\"b\",[],[])"
        ),
        "Derive([(\"a\",\"\",\"sha1\",\"\"),(\"b\",\"\",\"sha256\",\"\")],[],[],\"x\",\"b\",[],[])"
            .to_owned(),
    ];
    for bytes in cases {
        let derivation = Derivation::from_aterm_bytes(bytes.as_bytes(), "invalid").unwrap();
        assert!(matches!(
            derivation.validate(),
            Err(Error::InvalidDerivation(_))
        ));
        assert!(
            derivation
                .hash_derivation_modulo(false, |_| [0; 32])
                .is_err()
        );
    }
}

#[test]
fn validation_checks_nix_derived_output_paths_and_environment() {
    const EXPECTED: &str = "/nix/store/akkdxfxcn3zapi7a93n60nxk499zylgv-example";
    let valid = aterm(
        &format!("(\"out\",\"{EXPECTED}\",\"\",\"\")"),
        &format!("(\"out\",\"{EXPECTED}\")"),
    );
    Derivation::from_aterm_bytes(&valid, "example")
        .unwrap()
        .validate()
        .unwrap();

    let wrong_path = aterm(
        &format!("(\"out\",\"{PATH}\",\"\",\"\")"),
        &format!("(\"out\",\"{PATH}\")"),
    );
    assert!(matches!(
        Derivation::from_aterm_bytes(&wrong_path, "example")
            .unwrap()
            .validate(),
        Err(Error::InvalidDerivation(_))
    ));

    let missing_environment = aterm(&format!("(\"out\",\"{EXPECTED}\",\"\",\"\")"), "");
    assert!(matches!(
        Derivation::from_aterm_bytes(&missing_environment, "example")
            .unwrap()
            .validate(),
        Err(Error::InvalidDerivation(_))
    ));

    let input_path = "/nix/store/00000000000000000000000000000000-input.drv";
    let draft = format!(
        "Derive([(\"out\",\"{PATH}\",\"\",\"\")],[(\"{input_path}\",[\"out\"])],[],\"x86_64-linux\",\"/bin/sh\",[\"-c\"],[(\"out\",\"{PATH}\")])"
    );
    let draft = Derivation::from_aterm_bytes(draft.as_bytes(), "with-input").unwrap();
    let input_hash = [0x42; 32];
    let modulo = draft.hash_derivation_modulo(true, |_| input_hash).unwrap();
    let expected = store_path::build_output_path(&modulo, "out", "with-input").unwrap();
    let expected = expected.to_absolute_path();
    let valid_with_input = format!(
        "Derive([(\"out\",\"{expected}\",\"\",\"\")],[(\"{input_path}\",[\"out\"])],[],\"x86_64-linux\",\"/bin/sh\",[\"-c\"],[(\"out\",\"{expected}\")])"
    );
    let valid_with_input =
        Derivation::from_aterm_bytes(valid_with_input.as_bytes(), "with-input").unwrap();
    assert!(valid_with_input.validate().is_err());
    valid_with_input
        .validate_with_input_hashes(|_| input_hash)
        .unwrap();
}

#[test]
fn every_truncated_prefix_is_rejected_without_panicking() {
    let bytes = aterm(
        &format!("(\"out\",\"{PATH}\",\"\",\"\")"),
        "(\"escaped\",\"quote: \\\" slash: \\\\ newline: \\n\")",
    );
    for end in 0..bytes.len() {
        assert!(
            Derivation::from_aterm_bytes(&bytes[..end], "example").is_err(),
            "prefix of length {end} unexpectedly parsed"
        );
    }
    Derivation::from_aterm_bytes(&bytes, "example").unwrap();
}

#[test]
fn arbitrary_bounded_inputs_never_panic() {
    let mut state = 0x78d4_2f9a_13c6_b5e1_u64;
    for case in 0..10_000 {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        let len = (state as usize) % 1_024;
        let mut bytes = vec![0; len];
        for byte in &mut bytes {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            *byte = (state >> 32) as u8;
        }
        let _ = Derivation::from_aterm_bytes(&bytes, &format!("fuzz-{case}"));
    }
}
