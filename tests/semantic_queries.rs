use std::collections::BTreeSet;

use nix_derivation::store_path;
use nix_derivation::{
    CAHash, ContentAddressMethod, DerivationBuilder, DynamicInputResolution,
    DynamicOutputReplacement, Error, HashAlgorithm, InputDerivation, Output, StoreDir, StorePath,
    StructuredAttrs,
};

const BASE_DRV: &str = "/nix/store/11111111111111111111111111111111-base.drv";
const GENERATED_DRV: &str = "/nix/store/22222222222222222222222222222222-generated.drv";
const LEAF_PATH: &str = "/nix/store/33333333333333333333333333333333-leaf";
const OTHER_PATH: &str = "/nix/store/44444444444444444444444444444444-other";

fn ordinary(name: &str) -> nix_derivation::ValidatedDerivation {
    DerivationBuilder::new(name, "x86_64-linux", "/bin/sh")
        .input_addressed_output("out")
        .build()
        .unwrap()
}

#[test]
fn semantic_dynamic_derivation_detection_covers_all_nix_forms() {
    assert!(!ordinary("ordinary").uses_dynamic_derivations());

    let nested = InputDerivation::new(Vec::<String>::new())
        .with_dynamic_output("generated", InputDerivation::new(["out"]))
        .unwrap();
    let recursive = DerivationBuilder::new("recursive", "x86_64-linux", "/bin/sh")
        .output("out", Output::Deferred)
        .input_derivation(BASE_DRV.parse().unwrap(), nested)
        .build()
        .unwrap();
    assert!(recursive.uses_dynamic_derivations());

    let floating_text = DerivationBuilder::new("floating.drv", "x86_64-linux", "/bin/sh")
        .output(
            "out",
            Output::Floating {
                method: ContentAddressMethod::Text,
                hash_algorithm: HashAlgorithm::Sha256,
            },
        )
        .build()
        .unwrap();
    assert!(floating_text.uses_dynamic_derivations());

    let legacy_text = DerivationBuilder::new("legacy.drv", "x86_64-linux", "/bin/sh")
        .output(
            "out",
            Output::Fixed {
                ca: CAHash::Text([7; 32]),
            },
        )
        .build()
        .unwrap();
    assert!(
        legacy_text.resolved_outputs()["out"]
            .path
            .as_ref()
            .unwrap()
            .is_derivation()
    );
    assert!(legacy_text.uses_dynamic_derivations());

    let plain_text = DerivationBuilder::new("plain-text", "x86_64-linux", "/bin/sh")
        .output(
            "out",
            Output::Fixed {
                ca: CAHash::Text([8; 32]),
            },
        )
        .build()
        .unwrap();
    assert!(!plain_text.uses_dynamic_derivations());
}

#[test]
fn required_system_features_merge_deduplicate_and_ignore_non_strings() {
    let structured = StructuredAttrs::from_json_bytes(
        br#"{"requiredSystemFeatures":["builder-rpc-v0","kvm",false,3,null,"kvm"]}"#,
    )
    .unwrap();
    let derivation = DerivationBuilder::new("features", "x86_64-linux", "/bin/sh")
        .input_addressed_output("out")
        .environment(
            "requiredSystemFeatures",
            b"kvm\tbig-parallel\nrecursive-nix\rkvm",
        )
        .structured_attrs(structured)
        .build()
        .unwrap();

    assert_eq!(
        derivation.required_system_features(),
        BTreeSet::from([
            "big-parallel".to_owned(),
            "builder-rpc-v0".to_owned(),
            "kvm".to_owned(),
            "recursive-nix".to_owned(),
        ])
    );

    assert!(
        ordinary("missing-features")
            .required_system_features()
            .is_empty()
    );
    let non_array = DerivationBuilder::new("non-array", "x86_64-linux", "/bin/sh")
        .input_addressed_output("out")
        .structured_attrs(
            StructuredAttrs::from_json_bytes(br#"{"requiredSystemFeatures":"kvm"}"#).unwrap(),
        )
        .build()
        .unwrap();
    assert!(non_array.required_system_features().is_empty());
    assert!(StructuredAttrs::from_json_bytes(br#"{"requiredSystemFeatures":["kvm",}"#).is_err());
}

fn dynamic_consumer(
    arguments: impl IntoIterator<Item = String>,
    environment: impl Into<Vec<u8>>,
    structured_attrs: Option<StructuredAttrs>,
) -> nix_derivation::ValidatedDerivation {
    let input = InputDerivation::new(["direct"])
        .with_dynamic_output(
            "generated",
            InputDerivation::new(["out"])
                .with_dynamic_output("nested", InputDerivation::new(["out"]))
                .unwrap(),
        )
        .unwrap();
    let mut builder = DerivationBuilder::new("consumer", "x86_64-linux", "/bin/sh")
        .output("out", Output::Deferred)
        .input_derivation(BASE_DRV.parse().unwrap(), input)
        .environment("binary", environment);
    for argument in arguments {
        builder = builder.argument(argument);
    }
    if let Some(attrs) = structured_attrs {
        builder = builder.structured_attrs(attrs);
    }
    builder.build().unwrap()
}

#[test]
fn dynamic_input_resolution_rewrites_single_and_recursive_chains() {
    let base: StorePath = BASE_DRV.parse().unwrap();
    let generated: StorePath = GENERATED_DRV.parse().unwrap();
    let leaf: StorePath = LEAF_PATH.parse().unwrap();
    let direct_placeholder = store_path::downstream_placeholder(&base, ["direct"]).unwrap();
    let generated_placeholder = store_path::downstream_placeholder(&base, ["generated"]).unwrap();
    let leaf_placeholder = store_path::downstream_placeholder(&base, ["generated", "out"]).unwrap();
    let nested_placeholder =
        store_path::downstream_placeholder(&base, ["generated", "nested", "out"]).unwrap();
    let json = serde_json::to_vec(&serde_json::json!({
        generated_placeholder.clone(): {
            "leaf": leaf_placeholder,
            "nested": nested_placeholder,
        }
    }))
    .unwrap();
    let mut binary = vec![0xff, 0x00];
    binary.extend_from_slice(direct_placeholder.as_bytes());
    binary.push(0xfe);
    let consumer = dynamic_consumer(
        [
            format!("direct={direct_placeholder}"),
            format!("generated={generated_placeholder}"),
            format!("leaf={leaf_placeholder}"),
        ],
        binary,
        Some(StructuredAttrs::from_json_bytes(json).unwrap()),
    );
    let mut consumer_builder = consumer.into_builder();
    *consumer_builder.builder_mut() = format!("{direct_placeholder}/bin/builder");
    consumer_builder.environment_mut().insert(
        format!("dynamic-{direct_placeholder}"),
        generated_placeholder.as_bytes().to_vec(),
    );
    let consumer = consumer_builder.build().unwrap();

    let resolved = consumer
        .resolve_dynamic_inputs(DynamicInputResolution {
            replacements: vec![
                DynamicOutputReplacement {
                    base_derivation: base.clone(),
                    output_chain: vec!["direct".to_owned()],
                    realised_path: leaf.clone(),
                },
                DynamicOutputReplacement {
                    base_derivation: base.clone(),
                    output_chain: vec!["generated".to_owned()],
                    realised_path: generated.clone(),
                },
                DynamicOutputReplacement {
                    base_derivation: base.clone(),
                    output_chain: vec!["generated".to_owned(), "out".to_owned()],
                    realised_path: leaf.clone(),
                },
                DynamicOutputReplacement {
                    base_derivation: base,
                    output_chain: vec![
                        "generated".to_owned(),
                        "nested".to_owned(),
                        "out".to_owned(),
                    ],
                    realised_path: OTHER_PATH.parse().unwrap(),
                },
            ],
            input_sources: BTreeSet::from([leaf.clone(), OTHER_PATH.parse().unwrap()]),
        })
        .unwrap();

    assert!(resolved.input_derivations().is_empty());
    assert_eq!(
        resolved.input_sources(),
        &BTreeSet::from([leaf.clone(), OTHER_PATH.parse().unwrap()])
    );
    assert!(!resolved.input_sources().contains(&generated));
    assert_eq!(
        resolved.arguments(),
        [
            format!("direct={LEAF_PATH}"),
            format!("generated={GENERATED_DRV}"),
            format!("leaf={LEAF_PATH}"),
        ]
    );
    assert_eq!(resolved.builder(), format!("{LEAF_PATH}/bin/builder"));
    assert_eq!(
        resolved.environment()[&format!("dynamic-{LEAF_PATH}")],
        GENERATED_DRV.as_bytes()
    );
    let binary = &resolved.environment()["binary"];
    assert_eq!(&binary[..2], &[0xff, 0x00]);
    assert_eq!(&binary[2..binary.len() - 1], LEAF_PATH.as_bytes());
    assert_eq!(binary.last(), Some(&0xfe));
    let attrs = resolved.structured_attrs().unwrap();
    assert_eq!(
        attrs.get(GENERATED_DRV).unwrap()["leaf"],
        serde_json::Value::String(LEAF_PATH.to_owned())
    );
    assert_eq!(
        attrs.get(GENERATED_DRV).unwrap()["nested"],
        serde_json::Value::String(OTHER_PATH.to_owned())
    );
    assert!(
        !resolved
            .to_aterm_bytes()
            .windows(b"xp-dyn-drv".len())
            .any(|window| window == b"xp-dyn-drv")
    );
}

#[test]
fn dynamic_input_resolution_rejects_empty_and_conflicting_replacements() {
    let base: StorePath = BASE_DRV.parse().unwrap();
    let consumer = dynamic_consumer(Vec::<String>::new(), Vec::new(), None);
    let empty = consumer
        .clone()
        .resolve_dynamic_inputs(DynamicInputResolution {
            replacements: vec![DynamicOutputReplacement {
                base_derivation: base.clone(),
                output_chain: Vec::new(),
                realised_path: LEAF_PATH.parse().unwrap(),
            }],
            input_sources: BTreeSet::new(),
        });
    assert!(matches!(empty, Err(Error::InvalidStorePath(_))));

    let conflict = consumer.resolve_dynamic_inputs(DynamicInputResolution {
        replacements: vec![
            DynamicOutputReplacement {
                base_derivation: base.clone(),
                output_chain: vec!["direct".to_owned()],
                realised_path: LEAF_PATH.parse().unwrap(),
            },
            DynamicOutputReplacement {
                base_derivation: base,
                output_chain: vec!["direct".to_owned()],
                realised_path: OTHER_PATH.parse().unwrap(),
            },
        ],
        input_sources: BTreeSet::new(),
    });
    assert!(
        matches!(conflict, Err(Error::InvalidDerivation(message)) if message.contains("conflicting"))
    );
}

#[test]
fn dynamic_input_resolution_matches_nix_try_resolve_fixture() {
    // Generated by Nix 2.34.7 from fixtures/try-resolve.nix. Building the
    // dynamic consumer stores Nix's resolved basic derivation as a second
    // `.drv`; this compares our pure rewrite with those exact ATerm bytes.
    let input = include_str!("fixtures/try-resolve-input.aterm").trim_end();
    let expected = include_str!("fixtures/try-resolve-output.aterm").trim_end();
    let base_derivation: StorePath =
        "/nix/store/7yywx533ki5ax36vs6xrgjqvh9w4bk72-try-resolve-generated.drv.drv"
            .parse()
            .unwrap();
    let realised_path: StorePath =
        "/nix/store/rlfrx4f4h10kajkh27vxp99d9xfcl4lx-try-resolve-generated"
            .parse()
            .unwrap();
    let derivation = nix_derivation::ValidatedDerivation::from_aterm_bytes(
        input.as_bytes(),
        "try-resolve-consumer",
    )
    .unwrap();

    let resolved = derivation
        .resolve_dynamic_inputs(DynamicInputResolution {
            replacements: vec![DynamicOutputReplacement {
                base_derivation,
                output_chain: vec!["out".to_owned(), "out".to_owned()],
                realised_path: realised_path.clone(),
            }],
            input_sources: BTreeSet::from([realised_path]),
        })
        .unwrap();

    assert_eq!(resolved.to_aterm_bytes(), expected.as_bytes());
}

fn with_export_graph(
    store_dir: StoreDir,
    value: impl Into<Vec<u8>>,
) -> nix_derivation::ValidatedDerivation {
    DerivationBuilder::new_in_store(store_dir, "erg", "x86_64-linux", "/bin/sh")
        .input_addressed_output("out")
        .environment("exportReferencesGraph", value)
        .build()
        .unwrap()
}

#[test]
fn export_references_graph_parses_nix_tokenization_and_ordering() {
    assert!(
        ordinary("no-erg")
            .export_references_graph()
            .unwrap()
            .is_empty()
    );
    assert!(
        with_export_graph(StoreDir::default(), b"")
            .export_references_graph()
            .unwrap()
            .is_empty()
    );

    let first = "/nix/store/55555555555555555555555555555555-first";
    let second = "/nix/store/66666666666666666666666666666666-second";
    let graph = with_export_graph(
        StoreDir::default(),
        format!("first.json\t{first}\n_second-file\r{second}"),
    )
    .export_references_graph()
    .unwrap();
    assert_eq!(graph.len(), 2);
    assert_eq!(graph[0].file_name, "first.json");
    assert_eq!(graph[0].root, first.parse().unwrap());
    assert_eq!(graph[1].file_name, "_second-file");
    assert_eq!(graph[1].root, second.parse().unwrap());
}

#[test]
fn export_references_graph_rejects_invalid_options() {
    let root = "/nix/store/55555555555555555555555555555555-root";
    assert!(
        with_export_graph(StoreDir::default(), b"name")
            .export_references_graph()
            .is_err()
    );
    for file_name in ["/", ".hidden", "unicodé", "bad$name", "has/slash"] {
        let result = with_export_graph(StoreDir::default(), format!("{file_name} {root}"))
            .export_references_graph();
        assert!(result.is_err(), "accepted invalid file name {file_name:?}");
    }
    assert!(matches!(
        with_export_graph(StoreDir::default(), vec![b'n', b' ', 0xff]).export_references_graph(),
        Err(Error::InvalidUtf8 {
            field: "exportReferencesGraph"
        })
    ));
}

#[test]
fn export_references_graph_uses_the_logical_store_directory() {
    let store_dir = StoreDir::new("/gnu/store").unwrap();
    let root = "/gnu/store/77777777777777777777777777777777-root";
    let expected = store_dir.parse_path(root.as_bytes()).unwrap();
    let graph = with_export_graph(store_dir, format!("graph {root}"))
        .export_references_graph()
        .unwrap();
    assert_eq!(graph[0].root, expected);
}
