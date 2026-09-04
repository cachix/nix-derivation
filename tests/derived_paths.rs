use nix_derivation::{
    DerivedPath, DrvOutput, DrvOutputParseError, SingleDerivedPath, StoreDir, StorePath,
};

const BASE: &str = "00000000000000000000000000000000-producer.drv";

fn path() -> StorePath {
    StorePath::from_basename(BASE.as_bytes()).unwrap()
}

#[test]
fn derivation_output_ids_support_basename_and_store_aware_forms() {
    let id: DrvOutput = format!("{BASE}^out").parse().unwrap();
    assert_eq!(id, DrvOutput::new(path(), "out"));
    assert_eq!(id.to_string(), format!("{BASE}^out"));

    let store = StoreDir::new("/gnu/store").unwrap();
    let id = DrvOutput::parse_in(&store, &format!("/gnu/store/{BASE}^dev")).unwrap();
    assert_eq!(id, DrvOutput::new(path(), "dev"));
    assert_eq!(id.render(&store), format!("/gnu/store/{BASE}^dev"));

    assert_eq!(
        DrvOutput::parse("not-an-id"),
        Err(DrvOutputParseError::MissingSeparator)
    );
    assert!(matches!(
        DrvOutput::parse_in(&store, &format!("/nix/store/{BASE}^out")),
        Err(DrvOutputParseError::InvalidDerivationPath { .. })
    ));
}

#[test]
fn single_derived_paths_preserve_dynamic_chains() {
    let store = StoreDir::new("/gnu/store").unwrap();
    let parsed =
        SingleDerivedPath::parse_in(&store, &format!("/gnu/store/{BASE}^generated^out")).unwrap();
    let (base, outputs) = parsed.components();

    assert_eq!(base, &path());
    assert_eq!(outputs, ["generated", "out"]);
    assert_eq!(
        parsed.render(&store),
        format!("/gnu/store/{BASE}^generated^out")
    );
    assert_eq!(
        parsed.render_legacy(&store),
        format!("/gnu/store/{BASE}!generated!out")
    );
}

#[test]
fn transport_form_parses_without_owning_store_policy() {
    let parsed: SingleDerivedPath<String> =
        SingleDerivedPath::<String>::parse("remote/store/path^generated^out");
    assert_eq!(parsed.components().0, "remote/store/path");
    assert_eq!(parsed.components().1, ["generated", "out"]);
    assert_eq!(parsed.to_string(), "remote/store/path^generated^out");
}

#[test]
fn multi_derived_paths_parse_outputs_specs() {
    let store = StoreDir::default();
    let named =
        DerivedPath::parse_in(&store, &format!("/nix/store/{BASE}^generated^dev,out,dev")).unwrap();
    assert_eq!(
        named,
        DerivedPath::Built {
            drv_path: SingleDerivedPath::Built {
                drv_path: Box::new(SingleDerivedPath::Opaque(path())),
                output: "generated".to_owned(),
            },
            outputs: vec!["dev".to_owned(), "out".to_owned()],
        }
    );
    assert_eq!(
        named.render(&store),
        format!("/nix/store/{BASE}^generated^dev,out")
    );
    assert_eq!(
        named.to_string(),
        format!("/nix/store/{BASE}^generated^dev,out")
    );

    let all = DerivedPath::parse_in(&store, &format!("/nix/store/{BASE}^*")).unwrap();
    assert!(matches!(
        all,
        DerivedPath::Built { outputs, .. } if outputs.is_empty()
    ));
}

#[test]
fn opaque_and_invalid_paths_are_distinguished() {
    let store = StoreDir::default();
    assert_eq!(
        DerivedPath::parse_in(&store, &format!("/nix/store/{BASE}")).unwrap(),
        DerivedPath::Opaque(path())
    );
    assert!(SingleDerivedPath::parse_in(&store, "not-in-store^out").is_err());
    assert!(DerivedPath::parse_in(&store, &format!("/nix/store/{BASE}^bad output")).is_err());
}

#[test]
fn legacy_forms_parse_and_round_trip() {
    let store = StoreDir::new("/gnu/store").unwrap();
    let single_text = format!("/gnu/store/{BASE}!generated!out");
    let single = SingleDerivedPath::parse_legacy_in(&store, &single_text).unwrap();
    assert_eq!(single.render_legacy(&store), single_text);
    assert_eq!(
        single.render(&store),
        format!("/gnu/store/{BASE}^generated^out")
    );

    let transport = SingleDerivedPath::<String>::parse_legacy("remote/path!generated!out");
    assert_eq!(transport.components().0, "remote/path");
    assert_eq!(transport.components().1, ["generated", "out"]);

    let derived_text = format!("/gnu/store/{BASE}!generated!dev,out");
    let derived = DerivedPath::parse_legacy_in(&store, &derived_text).unwrap();
    assert_eq!(derived.render_legacy(&store), derived_text);
    assert_eq!(
        derived.render(&store),
        format!("/gnu/store/{BASE}^generated^dev,out")
    );
}

#[test]
fn from_str_uses_the_default_store() {
    let single: SingleDerivedPath = format!("/nix/store/{BASE}^out").parse().unwrap();
    assert_eq!(single.base(), &path());
    assert_eq!(single.to_string(), format!("/nix/store/{BASE}^out"));

    let derived: DerivedPath = format!("/nix/store/{BASE}^dev,out").parse().unwrap();
    assert_eq!(derived.base(), &path());
    assert_eq!(derived.to_string(), format!("/nix/store/{BASE}^dev,out"));

    let output: DrvOutput = format!("{BASE}^out").parse().unwrap();
    assert_eq!(output.drv_path(), &path());
    assert_eq!(output.output_name(), "out");
}

#[test]
fn opaque_and_all_output_forms_render_exactly() {
    let store = StoreDir::default();
    let opaque = DerivedPath::Opaque(path());
    assert_eq!(opaque.render(&store), format!("/nix/store/{BASE}"));
    assert_eq!(opaque.render_legacy(&store), format!("/nix/store/{BASE}"));
    assert_eq!(opaque.to_string(), format!("/nix/store/{BASE}"));

    let all = DerivedPath::Built {
        drv_path: SingleDerivedPath::Opaque(path()),
        outputs: Vec::new(),
    };
    assert_eq!(all.render(&store), format!("/nix/store/{BASE}^*"));
    assert_eq!(all.render_legacy(&store), format!("/nix/store/{BASE}!*"));
    assert_eq!(all.to_string(), format!("/nix/store/{BASE}^*"));
}

#[test]
fn derived_paths_round_trip_in_an_alternate_store() {
    let store = StoreDir::new("/gnu/store").unwrap();
    let modern = format!("/gnu/store/{BASE}^generated^dev,out");
    let parsed = DerivedPath::parse_in(&store, &modern).unwrap();
    assert_eq!(parsed.render(&store), modern);
    assert_eq!(
        DerivedPath::parse_in(&store, &parsed.render(&store)).unwrap(),
        parsed
    );

    let legacy = format!("/gnu/store/{BASE}!generated!dev,out");
    assert_eq!(parsed.render_legacy(&store), legacy);
    assert_eq!(
        DerivedPath::parse_legacy_in(&store, &parsed.render_legacy(&store)).unwrap(),
        parsed
    );
    assert!(DerivedPath::parse_in(&StoreDir::default(), &modern).is_err());
}

#[test]
fn malformed_output_specs_are_rejected() {
    let store = StoreDir::default();
    for outputs in ["", ",out", "out,", "out,,dev", "*,out", "bad output"] {
        let value = format!("/nix/store/{BASE}^{outputs}");
        assert!(
            DerivedPath::parse_in(&store, &value).is_err(),
            "accepted malformed outputs spec {outputs:?}"
        );
    }
}

#[test]
fn base_follows_nested_paths() {
    let nested = SingleDerivedPath::Built {
        drv_path: Box::new(SingleDerivedPath::Built {
            drv_path: Box::new(SingleDerivedPath::Opaque(path())),
            output: "generated".to_owned(),
        }),
        output: "out".to_owned(),
    };
    assert_eq!(nested.base(), &path());

    let derived = DerivedPath::Built {
        drv_path: nested,
        outputs: vec!["out".to_owned()],
    };
    assert_eq!(derived.base(), &path());
    assert_eq!(DerivedPath::Opaque(path()).base(), &path());
}

#[test]
fn moderately_deep_dynamic_chains_remain_iterable() {
    let store = StoreDir::default();
    let value = format!("/nix/store/{BASE}{}", "^out".repeat(256));
    let parsed = SingleDerivedPath::parse_in(&store, &value).unwrap();
    let (base, outputs) = parsed.components();
    assert_eq!(base, &path());
    assert_eq!(outputs.len(), 256);
    assert!(outputs.iter().all(|output| *output == "out"));
    assert_eq!(parsed.render(&store), value);
}

#[test]
fn json_matches_nix_derived_path_shapes() {
    let opaque = SingleDerivedPath::Opaque(path());
    assert_eq!(
        serde_json::to_value(&opaque).unwrap(),
        serde_json::json!(BASE)
    );

    let nested = SingleDerivedPath::Built {
        drv_path: Box::new(SingleDerivedPath::Built {
            drv_path: Box::new(opaque),
            output: "generated".to_owned(),
        }),
        output: "out".to_owned(),
    };
    assert_eq!(
        serde_json::to_value(&nested).unwrap(),
        serde_json::json!({
            "drvPath": {
                "drvPath": BASE,
                "output": "generated",
            },
            "output": "out",
        })
    );

    let named = DerivedPath::Built {
        drv_path: nested,
        outputs: vec!["out".to_owned(), "dev".to_owned(), "out".to_owned()],
    };
    assert_eq!(
        serde_json::to_value(&named).unwrap(),
        serde_json::json!({
            "drvPath": {
                "drvPath": {
                    "drvPath": BASE,
                    "output": "generated",
                },
                "output": "out",
            },
            "outputs": ["dev", "out"],
        })
    );

    let all = DerivedPath::Built {
        drv_path: SingleDerivedPath::Opaque(path()),
        outputs: Vec::new(),
    };
    assert_eq!(
        serde_json::to_value(&all).unwrap(),
        serde_json::json!({"drvPath": BASE, "outputs": ["*"]})
    );

    assert_eq!(
        serde_json::to_value(DerivedPath::Opaque(path())).unwrap(),
        serde_json::json!(BASE)
    );

    let transport = SingleDerivedPath::Built {
        drv_path: Box::new(SingleDerivedPath::Opaque("remote/path".to_owned())),
        output: "out".to_owned(),
    };
    assert_eq!(
        serde_json::to_value(transport).unwrap(),
        serde_json::json!({"drvPath": "remote/path", "output": "out"})
    );

    let output = DrvOutput::new(path(), "out");
    assert_eq!(
        serde_json::to_value(&output).unwrap(),
        serde_json::json!({"drvPath": BASE, "outputName": "out"})
    );
    assert_eq!(
        serde_json::to_string(&output).unwrap(),
        format!(r#"{{"drvPath":"{BASE}","outputName":"out"}}"#)
    );
}
