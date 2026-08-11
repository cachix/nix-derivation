use nix_derivation::{
    Derivation, DerivationBuilder, StoreDir, StructuredAttrs, ValidatedDerivation,
};

const NAME: &str = "anthy-9100h.tar.gz";
const DRV_PATH: &str = "/gnu/store/cxn846g7ksak21wbq4hgnhiyq5x2wkh7-anthy-9100h.tar.gz.drv";
const OUTPUT_PATH: &str = "/gnu/store/s669awkxfshsnz6cnz3bg0pqbdz3lxj2-anthy-9100h.tar.gz";

fn fixture() -> &'static [u8] {
    let bytes = include_bytes!("fixtures/guix-anthy-9100h.tar.gz.drv");
    bytes.strip_suffix(b"\n").unwrap_or(bytes)
}

#[test]
fn guix_derivation_matches_real_store_paths_and_round_trips() {
    // Captured from the Guix Data Service:
    // https://data.guix.gnu.org/gnu/store/cxn846g7ksak21wbq4hgnhiyq5x2wkh7-anthy-9100h.tar.gz.drv/plain
    let store_dir = StoreDir::new("/gnu/store").unwrap();
    let derivation = Derivation::from_aterm_bytes_in(fixture(), NAME, store_dir.clone()).unwrap();

    assert_eq!(derivation.store_dir(), &store_dir);
    assert_eq!(derivation.to_aterm_bytes(), fixture());
    assert_eq!(
        derivation
            .drv_path()
            .unwrap()
            .to_absolute_path_in(&store_dir),
        DRV_PATH
    );
    assert_eq!(
        derivation.resolved_outputs().unwrap()["out"]
            .path
            .as_ref()
            .unwrap()
            .to_absolute_path_in(&store_dir),
        OUTPUT_PATH
    );
    assert_eq!(derivation.input_sources().len(), 3);
    assert!(derivation.input_sources().iter().all(|path| {
        path.to_absolute_path_in(&store_dir)
            .starts_with("/gnu/store/")
    }));
    derivation.validate().unwrap();
}

#[test]
fn guix_derivation_is_rejected_by_the_default_store_parser() {
    assert!(Derivation::from_aterm_bytes(fixture(), NAME).is_err());
}

#[test]
fn custom_store_round_trip_covers_every_aterm_path_position() {
    let store_dir = StoreDir::new("/gnu/store").unwrap();
    let output = "/gnu/store/00000000000000000000000000000000-parent";
    let input_drv = "/gnu/store/11111111111111111111111111111111-input.drv";
    let input_source = "/gnu/store/22222222222222222222222222222222-source";
    let bytes = format!(
        "Derive([(\"out\",\"{output}\",\"\",\"\")],[(\"{input_drv}\",[\"out\"])],[\"{input_source}\"],\"x86_64-linux\",\"/bin/sh\",[],[(\"out\",\"{output}\")])"
    );

    let derivation =
        Derivation::from_aterm_bytes_in(bytes.as_bytes(), "parent", store_dir.clone()).unwrap();

    assert_eq!(derivation.to_aterm_bytes(), bytes.as_bytes());
    assert_eq!(derivation.input_derivations().len(), 1);
    assert_eq!(derivation.input_sources().len(), 1);
    assert!(Derivation::from_aterm_bytes(bytes.as_bytes(), "parent").is_err());
}

#[test]
fn structured_attrs_use_custom_store_paths_for_outputs_and_placeholders() {
    const OUT_PLACEHOLDER: &str = "/1rz4g4znpzjwh1xymhjpm42vipw92pr73vdgl6xs1hycac8kf2n9";

    let store_dir = StoreDir::new("/gnu/store").unwrap();
    let attrs = StructuredAttrs::from_json_bytes(
        format!(r#"{{"message":"prefix-{OUT_PLACEHOLDER}-suffix"}}"#).into_bytes(),
    )
    .unwrap();
    let derivation =
        DerivationBuilder::new_in_store(store_dir.clone(), "structured", "x86_64-linux", "/bin/sh")
            .input_addressed_output("out")
            .structured_attrs(attrs)
            .build()
            .unwrap();
    let output = derivation.resolved_outputs()["out"]
        .path
        .as_ref()
        .unwrap()
        .to_absolute_path_in(&store_dir);

    let files = derivation.structured_attrs_files().unwrap().unwrap();
    let json: serde_json::Value = serde_json::from_slice(&files.json).unwrap();
    assert_eq!(json["outputs"]["out"], output);
    assert_eq!(json["message"], format!("prefix-{output}-suffix"));
    assert!(
        files
            .shell
            .windows(output.len())
            .any(|part| part == output.as_bytes())
    );
    assert!(
        !files
            .json
            .windows(b"/nix/store".len())
            .any(|part| part == b"/nix/store")
    );
    assert!(
        !files
            .shell
            .windows(b"/nix/store".len())
            .any(|part| part == b"/nix/store")
    );
}

#[test]
fn aterm_escapes_store_directory_characters() {
    let store_dir = StoreDir::new("/tmp/quoted\"and\\slashed\nstore\tname").unwrap();
    let derivation = DerivationBuilder::new_in_store(
        store_dir.clone(),
        "escaped-store",
        "x86_64-linux",
        "/bin/sh",
    )
    .input_addressed_output("out")
    .build()
    .unwrap();
    let bytes = derivation.to_aterm_bytes();

    assert!(
        bytes
            .windows(b"quoted\\\"and\\\\slashed\\nstore\\tname".len())
            .any(|part| part == b"quoted\\\"and\\\\slashed\\nstore\\tname")
    );
    let reparsed =
        ValidatedDerivation::from_aterm_bytes_in(&bytes, derivation.name(), store_dir).unwrap();
    assert_eq!(reparsed, derivation);
}

#[test]
fn root_store_aterm_round_trips_without_a_double_slash() {
    let store_dir = StoreDir::new("/").unwrap();
    let derivation =
        DerivationBuilder::new_in_store(store_dir.clone(), "root-store", "x86_64-linux", "/bin/sh")
            .input_addressed_output("out")
            .build()
            .unwrap();
    let output = derivation.resolved_outputs()["out"]
        .path
        .as_ref()
        .unwrap()
        .to_absolute_path_in(&store_dir);
    let bytes = derivation.to_aterm_bytes();

    assert!(output.starts_with('/'));
    assert!(!output.starts_with("//"));
    assert!(
        bytes
            .windows(output.len())
            .any(|part| part == output.as_bytes())
    );
    let reparsed =
        ValidatedDerivation::from_aterm_bytes_in(&bytes, derivation.name(), store_dir).unwrap();
    assert_eq!(reparsed, derivation);
}
