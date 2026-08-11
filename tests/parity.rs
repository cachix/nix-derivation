//! The differential harness.
//!
//! Every assertion here is self-oracling. A `.drv` file's store path is the
//! text hash of its own bytes, and the file records the store paths of its own
//! outputs. So Nix's answers are already inside the corpus, and no test needs
//! to shell out to compare hashes.
//!
//! These tests are not circular: Nix generates identity-bearing inputs, while
//! an independent pure Rust implementation must reproduce the embedded paths
//! and bytes — including output masking, actual-input substitution,
//! store-path fingerprints, and nixbase32.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use nix_derivation::nixbase32;
use nix_derivation::store_path::{self, StorePath};
use nix_derivation::{Derivation, DerivationModuloHash, InputDerivationHash};

#[path = "support/differential_corpus.rs"]
mod corpus;

fn corpus_or_skip() -> Option<Vec<PathBuf>> {
    match corpus::drvs() {
        Some(d) => Some(d),
        None => {
            eprintln!("skipping: nix-instantiate not on PATH");
            None
        }
    }
}

fn parse(path: &Path) -> Derivation {
    let bytes = corpus::read_drv(path);
    Derivation::from_aterm_bytes(&bytes, &corpus::drv_name(path))
        .unwrap_or_else(|e| panic!("parsing {} failed: {e}", path.display()))
}

/// Reserializing a parsed derivation must reproduce the exact bytes.
///
/// This is not a stylistic nicety. The derivation's store path is the text hash
/// of these bytes. A store that reserializes derivations on read relies on a
/// single byte of drift not making the path stop addressing its own contents.
#[test]
fn aterm_round_trip_is_byte_exact() {
    let Some(drvs) = corpus_or_skip() else { return };

    for path in &drvs {
        let original = corpus::read_drv(path);
        let reserialized = parse(path).to_aterm_bytes();
        assert_eq!(
            reserialized,
            original,
            "round trip lost bytes for {}",
            path.display()
        );
    }
}

/// Every derivation emitted by Nix also satisfies the package's explicit
/// semantic validator. Parsing remains separate so diagnostic/characterization
/// ATerms can still be inspected and round-tripped.
#[test]
fn nix_generated_corpus_is_semantically_valid() {
    let Some(drvs) = corpus_or_skip() else { return };
    let mut cache = HashMap::new();

    for path in &drvs {
        fill_input_modulo(path, &mut cache);
        parse(path)
            .validate_with_input_hashes(|input| {
                cache
                    .get(&PathBuf::from(input.to_absolute_path()))
                    .expect("input derivation resolved before validation")
                    .to_owned()
            })
            .unwrap_or_else(|error| panic!("{} is invalid: {error}", path.display()));
    }
}

/// A `.drv`'s own store path is `build_text_path` over its bytes, with its
/// input derivations and input sources as references.
#[test]
fn drv_path_is_text_hash_of_its_own_bytes() {
    let Some(drvs) = corpus_or_skip() else { return };

    for path in &drvs {
        let bytes = corpus::read_drv(path);
        let drv = parse(path);

        let name = format!("{}.drv", corpus::drv_name(path));
        let computed = store_path::build_text_path(
            &name,
            &bytes,
            drv.input_derivations().keys().chain(drv.input_sources()),
        )
        .expect("build_text_path");

        assert_eq!(
            computed.to_absolute_path(),
            path.to_str().unwrap(),
            "computed drv path differs for {}",
            path.display()
        );
    }
}

/// Fill `cache` with each derivation's identity as an input, recursing first
/// so every input modulo is available when the callback asks for it.
fn fill_input_modulo(path: &Path, cache: &mut HashMap<PathBuf, InputDerivationHash>) {
    if cache.contains_key(path) {
        return;
    }

    let drv = parse(path);
    for input in drv.input_derivations().keys() {
        fill_input_modulo(&PathBuf::from(input.to_absolute_path()), cache);
    }

    let hash = drv
        .hash_input_derivation_modulo(|input| {
            cache
                .get(&PathBuf::from(input.to_absolute_path()))
                .expect("input derivation resolved before use")
                .to_owned()
        })
        .expect("input derivation modulo");
    cache.insert(path.to_path_buf(), hash);
}

/// The quotient hash from which input-addressed output paths are built.
fn output_path_modulo(
    path: &Path,
    cache: &mut HashMap<PathBuf, InputDerivationHash>,
) -> DerivationModuloHash {
    let drv = parse(path);
    for input in drv.input_derivations().keys() {
        fill_input_modulo(&PathBuf::from(input.to_absolute_path()), cache);
    }
    drv.hash_output_path_modulo(|input| {
        cache
            .get(&PathBuf::from(input.to_absolute_path()))
            .expect("input derivation resolved before use")
            .to_owned()
    })
    .expect("output-path modulo")
    .into_ready()
    .expect("generated input-addressed derivation is resolved")
}

/// Every output path recorded inside a `.drv` must be the path we compute for
/// it. Input addressed outputs go through `build_output_path`, fixed output
/// ones through `build_ca_path`.
///
/// This is the test that decides whether the implementation interoperates with
/// the rest of the Nix world.
#[test]
fn output_paths_match_output_path_modulo() {
    let Some(drvs) = corpus_or_skip() else { return };
    let mut cache = HashMap::new();

    for path in &drvs {
        let drv = parse(path);
        let drv_name = corpus::drv_name(path);

        for (output_name, output) in drv.resolved_outputs().expect("outputs") {
            let Some(expected) = &output.path else {
                // floating content addressed or deferred: no path until built
                continue;
            };

            let computed = match &output.ca_hash {
                Some(ca) => {
                    let name = store_path::output_path_name(&drv_name, &output_name)
                        .expect("output_path_name");
                    // A derivation's fixed outputs carry no references and no
                    // self reference (Nix uses `withoutRefs` here), whatever
                    // the hash mode.
                    store_path::build_ca_path(&name, ca, std::iter::empty::<&StorePath>(), false)
                        .expect("build_ca_path")
                }
                None => {
                    let hash = output_path_modulo(path, &mut cache);
                    store_path::build_output_path(hash, &output_name, &drv_name)
                        .expect("build_output_path")
                }
            };

            assert_eq!(
                &computed,
                expected,
                "output {output_name:?} of {} computed wrong",
                path.display()
            );
        }
    }
}

/// nixbase32 must round trip the digest of every real store path in the corpus.
///
/// Cheaper than hand written vectors, and it cannot be wrong: these digests were
/// encoded by Nix itself.
#[test]
fn nixbase32_round_trips_real_store_path_digests() {
    let Some(drvs) = corpus_or_skip() else { return };

    for path in &drvs {
        let base = path.file_name().unwrap().to_str().unwrap();
        let (encoded, _name) = base.split_once('-').expect("store path has no separator");

        let decoded = nixbase32::decode(encoded.as_bytes())
            .unwrap_or_else(|e| panic!("decoding {encoded:?} failed: {e}"));
        assert_eq!(decoded.len(), store_path::DIGEST_LEN);
        assert_eq!(nixbase32::encode(&decoded), encoded);
    }
}
