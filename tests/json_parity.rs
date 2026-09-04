//! Live differential checks against Nix's derivation JSON implementation.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use nix_derivation::{CAHash, Derivation, DerivationBuilder, NixHash, Output, json};
use serde_json::Value;

#[path = "support/differential_corpus.rs"]
#[allow(dead_code)]
mod corpus;

fn nix_json(path: &Path) -> Option<Value> {
    let output = Command::new("nix")
        .args([
            "--extra-experimental-features",
            "nix-command ca-derivations",
            "--store",
            &corpus::store_arg(),
            "derivation",
            "show",
        ])
        .arg(path)
        .arg("--no-pretty")
        .output()
        .expect("nix derivation show failed to spawn");
    assert!(
        output.status.success(),
        "nix derivation show failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let value: Value = serde_json::from_slice(&output.stdout).expect("Nix emitted invalid JSON");
    if value.get("version").and_then(Value::as_u64) != Some(json::VERSION) {
        eprintln!("skipping: installed Nix does not emit derivation JSON v4");
        return None;
    }
    let basename = path.file_name().unwrap().to_str().unwrap();
    Some(
        value["derivations"]
            .get(basename)
            .unwrap_or_else(|| panic!("Nix JSON omitted {basename:?}"))
            .clone(),
    )
}

fn nix_add_json(encoded: &[u8], features: &str) -> std::process::Output {
    let mut child = Command::new("nix")
        .args([
            "--extra-experimental-features",
            features,
            "--store",
            &corpus::store_arg(),
            "derivation",
            "add",
            "--dry-run",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("nix derivation add failed to spawn");
    child.stdin.take().unwrap().write_all(encoded).unwrap();
    child.wait_with_output().unwrap()
}

fn nix_accepts_json(encoded: &[u8], expected_path: &Path) {
    let output = nix_add_json(encoded, "nix-command ca-derivations");
    assert!(
        output.status.success(),
        "Nix rejected reserialized JSON for {}:\n{}",
        expected_path.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        expected_path.to_str().unwrap()
    );
}

#[test]
fn nix_v4_json_is_lossless_and_nix_accepts_our_serialization() {
    if Command::new("nix").arg("--version").output().is_err() {
        eprintln!("skipping: Nix is not on PATH");
        return;
    }
    let Some(paths) = corpus::drvs() else {
        eprintln!("skipping: Nix is not on PATH");
        return;
    };

    for path in paths {
        let Some(expected) = nix_json(&path) else {
            return;
        };
        let encoded = serde_json::to_vec(&expected).unwrap();
        let derivation = Derivation::from_json_bytes(&encoded)
            .unwrap_or_else(|error| panic!("failed to parse {}: {error}", path.display()));
        assert_eq!(
            json::to_value(&derivation).unwrap(),
            expected,
            "JSON round trip changed {}",
            path.display()
        );
        nix_accepts_json(&derivation.to_json_bytes().unwrap(), &path);
    }
}

#[test]
fn nix_accepts_blake3_fixed_output_json() {
    if Command::new("nix").arg("--version").output().is_err() {
        eprintln!("skipping: Nix is not on PATH");
        return;
    }

    let derivation = DerivationBuilder::new("blake3-json", "x86_64-linux", "/bin/sh")
        .output(
            "out",
            Output::Fixed {
                ca: CAHash::Nar(NixHash::Blake3([0; 32])),
            },
        )
        .build()
        .unwrap();
    let expected_path = derivation.drv_path();
    let output = nix_add_json(
        &derivation.to_json_bytes().unwrap(),
        "nix-command blake3-hashes",
    );
    if !output.status.success() && String::from_utf8_lossy(&output.stderr).contains("blake3-hashes")
    {
        eprintln!("skipping: installed Nix does not support blake3-hashes");
        return;
    }
    assert!(
        output.status.success(),
        "Nix rejected BLAKE3 derivation JSON:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        expected_path.to_absolute_path()
    );
}
