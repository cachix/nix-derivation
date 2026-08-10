//! Corpus generation for the differential harness.
//!
//! We do not sample `/nix/store`, because a machine may have no `.drv` files at
//! all. Instead we instantiate a fixed set of expressions with
//! `nix-instantiate --expr`, which needs no nixpkgs, no network, and no
//! writable store beyond what Nix already has. The expressions are chosen to
//! cover the corners that break derivation hashing.
//!
//! Every `.drv` is self-oracling: its store path is the text hash of its own
//! bytes, and it records the paths of its own outputs. So these tests need no
//! oracle beyond `nix-instantiate` itself.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Expressions covering the shapes that derivation hashing has to get right.
///
/// A non-UTF-8 environment value cannot be produced by the Nix language; the
/// package's byte-oriented unit corpus covers that case directly.
pub const EXPRS: &[(&str, &str)] = &[
    (
        "simple",
        r#"derivation { name = "a"; builder = "/bin/sh"; system = "x86_64-linux"; }"#,
    ),
    (
        "multi-output-with-input-drv",
        r#"let a = derivation { name = "a"; builder = "/bin/sh"; system = "x86_64-linux"; };
           in derivation {
             name = "b"; builder = "/bin/sh"; system = "x86_64-linux";
             outputs = [ "out" "dev" ]; inherit a;
           }"#,
    ),
    (
        "fixed-output-flat",
        r#"derivation {
             name = "fod-flat"; builder = "/bin/sh"; system = "x86_64-linux";
             outputHashMode = "flat"; outputHashAlgo = "sha256";
             outputHash = "0000000000000000000000000000000000000000000000000000000000000000";
           }"#,
    ),
    (
        "fixed-output-recursive",
        r#"derivation {
             name = "fod-rec"; builder = "/bin/sh"; system = "x86_64-linux";
             outputHashMode = "recursive"; outputHashAlgo = "sha256";
             outputHash = "1111111111111111111111111111111111111111111111111111111111111111";
           }"#,
    ),
    (
        "fixed-output-flat-sha1",
        r#"derivation {
             name = "fod-flat-sha1"; builder = "/bin/sh"; system = "x86_64-linux";
             outputHashMode = "flat"; outputHashAlgo = "sha1";
             outputHash = "2222222222222222222222222222222222222222";
           }"#,
    ),
    (
        "fixed-output-flat-md5",
        r#"derivation {
             name = "fod-flat-md5"; builder = "/bin/sh"; system = "x86_64-linux";
             outputHashMode = "flat"; outputHashAlgo = "md5";
             outputHash = "33333333333333333333333333333333";
           }"#,
    ),
    (
        "fixed-output-recursive-sha512",
        r#"derivation {
             name = "fod-rec-sha512"; builder = "/bin/sh"; system = "x86_64-linux";
             outputHashMode = "recursive"; outputHashAlgo = "sha512";
             outputHash = "44444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444";
           }"#,
    ),
    (
        "placeholder-in-args",
        r#"derivation {
             name = "ph"; builder = "/bin/sh"; system = "x86_64-linux";
             args = [ (builtins.placeholder "out") ];
           }"#,
    ),
    (
        "input-source",
        r#"derivation {
             name = "src"; builder = "/bin/sh"; system = "x86_64-linux";
             f = builtins.toFile "greeting" "hello";
           }"#,
    ),
    (
        "structured-attrs",
        r#"derivation {
             name = "sa"; builder = "/bin/sh"; system = "x86_64-linux";
             __structuredAttrs = true; nested = { a = 1; b = [ "x" ]; };
           }"#,
    ),
    (
        "escaping-and-unicode",
        r#"derivation {
             name = "unicode"; builder = "/bin/sh"; system = "x86_64-linux";
             args = [ "quote:\"" "slash:\\" "line\nbreak" "héllö λ" ];
             message = "tabs\tcarriage\rreturn";
           }"#,
    ),
    (
        "nested-structured-attrs",
        r#"derivation {
             name = "nested-sa"; builder = "/bin/sh"; system = "x86_64-linux";
             __structuredAttrs = true;
             scalars = [ null true false (-42) "it's fine" ];
             fraction = 1.25;
             unicode = "héllö λ";
             nested = { z = { y = [ 1 2 3 ]; }; a = "first"; };
           }"#,
    ),
    (
        "several-requested-input-outputs",
        r#"let a = derivation {
             name = "multi-input"; builder = "/bin/sh"; system = "x86_64-linux";
             outputs = [ "out" "dev" "doc" "debug" ];
           };
           in derivation {
             name = "uses-several"; builder = "/bin/sh"; system = "x86_64-linux";
             fromOut = a.out; fromDev = a.dev; fromDoc = a.doc; fromDebug = a.debug;
           }"#,
    ),
    (
        "two-levels-of-input-drvs",
        r#"let
             a = derivation { name = "a"; builder = "/bin/sh"; system = "x86_64-linux"; };
             b = derivation { name = "b"; builder = "/bin/sh"; system = "x86_64-linux"; inherit a; };
           in derivation { name = "c"; builder = "/bin/sh"; system = "x86_64-linux"; inherit a b; }"#,
    ),
];

/// Expressions requiring `--extra-experimental-features ca-derivations`.
///
/// These cover the `DrvHash::Kind::Deferred` corner: a floating content
/// addressed derivation has outputs with no path, and an input addressed
/// derivation depending on it gets *deferred* outputs — also pathless until
/// build time. The parity test skips pathless outputs, but parse, byte exact
/// round trip, drv path computation, and the modulo hash substitution all
/// still run over them.
pub const CA_EXPRS: &[(&str, &str)] = &[
    (
        "ca-floating",
        r#"derivation {
             name = "ca-float"; builder = "/bin/sh"; system = "x86_64-linux";
             __contentAddressed = true;
             outputHashMode = "recursive"; outputHashAlgo = "sha256";
           }"#,
    ),
    (
        "deferred-dep-on-ca",
        r#"let ca = derivation {
             name = "ca-float"; builder = "/bin/sh"; system = "x86_64-linux";
             __contentAddressed = true;
             outputHashMode = "recursive"; outputHashAlgo = "sha256";
           };
           in derivation { name = "dep-on-ca"; builder = "/bin/sh"; system = "x86_64-linux"; inherit ca; }"#,
    ),
];

fn have_nix() -> bool {
    Command::new("nix-instantiate")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

/// The corpus lives in a user-owned chroot store (`local?root=...`), not the
/// system store. Two reasons: the system store may be served by a daemon whose
/// experimental features we cannot control (the CA expressions need
/// `ca-derivations` at *parse* time, and the daemon parses server side), and
/// the harness should not write into the real store at all. The *logical*
/// store dir of a chroot store is still `/nix/store`, so every path in the
/// corpus remains valid for parity.
fn store_root() -> PathBuf {
    PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("corpus-store")
}

fn store_arg() -> String {
    format!("local?root={}", store_root().display())
}

/// Read a corpus `.drv` by its logical store path, translating to the file's
/// physical location under the chroot store root.
pub fn read_drv(logical: &Path) -> Vec<u8> {
    let physical = store_root().join(logical.strip_prefix("/").expect("absolute store path"));
    std::fs::read(&physical)
        .unwrap_or_else(|e| panic!("reading {} failed: {e}", physical.display()))
}

fn instantiate(expr: &str) -> Vec<PathBuf> {
    let out = Command::new("nix-instantiate")
        .args(["--extra-experimental-features", "ca-derivations"])
        .args(["--store", &store_arg()])
        .arg("--expr")
        .arg(expr)
        .output()
        .expect("nix-instantiate failed to spawn");
    assert!(
        out.status.success(),
        "nix-instantiate failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout)
        .lines()
        // `nix-instantiate` prints `<drv path>!<output>` for some expressions.
        .map(|l| PathBuf::from(l.split('!').next().unwrap_or(l).trim()))
        .filter(|p| p.extension().is_some_and(|e| e == "drv"))
        .collect()
}

/// The transitive `.drv` closure of a derivation, so derivation-modulo hashing
/// has every input derivation available to resolve.
fn requisite_drvs(drv: &Path) -> Vec<PathBuf> {
    let out = Command::new("nix-store")
        .args(["--extra-experimental-features", "ca-derivations"])
        .args(["--store", &store_arg()])
        .args(["--query", "--requisites"])
        .arg(drv)
        .output()
        .expect("nix-store failed to spawn");
    assert!(
        out.status.success(),
        "nix-store --query --requisites failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(PathBuf::from)
        .filter(|p| p.extension().is_some_and(|e| e == "drv"))
        .collect()
}

/// Every `.drv` in the corpus, deduplicated and sorted.
///
/// Returns `None` when Nix is unavailable, so the tests skip rather than fail
/// on a machine without it.
///
/// Generated exactly once per test process: the tests run as parallel threads,
/// and racing several `nix-instantiate` invocations against a cold chroot
/// store is flaky. `OnceLock` serializes generation; every test reads the same
/// list.
pub fn drvs() -> Option<Vec<PathBuf>> {
    static CORPUS: std::sync::OnceLock<Option<Vec<PathBuf>>> = std::sync::OnceLock::new();
    CORPUS.get_or_init(generate).clone()
}

fn generate() -> Option<Vec<PathBuf>> {
    if !have_nix() {
        return None;
    }

    let mut all = BTreeSet::new();
    for (label, expr) in EXPRS.iter().chain(CA_EXPRS.iter()) {
        let roots = instantiate(expr);
        assert!(!roots.is_empty(), "expression {label:?} produced no .drv");
        for root in &roots {
            all.extend(requisite_drvs(root));
        }
        all.extend(roots);
    }
    Some(all.into_iter().collect())
}

/// `/nix/store/<digest>-hello.drv` becomes `hello`.
pub fn drv_name(path: &Path) -> String {
    let base = path.file_name().unwrap().to_str().unwrap();
    let (_digest, rest) = base.split_once('-').expect("store path has no separator");
    rest.strip_suffix(".drv").expect("not a .drv").to_string()
}
