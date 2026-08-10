use std::hint::black_box;
use std::time::{Duration, Instant};

use nix_derivation::Derivation;

const PATH: &str = "/nix/store/00000000000000000000000000000000-bench";

fn fixture(target_size: usize) -> Vec<u8> {
    let prefix = format!(
        "Derive([(\"out\",\"{PATH}\",\"\",\"\")],[],[],\"x86_64-linux\",\"/bin/sh\",[\"-c\",\"printf benchmark\"],["
    );
    let suffix = "\")])";
    let final_prefix = "(\"payload\",\"";
    assert!(target_size >= prefix.len() + final_prefix.len() + suffix.len());
    let mut bytes = Vec::with_capacity(target_size);
    bytes.extend_from_slice(prefix.as_bytes());

    // Many entries exercise map allocation, sorting, and short-string parsing
    // like a real package derivation; one final value pads to the exact size.
    let mut entries = 0;
    loop {
        let separator = usize::from(entries != 0);
        let entry = format!("(\"key-{entries:04}\",\"{}\")", "x".repeat(96));
        let final_separator = 1;
        if bytes.len()
            + separator
            + entry.len()
            + final_separator
            + final_prefix.len()
            + suffix.len()
            > target_size
        {
            break;
        }
        if separator != 0 {
            bytes.push(b',');
        }
        bytes.extend_from_slice(entry.as_bytes());
        entries += 1;
    }
    if entries != 0 {
        bytes.push(b',');
    }
    bytes.extend_from_slice(final_prefix.as_bytes());
    bytes.resize(target_size - suffix.len(), b'x');
    bytes.extend_from_slice(suffix.as_bytes());
    assert_eq!(bytes.len(), target_size);
    bytes
}

fn measure(mut operation: impl FnMut()) -> (f64, f64) {
    let warmup_deadline = Instant::now() + Duration::from_millis(250);
    while Instant::now() < warmup_deadline {
        operation();
    }

    let mut micros = Vec::with_capacity(7);
    for _ in 0..7 {
        let start = Instant::now();
        let deadline = start + Duration::from_millis(300);
        let mut iterations = 0_u64;
        while Instant::now() < deadline {
            operation();
            iterations += 1;
        }
        micros.push(start.elapsed().as_secs_f64() * 1_000_000.0 / iterations as f64);
    }
    micros.sort_by(f64::total_cmp);
    let micros = micros[micros.len() / 2];
    (1_000_000.0 / micros, micros)
}

fn report(label: &str, bytes: usize, operation: impl FnMut()) {
    let (per_second, micros) = measure(operation);
    let mib_per_second = per_second * bytes as f64 / (1024.0 * 1024.0);
    println!("{label:<23} {per_second:>9.0}/s  {micros:>8.2} us  {mib_per_second:>8.1} MiB/s");
}

fn main() {
    // Nix's C++ parser benchmark uses its 1,764-byte hello.drv and
    // 16,026-byte firefox.drv golden files. Matching those byte sizes makes
    // local before/after comparisons meaningful without copying upstream fixtures.
    for size in [1_764, 16_026, 65_536] {
        let bytes = fixture(size);
        let derivation = Derivation::from_aterm_bytes(&bytes, "bench").unwrap();
        let label = if size.is_multiple_of(1024) {
            format!("{} KiB", size / 1024)
        } else {
            format!("{size} B")
        };

        report(&format!("parse {label}"), size, || {
            black_box(Derivation::from_aterm_bytes(black_box(&bytes), "bench").unwrap());
        });
        report(&format!("serialize {label}"), size, || {
            black_box(derivation.to_aterm_bytes());
        });
        report(&format!("masked hash {label}"), size, || {
            black_box(
                derivation
                    .hash_derivation_modulo(true, |_| unreachable!())
                    .unwrap(),
            );
        });
    }
}
