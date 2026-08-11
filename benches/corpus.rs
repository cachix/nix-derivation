use std::hint::black_box;
use std::time::{Duration, Instant};

use nix_derivation::Derivation;

struct Fixture {
    label: &'static str,
    name: &'static str,
    bytes: &'static [u8],
    hashable: bool,
}

fn fixture_bytes(bytes: &'static [u8]) -> &'static [u8] {
    bytes.strip_suffix(b"\n").unwrap_or(bytes)
}

fn fixtures() -> [Fixture; 5] {
    [
        Fixture {
            label: "structured attrs",
            name: "bench-structured-attrs",
            bytes: fixture_bytes(include_bytes!("corpus/structured-attrs.drv")),
            hashable: true,
        },
        Fixture {
            label: "many inputs (128)",
            name: "bench-many-inputs",
            bytes: fixture_bytes(include_bytes!("corpus/many-inputs.drv")),
            hashable: true,
        },
        Fixture {
            label: "fixed output",
            name: "bench-fixed-output",
            bytes: fixture_bytes(include_bytes!("corpus/fixed-output.drv")),
            hashable: true,
        },
        Fixture {
            label: "escaped strings",
            name: "bench-escapes",
            bytes: fixture_bytes(include_bytes!("corpus/escapes.drv")),
            hashable: true,
        },
        Fixture {
            label: "dynamic derivation",
            name: "dyn-dep-derivation",
            bytes: fixture_bytes(include_bytes!("corpus/dynamic-derivation.drv")),
            // Nix's characterization fixture intentionally has no outputs, so
            // it is parseable but not a semantically hashable build recipe.
            hashable: false,
        },
    ]
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
    println!("{label:<38} {per_second:>9.0}/s  {micros:>8.2} us  {mib_per_second:>8.1} MiB/s");
}

fn main() {
    for fixture in fixtures() {
        let derivation = Derivation::from_aterm_bytes(fixture.bytes, fixture.name).unwrap();
        let canonical = derivation.to_aterm_bytes();
        assert_eq!(canonical, fixture.bytes);
        let reparsed = Derivation::from_aterm_bytes(&canonical, fixture.name).unwrap();
        assert_eq!(reparsed.to_aterm_bytes(), canonical);
        if fixture.hashable {
            derivation.validate().unwrap();
        }

        let size = fixture.bytes.len();
        println!("\n{} ({size} bytes)", fixture.label);
        report(&format!("parse {}", fixture.label), size, || {
            black_box(
                Derivation::from_aterm_bytes(black_box(fixture.bytes), fixture.name).unwrap(),
            );
        });
        report(
            &format!("parse + first serialize {}", fixture.label),
            size,
            || {
                let derivation =
                    Derivation::from_aterm_bytes(black_box(fixture.bytes), fixture.name).unwrap();
                black_box(derivation.to_aterm_bytes());
            },
        );
        report(&format!("serialize (warm) {}", fixture.label), size, || {
            black_box(derivation.to_aterm_bytes());
        });
        if fixture.hashable {
            report(&format!("modulo hash {}", fixture.label), size, || {
                if derivation.is_fixed_output().unwrap() {
                    black_box(
                        derivation
                            .hash_input_derivation_modulo(|_| [0x42; 32])
                            .unwrap(),
                    );
                } else {
                    black_box(derivation.hash_output_path_modulo(|_| [0x42; 32]).unwrap());
                }
            });
        }
    }
}
