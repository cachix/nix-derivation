use std::panic::{AssertUnwindSafe, catch_unwind};

use antithesis_instrumentation as _;
use antithesis_sdk::{
    antithesis_init, assert_always, assert_reachable, assert_sometimes, lifecycle, random,
};
use nix_derivation::{Derivation, StorePath, StructuredAttrs, ValidatedDerivation};
use serde_json::json;

const DEFAULT_ITERATIONS: u64 = 10_000;
const MAX_RAW_INPUT: usize = 4_096;
const MAX_MUTATIONS: usize = 8;

#[derive(Clone, Copy)]
struct AtermSeed {
    name: &'static str,
    bytes: &'static [u8],
}

const ATERM_SEEDS: &[AtermSeed] = &[
    AtermSeed {
        name: "minimal",
        bytes: b"Derive([],[],[],\"x\",\"b\",[],[])",
    },
    AtermSeed {
        name: "bench-structured-attrs",
        bytes: include_bytes!("../../benches/corpus/structured-attrs.drv"),
    },
    AtermSeed {
        name: "bench-many-inputs",
        bytes: include_bytes!("../../benches/corpus/many-inputs.drv"),
    },
    AtermSeed {
        name: "bench-fixed-output",
        bytes: include_bytes!("../../benches/corpus/fixed-output.drv"),
    },
    AtermSeed {
        name: "bench-escapes",
        bytes: include_bytes!("../../benches/corpus/escapes.drv"),
    },
    AtermSeed {
        name: "dyn-dep-derivation",
        bytes: include_bytes!("../../benches/corpus/dynamic-derivation.drv"),
    },
];

const JSON_SEEDS: &[&[u8]] = &[
    b"{}",
    br#"{"array":[null,true,false,0,-0.0,1e-7],"nested":{"text":"line\nquote\""}}"#,
    br#"{"unicode":"lambda: \u03bb","large":1e20,"small":0.0001}"#,
];

const STORE_PATH_SEEDS: &[&[u8]] = &[
    b"/nix/store/00000000000000000000000000000000-example",
    b"/nix/store/abcdfghijklmnpqrsvwxyz0123456789-name-with-dashes.drv",
];

#[derive(Clone, Copy)]
enum Mutation {
    FlipBit,
    ReplaceByte,
    InsertByte,
    RemoveByte,
    Truncate,
    AppendByte,
    DuplicateRange,
}

const MUTATIONS: &[Mutation] = &[
    Mutation::FlipBit,
    Mutation::ReplaceByte,
    Mutation::InsertByte,
    Mutation::RemoveByte,
    Mutation::Truncate,
    Mutation::AppendByte,
    Mutation::DuplicateRange,
];

fn main() {
    antithesis_init();

    let iterations = iteration_limit();
    lifecycle::setup_complete(&json!({
        "driver": "nix-derivation",
        "iterations": iterations,
        "zero_means_unbounded": true,
    }));

    exercise_seeds();

    let mut iteration = 0;
    while iterations == 0 || iteration < iterations {
        let seed = *random::random_choice(ATERM_SEEDS).expect("ATerm seeds are nonempty");
        let seed_bytes = without_trailing_newline(seed.bytes);
        let mutated = mutate(seed_bytes, 1 + bounded(MAX_MUTATIONS));
        exercise_aterm(&mutated, seed.name, "mutated seed", iteration);

        let raw = random_bytes(bounded(MAX_RAW_INPUT + 1));
        exercise_aterm(&raw, "raw", "raw bytes", iteration);
        exercise_structured_attrs(&raw, "raw bytes", iteration);
        exercise_store_path(&raw, "raw bytes", iteration);

        let json_seed = *random::random_choice(JSON_SEEDS).expect("JSON seeds are nonempty");
        exercise_structured_attrs(
            &mutate(json_seed, 1 + bounded(MAX_MUTATIONS)),
            "mutated seed",
            iteration,
        );

        let store_seed =
            *random::random_choice(STORE_PATH_SEEDS).expect("store path seeds are nonempty");
        exercise_store_path(
            &mutate(store_seed, 1 + bounded(MAX_MUTATIONS)),
            "mutated seed",
            iteration,
        );

        iteration += 1;
    }
}

fn iteration_limit() -> u64 {
    std::env::args()
        .nth(1)
        .map(|value| {
            value
                .parse()
                .expect("iteration count must be a non-negative integer")
        })
        .unwrap_or(DEFAULT_ITERATIONS)
}

fn exercise_seeds() {
    for seed in ATERM_SEEDS {
        exercise_aterm(
            without_trailing_newline(seed.bytes),
            seed.name,
            "unmodified seed",
            0,
        );
    }
    for bytes in JSON_SEEDS {
        exercise_structured_attrs(bytes, "unmodified seed", 0);
    }
    for bytes in STORE_PATH_SEEDS {
        exercise_store_path(bytes, "unmodified seed", 0);
    }
}

fn exercise_aterm(bytes: &[u8], name: &str, source: &str, iteration: u64) {
    let details = json!({
        "source": source,
        "derivation_name": name,
        "iteration": iteration,
        "input_length": bytes.len(),
    });
    let parse = catch_unwind(AssertUnwindSafe(|| {
        Derivation::from_aterm_bytes(bytes, name)
    }));
    assert_always!(parse.is_ok(), "ATerm parsing never panics", &details);
    let Ok(parse) = parse else {
        return;
    };

    assert_sometimes!(
        parse.is_ok(),
        "ATerm parser accepts generated input",
        &details
    );
    assert_sometimes!(
        parse.is_err(),
        "ATerm parser rejects generated input",
        &details
    );
    let Ok(derivation) = parse else {
        return;
    };
    assert_reachable!("A syntactically valid ATerm is parsed", &details);

    let operations = catch_unwind(AssertUnwindSafe(|| {
        let canonical = derivation.to_aterm_bytes();
        let mut streamed = Vec::new();
        let stream_result = derivation.write_aterm(&mut streamed);
        let reparsed = Derivation::from_aterm_bytes(&canonical, name);
        let validation_succeeded = derivation.validate().is_ok();
        let validated_parse_succeeded =
            ValidatedDerivation::from_aterm_bytes(&canonical, name).is_ok();

        (
            canonical,
            streamed,
            stream_result,
            reparsed,
            validation_succeeded,
            validated_parse_succeeded,
        )
    }));
    assert_always!(
        operations.is_ok(),
        "Operations on a parsed ATerm never panic",
        &details
    );
    let Ok((
        canonical,
        streamed,
        stream_result,
        reparsed,
        validation_succeeded,
        validated_parse_succeeded,
    )) = operations
    else {
        return;
    };

    assert_always!(
        stream_result.is_ok() && streamed == canonical,
        "Streaming and allocating ATerm serialization agree",
        &details
    );
    assert_always!(
        reparsed.is_ok(),
        "Canonical ATerm serialization reparses",
        &details
    );
    if let Ok(reparsed) = reparsed {
        assert_always!(
            reparsed.to_aterm_bytes() == canonical,
            "Canonical ATerm serialization is idempotent",
            &details
        );
    }
    assert_always!(
        validation_succeeded == validated_parse_succeeded,
        "Direct validation and validated parsing agree",
        &details
    );
}

fn exercise_structured_attrs(bytes: &[u8], source: &str, iteration: u64) {
    let details = json!({
        "source": source,
        "iteration": iteration,
        "input_length": bytes.len(),
    });
    let parse = catch_unwind(AssertUnwindSafe(|| {
        StructuredAttrs::from_json_bytes(bytes.to_vec())
    }));
    assert_always!(
        parse.is_ok(),
        "Structured attribute parsing never panics",
        &details
    );
    let Ok(parse) = parse else {
        return;
    };

    assert_sometimes!(
        parse.is_ok(),
        "Structured attribute parser accepts generated input",
        &details
    );
    assert_sometimes!(
        parse.is_err(),
        "Structured attribute parser rejects generated input",
        &details
    );
    let Ok(attrs) = parse else {
        return;
    };

    let canonical = catch_unwind(AssertUnwindSafe(|| attrs.canonical_json().to_vec()));
    assert_always!(
        canonical.is_ok(),
        "Structured attribute canonicalization never panics",
        &details
    );
    let Ok(canonical) = canonical else {
        return;
    };
    let reparsed = StructuredAttrs::from_json_bytes(canonical.clone());
    assert_always!(
        reparsed.is_ok(),
        "Canonical structured attributes reparse",
        &details
    );
    if let Ok(reparsed) = reparsed {
        assert_always!(
            reparsed.canonical_json() == canonical,
            "Structured attribute canonicalization is idempotent",
            &details
        );
    }
}

fn exercise_store_path(bytes: &[u8], source: &str, iteration: u64) {
    let details = json!({
        "source": source,
        "iteration": iteration,
        "input_length": bytes.len(),
    });
    let parse = catch_unwind(AssertUnwindSafe(|| StorePath::from_absolute_path(bytes)));
    assert_always!(parse.is_ok(), "Store path parsing never panics", &details);
    let Ok(parse) = parse else {
        return;
    };

    assert_sometimes!(
        parse.is_ok(),
        "Store path parser accepts generated input",
        &details
    );
    assert_sometimes!(
        parse.is_err(),
        "Store path parser rejects generated input",
        &details
    );
    let Ok(path) = parse else {
        return;
    };
    let rendered = path.to_absolute_path();
    let reparsed = StorePath::from_absolute_path(rendered.as_bytes());
    assert_always!(
        reparsed.as_ref() == Ok(&path),
        "Store path rendering round trips",
        &details
    );
}

fn mutate(seed: &[u8], count: usize) -> Vec<u8> {
    let mut bytes = seed.to_vec();
    for _ in 0..count {
        let mutation = *random::random_choice(MUTATIONS).expect("mutations are nonempty");
        match mutation {
            Mutation::FlipBit if !bytes.is_empty() => {
                let index = bounded(bytes.len());
                bytes[index] ^= 1 << bounded(8);
            }
            Mutation::ReplaceByte if !bytes.is_empty() => {
                let index = bounded(bytes.len());
                bytes[index] = random::get_random() as u8;
            }
            Mutation::InsertByte => {
                let index = bounded(bytes.len() + 1);
                bytes.insert(index, random::get_random() as u8);
            }
            Mutation::RemoveByte if !bytes.is_empty() => {
                let index = bounded(bytes.len());
                bytes.remove(index);
            }
            Mutation::Truncate if !bytes.is_empty() => {
                bytes.truncate(bounded(bytes.len() + 1));
            }
            Mutation::AppendByte => bytes.push(random::get_random() as u8),
            Mutation::DuplicateRange if !bytes.is_empty() => {
                let start = bounded(bytes.len());
                let available = bytes.len() - start;
                let length = 1 + bounded(available.min(64));
                bytes.extend_from_within(start..start + length);
            }
            Mutation::FlipBit
            | Mutation::ReplaceByte
            | Mutation::RemoveByte
            | Mutation::Truncate
            | Mutation::DuplicateRange => {}
        }
    }
    bytes
}

fn random_bytes(length: usize) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(length);
    while bytes.len() < length {
        bytes.extend_from_slice(&random::get_random().to_le_bytes());
    }
    bytes.truncate(length);
    bytes
}

fn bounded(upper_exclusive: usize) -> usize {
    debug_assert!(upper_exclusive > 0);
    (random::get_random() as usize) % upper_exclusive
}

fn without_trailing_newline(bytes: &[u8]) -> &[u8] {
    bytes.strip_suffix(b"\n").unwrap_or(bytes)
}
