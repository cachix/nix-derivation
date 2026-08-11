# Changelog

All notable changes to this project are documented in this file.

## [0.3.0] - 2026-08-11

### Added

- Add `StoreDir` and store-aware parsing, rendering, path-construction, builder,
  and validated-derivation APIs for non-default logical store directories such
  as Guix's `/gnu/store`.
- Add an opt-in Antithesis workload that exercises parsing, serialization,
  validation, structured attributes, and store-path round trips with mutated
  and arbitrary inputs.
- Add Guix fixtures and parity tests covering alternate-store derivation paths,
  outputs, inputs, structured attributes, placeholders, and ATerm escaping.

### Changed

- Carry the configured store directory through derivation serialization,
  hashing, output calculation, and structured-attribute generation while
  preserving the existing `/nix/store` APIs as default-store wrappers.

## [0.2.0] - 2026-08-10

### Breaking changes

- Replace `hash_derivation_modulo` and `try_hash_derivation_modulo` with
  type-directed input-identity and output-path hashing APIs. The new
  `DerivationModuloHash`, `InputDerivationHash`, and `OutputPathHash` types make
  fixed-output and deferred hashes explicit and align the behavior with Nix's
  intermediate-derivation model.
- Rename `HashDerivationError` to `InputResolutionError` and allow input hash
  resolvers to return typed `InputDerivationHash` values. Raw `[u8; 32]` values
  remain accepted as regular input-addressed hashes.
- Strengthen hash and content-address APIs with public `HashAlgorithm` and
  `ContentAddressMethod` types. This renames `NixHash::from_algo_and_digest` to
  `from_algorithm_and_digest` and `NixHash::algo` to `algorithm`, and changes
  the corresponding `CAHash` constructors and accessors to use typed values.
- Change store-path constructors to accept validated `StorePath` references
  instead of path strings, and make `build_output_path` accept a
  `DerivationModuloHash`.
- Mark public error enums as non-exhaustive and update hash and store-path error
  variants to carry the new typed values.

### Added

- Add `DerivationBuilder::input_addressed_output` and read-only accessors for
  every accumulated builder field.
- Add parsing and display implementations for hash algorithms, content-address
  methods, Nix hashes, and content addresses.
- Add differential tests for derivation-modulo hashing and Nix 2.34 parity,
  including fixed-output, content-addressed, and dynamic derivations.

### Changed

- Match Nix's derivation-modulo hashing semantics for fixed-output identities,
  output-name merging, and unresolved dynamic or content-addressed inputs.
- Validate structured attributes without eagerly materializing their JSON value
  tree, cache the sorted representation on first use, and generate structured
  attribute files without cloning the full object.
- Reduce allocations and copies in ATerm serialization, structured-attribute
  output substitution, and Nix base32 encoding.
- Expand API documentation and update benchmark methodology and results.

## [0.1.0] - 2026-08-09

- Initial release.

[0.3.0]: https://github.com/cachix/nix-derivation/releases/tag/0.3.0
[0.2.0]: https://github.com/cachix/nix-derivation/releases/tag/0.2.0
[0.1.0]: https://crates.io/crates/nix-derivation/0.1.0
