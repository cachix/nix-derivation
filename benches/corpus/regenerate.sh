#!/usr/bin/env bash
set -euo pipefail

corpus_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
output_dir=${1:-$corpus_dir}
mkdir -p -- "$output_dir"
temporary_store=$(mktemp -d)
trap 'rm -rf -- "$temporary_store"' EXIT

for fixture in structured-attrs many-inputs fixed-output escapes; do
  logical_path=$(
    nix-instantiate \
      --store "local?root=$temporary_store" \
      "$corpus_dir/$fixture.nix"
  )
  cp -- "$temporary_store$logical_path" "$output_dir/$fixture.drv"
done

curl \
  --fail \
  --location \
  --output "$output_dir/dynamic-derivation.drv" \
  https://raw.githubusercontent.com/NixOS/nix/2.34.4/src/libstore-tests/data/derivation/dyn-dep-derivation.drv
