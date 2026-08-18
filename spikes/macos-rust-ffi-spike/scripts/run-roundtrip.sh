#!/bin/bash
set -euo pipefail

script_directory=$(cd "$(dirname "$0")" && pwd)
spike_directory=$(cd "$script_directory/.." && pwd)
rust_directory="$spike_directory/rust"
target_triple="aarch64-apple-darwin"
deployment_target="arm64-apple-macosx14.0"

if [[ "$(uname -m)" != "arm64" ]]; then
    echo "error: this spike requires an Apple Silicon host" >&2
    exit 1
fi

cargo build --manifest-path "$rust_directory/Cargo.toml" --locked --target "$target_triple"

build_directory=$(mktemp -d "${TMPDIR:-/tmp}/novaray-ffi-roundtrip.XXXXXX")
trap 'rm -rf "$build_directory"' EXIT

swiftc \
    -swift-version 6 \
    -warnings-as-errors \
    -target "$deployment_target" \
    -module-cache-path "$build_directory/module-cache" \
    -I "$spike_directory/include" \
    "$spike_directory/swift/Roundtrip.swift" \
    "$rust_directory/target/$target_triple/debug/libnovaray_ffi_spike.a" \
    -o "$build_directory/novaray-ffi-roundtrip"

"$build_directory/novaray-ffi-roundtrip"
