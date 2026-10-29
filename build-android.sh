#!/usr/bin/env bash
# Copyright (c) 2026 Pingolin LLC
#
# This file is part of Pingolin Mobile SDK.
#
# Pingolin Mobile SDK is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Pingolin Mobile SDK is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Pingolin Mobile SDK. If not, see <https://www.gnu.org/licenses/>.

# Build the Pingolin mobile SDK Rust crates as Android shared libraries, and
# generate their Kotlin (UniFFI) bindings.
#
# This is the whole recipe behind the .so files that ship inside the Android
# apps: track-android and note-android carry the products of this script in
# library/src/main/jniLibs/<abi>/ and library/src/main/java/uniffi/. Running
# this script and diffing the result against those committed files is how you
# check that the binaries match this source.
#
# Outputs (under ./build/android/ by default):
#
#   <abi>/libpingolin_mobile.so             from crates/mobile-sdk
#   <abi>/libnote_collab_sdk.so             from crates/note-collab-sdk
#   kotlin/mobile-sdk/uniffi/...            Kotlin bindings, uniffi.pingolin_mobile
#   kotlin/note-collab-sdk/uniffi/...       Kotlin bindings, uniffi.collab
#
# The two crates are built and bound separately: they produce different
# libraries, sit in different Kotlin namespaces, and pin different UniFFI
# versions, so neither one's bindgen can speak for the other.
#
# PREREQUISITES
#
#   * Rust (stable) via rustup, plus the Android std targets:
#       rustup target add aarch64-linux-android armv7-linux-androideabi \
#                         x86_64-linux-android
#
#   * Android NDK, r26 or newer (developed and tested against r27). Set
#     ANDROID_NDK_HOME, or let the script find it in the usual SDK locations.
#
#   * protoc, on PATH. crates/track-proto compiles the location-streaming
#     .proto files at build time, and crates/mobile-sdk depends on it.
#       Debian/Ubuntu: apt install protobuf-compiler
#       macOS:         brew install protobuf
#
#   * pingolin-crypto checked out as a SIBLING of this repo. crates/mobile-sdk
#     depends on it by relative path (../../../pingolin-crypto), so the
#     directory layout has to be:
#
#         <parent>/
#           mobile-sdk/          <- this repo
#           pingolin-crypto/     <- git@github.com:pingolindev/pingolin-crypto.git
#
# ABIS
#
#   arm64-v8a     aarch64-linux-android        phones and tablets
#   armeabi-v7a   armv7-linux-androideabi      older 32-bit devices
#   x86_64        x86_64-linux-android         the emulator
#
# The iOS equivalent of this script is build-ios.sh in track-ios and note-ios;
# it needs Xcode, so it cannot live here.
#
# Nothing in this script needs root, and it writes only inside this repo's
# build/ and target/ directories.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$SCRIPT_DIR"

ALL_ABIS="arm64-v8a armeabi-v7a x86_64"
ALL_CRATES="mobile-sdk note-collab-sdk"

CRATES=""
ABIS=""
OUT_DIR="$REPO_DIR/build/android"
API_LEVEL="${ANDROID_API_LEVEL:-26}"

die() { echo "error: $*" >&2; exit 1; }

usage() {
    cat <<EOF
Usage: $(basename "$0") [options]

  --crate NAME    mobile-sdk | note-collab-sdk | all   (default: all)
                  Repeatable.
  --abi LIST      comma-separated ABIs from: $ALL_ABIS
                  (default: all of them). Rust target triples are accepted too.
  --out-dir DIR   where to put the artifacts (default: ./build/android)
  --api-level N   Android API level of the NDK toolchain (default: $API_LEVEL)
  -h, --help      this message

Examples:
  $(basename "$0")
  $(basename "$0") --crate mobile-sdk --abi arm64-v8a
  ANDROID_NDK_HOME=/opt/android-ndk/r27 $(basename "$0")
EOF
}

# ---------------------------------------------------------------------------
# Arguments
# ---------------------------------------------------------------------------

while [[ $# -gt 0 ]]; do
    case "$1" in
        --crate)
            [[ $# -ge 2 ]] || die "--crate needs a value"
            case "$2" in
                all) CRATES="$ALL_CRATES" ;;
                mobile-sdk|note-collab-sdk) CRATES="${CRATES} $2" ;;
                *) die "unknown crate '$2' (expected: mobile-sdk, note-collab-sdk, all)" ;;
            esac
            shift 2
            ;;
        --abi)
            [[ $# -ge 2 ]] || die "--abi needs a value"
            ABIS="${ABIS} ${2//,/ }"
            shift 2
            ;;
        --out-dir)
            [[ $# -ge 2 ]] || die "--out-dir needs a value"
            OUT_DIR="$2"
            shift 2
            ;;
        --api-level)
            [[ $# -ge 2 ]] || die "--api-level needs a value"
            API_LEVEL="$2"
            shift 2
            ;;
        -h|--help) usage; exit 0 ;;
        *) usage >&2; die "unknown argument '$1'" ;;
    esac
done

[[ -n "$CRATES" ]] || CRATES="$ALL_CRATES"
[[ -n "$ABIS" ]] || ABIS="$ALL_ABIS"

# Accept Rust triples wherever an ABI name is expected — the two namings get
# mixed up constantly, and silently building nothing is a worse answer than
# accepting both.
normalise_abi() {
    case "$1" in
        arm64-v8a|aarch64-linux-android)      echo "arm64-v8a" ;;
        armeabi-v7a|armv7-linux-androideabi)  echo "armeabi-v7a" ;;
        x86_64|x86_64-linux-android)          echo "x86_64" ;;
        *) die "unknown ABI '$1' (expected one of: $ALL_ABIS)" ;;
    esac
}

NORMALISED=""
for abi in $ABIS; do
    NORMALISED="${NORMALISED} $(normalise_abi "$abi")"
done
ABIS="$NORMALISED"

abi_triple() {
    case "$1" in
        arm64-v8a)   echo "aarch64-linux-android" ;;
        armeabi-v7a) echo "armv7-linux-androideabi" ;;
        x86_64)      echo "x86_64-linux-android" ;;
    esac
}

# The NDK's wrapper names are not derivable from the triple: armv7's compiler
# is armv7a-..., with an 'a' the Rust target does not have.
abi_clang() {
    case "$1" in
        arm64-v8a)   echo "aarch64-linux-android${API_LEVEL}-clang" ;;
        armeabi-v7a) echo "armv7a-linux-androideabi${API_LEVEL}-clang" ;;
        x86_64)      echo "x86_64-linux-android${API_LEVEL}-clang" ;;
    esac
}

# ---------------------------------------------------------------------------
# Toolchain: NDK
# ---------------------------------------------------------------------------

if [[ -z "${ANDROID_NDK_HOME:-}" ]]; then
    # Standard SDK locations only. The environment variables come first because
    # they are the authoritative answer when someone has bothered to set them.
    for candidate in \
        "${ANDROID_SDK_ROOT:-/nonexistent}/ndk"/* \
        "${ANDROID_HOME:-/nonexistent}/ndk"/* \
        "${HOME:-/nonexistent}/Android/Sdk/ndk"/* \
        "${HOME:-/nonexistent}/Library/Android/sdk/ndk"/* \
        "/opt/android-ndk"/* \
        ; do
        if [[ -d "$candidate" ]]; then
            export ANDROID_NDK_HOME="$candidate"
            break
        fi
    done
fi

if [[ -z "${ANDROID_NDK_HOME:-}" || ! -d "$ANDROID_NDK_HOME" ]]; then
    die "Android NDK not found.
  Install it (Android Studio: SDK Manager -> SDK Tools -> NDK (Side by side),
  or download from https://developer.android.com/ndk/downloads) and either
  point ANDROID_NDK_HOME at it or place it under one of:
      \$ANDROID_SDK_ROOT/ndk/<version>
      \$ANDROID_HOME/ndk/<version>
      ~/Android/Sdk/ndk/<version>            (Linux)
      ~/Library/Android/sdk/ndk/<version>    (macOS)
      /opt/android-ndk/<version>"
fi

case "$(uname -s)" in
    Linux)  NDK_PREBUILT="linux-x86_64" ;;
    Darwin) NDK_PREBUILT="darwin-x86_64" ;;   # also the Apple Silicon layout
    *)      die "unsupported host OS '$(uname -s)' — this script needs a Linux or macOS NDK" ;;
esac

NDK_BIN="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$NDK_PREBUILT/bin"
[[ -d "$NDK_BIN" ]] || die "NDK toolchain not found at $NDK_BIN
  ANDROID_NDK_HOME=$ANDROID_NDK_HOME does not look like an NDK root (it should
  contain toolchains/llvm/prebuilt/$NDK_PREBUILT/bin). If you pointed it at the
  SDK's ndk/ directory, add the version component: .../ndk/27.2.12479018"

export ANDROID_NDK_HOME NDK_BIN
export PATH="$NDK_BIN:$PATH"

[[ -x "$NDK_BIN/llvm-ar" ]] || die "no llvm-ar in $NDK_BIN — the NDK install looks incomplete"

# Per-ABI compiler/linker/archiver. cargo reads CC_<triple> and
# CARGO_TARGET_<TRIPLE>_LINKER; both have to be the NDK's API-level wrapper,
# not a bare clang, or the link picks up the host libc.
for abi in $ABIS; do
    triple="$(abi_triple "$abi")"
    clang="$NDK_BIN/$(abi_clang "$abi")"

    if [[ ! -x "$clang" ]]; then
        # Strip the exact "<api>-clang" suffix rather than pattern-matching
        # digits: the x86_64 wrapper has digits in its ABI name too.
        wrapper_prefix="$(abi_clang "$abi")"
        wrapper_prefix="${wrapper_prefix%"${API_LEVEL}-clang"}"
        die "missing NDK compiler for $abi: $clang
  API level $API_LEVEL is not provided by this NDK. Available for this ABI:
$(ls "$NDK_BIN" 2>/dev/null | grep -E "^${wrapper_prefix}[0-9]+-clang$" | sed 's/^/      /' || echo '      (none)')
  Re-run with --api-level <N> using one of the levels above."
    fi

    env_triple="${triple//-/_}"
    env_TRIPLE="$(echo "$env_triple" | tr '[:lower:]' '[:upper:]')"
    export "CC_${env_triple}=$clang"
    export "AR_${env_triple}=$NDK_BIN/llvm-ar"
    export "CARGO_TARGET_${env_TRIPLE}_LINKER=$clang"
done

# ---------------------------------------------------------------------------
# Toolchain: Rust, protoc, sibling checkout
# ---------------------------------------------------------------------------

command -v cargo >/dev/null 2>&1 || die "cargo not found on PATH — install Rust from https://rustup.rs"

# `rustup target add` needs a writable RUSTUP_HOME, which a sandboxed CI build
# user does not have. Attempt it, then verify: what matters is whether the
# target's std is present, not whether the install command could run.
#
# Both commands MUST run in the directory cargo will build from. rustup picks
# the toolchain from the current directory, so a rust-toolchain.toml anywhere
# up the tree from wherever the caller happened to be standing would otherwise
# answer for a completely different toolchain — and since this check is
# fail-closed, a wrong answer blocks a build that would have worked.
ensure_rust_targets() {
    local dir="$1" installed abi triple
    command -v rustup >/dev/null 2>&1 || return 0

    for abi in $ABIS; do
        ( cd "$dir" && rustup target add "$(abi_triple "$abi")" ) >/dev/null 2>&1 || true
    done

    installed="$( cd "$dir" && rustup target list --installed 2>/dev/null || true )"
    for abi in $ABIS; do
        triple="$(abi_triple "$abi")"
        grep -qx -- "$triple" <<<"$installed" || die "Rust std for '$triple' is not installed for the toolchain active in $dir.
  Active toolchain: $( cd "$dir" && rustup show active-toolchain 2>/dev/null || echo unknown )
  Install it with:  rustup target add $triple
  If the active toolchain is not the one you expected, check for a
  rust-toolchain.toml pinning a channel that lacks the Android targets.
  In a sandboxed build this can also mean RUSTUP_HOME is read-only, and the
  target has to be installed by whoever owns the toolchain."
    done
}

command -v protoc >/dev/null 2>&1 || die "protoc not found on PATH.
  crates/track-proto compiles .proto files during the build.
  Debian/Ubuntu: apt install protobuf-compiler
  macOS:         brew install protobuf"

CRYPTO_DIR="$(cd "$REPO_DIR/.." && pwd)/pingolin-crypto"
if [[ " $CRATES " == *" mobile-sdk "* && ! -f "$CRYPTO_DIR/Cargo.toml" ]]; then
    die "pingolin-crypto not found at $CRYPTO_DIR
  crates/mobile-sdk depends on it by relative path
  (pingolin-crypto = { path = \"../../../pingolin-crypto\" }), so it must be
  cloned as a sibling of this repo:
      git clone https://github.com/pingolindev/pingolin-crypto-public.git \"$CRYPTO_DIR\""
fi

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

# crates/mobile-sdk is excluded from the workspace (its bundled-sqlite stack
# conflicts with the workspace's linking), so it builds from its own directory
# into its own target/. note-collab-sdk is a normal member and builds from the
# repo root. That is why each crate carries its own directory and -p flags
# rather than one loop over a uniform convention.
crate_dir() {
    case "$1" in
        mobile-sdk)      echo "$REPO_DIR/crates/mobile-sdk" ;;
        note-collab-sdk) echo "$REPO_DIR" ;;
    esac
}
crate_lib() {
    case "$1" in
        mobile-sdk)      echo "libpingolin_mobile" ;;
        note-collab-sdk) echo "libnote_collab_sdk" ;;
    esac
}
crate_cargo_args() {
    case "$1" in
        mobile-sdk)      echo "" ;;
        note-collab-sdk) echo "-p note-collab-sdk" ;;
    esac
}

case "$(uname -s)" in
    Darwin) HOST_LIB_EXT="dylib" ;;
    *)      HOST_LIB_EXT="so" ;;
esac

echo "========================================"
echo "Pingolin mobile SDK — Android build"
echo "========================================"
echo "  repo:      $REPO_DIR"
echo "  crates:   $CRATES"
echo "  ABIs:     $ABIS"
echo "  NDK:       $ANDROID_NDK_HOME (API $API_LEVEL)"
echo "  output:    $OUT_DIR"
echo

mkdir -p "$OUT_DIR"

for crate in $CRATES; do
    dir="$(crate_dir "$crate")"
    lib="$(crate_lib "$crate")"
    # shellcheck disable=SC2046 # deliberate word-splitting of the -p flags
    args=$(crate_cargo_args "$crate")

    ensure_rust_targets "$dir"

    for abi in $ABIS; do
        triple="$(abi_triple "$abi")"
        echo "----------------------------------------"
        echo "$crate -> $abi ($triple)"
        echo "----------------------------------------"

        # shellcheck disable=SC2086
        ( cd "$dir" && cargo build --release --target "$triple" $args )

        built="$dir/target/$triple/release/$lib.so"
        [[ -f "$built" ]] || die "$crate: expected $built after a successful build, but it is not there"

        mkdir -p "$OUT_DIR/$abi"
        cp "$built" "$OUT_DIR/$abi/$lib.so"
        echo "  -> $OUT_DIR/$abi/$lib.so"
    done

    # UniFFI reads the metadata out of a compiled library, so the bindings come
    # from a HOST build of the same crate — the Android .so cannot be loaded by
    # the generator.
    echo "----------------------------------------"
    echo "$crate -> Kotlin bindings"
    echo "----------------------------------------"

    # shellcheck disable=SC2086
    ( cd "$dir" && cargo build --release --lib $args )

    host_lib="$dir/target/release/$lib.$HOST_LIB_EXT"
    [[ -f "$host_lib" ]] || die "$crate: host library not found at $host_lib (needed to generate bindings)"

    kotlin_out="$OUT_DIR/kotlin/$crate"
    rm -rf "$kotlin_out"
    mkdir -p "$kotlin_out"

    # Each crate builds its own uniffi-bindgen binary against its own pinned
    # UniFFI version; they are not interchangeable. mobile-sdk keeps the
    # generator behind a `bindgen` feature so the shipped library does not carry
    # clap and the bindgen crate.
    case "$crate" in
        mobile-sdk)
            ( cd "$dir" && cargo run --release --features bindgen --bin uniffi-bindgen -- \
                generate --library "$host_lib" --language kotlin --out-dir "$kotlin_out" )
            ;;
        note-collab-sdk)
            ( cd "$dir" && cargo run --release --bin uniffi-bindgen -p note-collab-sdk -- \
                generate --library "$host_lib" --language kotlin --out-dir "$kotlin_out" )
            ;;
    esac

    [[ -d "$kotlin_out/uniffi" ]] \
        || die "$crate: uniffi-bindgen reported success but produced no $kotlin_out/uniffi directory"
    echo "  -> $kotlin_out/uniffi/"
done

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

echo
echo "========================================"
echo "Done — artifacts in $OUT_DIR"
echo "========================================"
# List only what THIS run produced. Globbing the ABI directories would also
# report libraries left there by a previous run with a different --crate, which
# is a build log claiming output it did not create.
for crate in $CRATES; do
    lib="$(crate_lib "$crate")"
    for abi in $ABIS; do
        so="$OUT_DIR/$abi/$lib.so"
        [[ -f "$so" ]] || continue
        printf '  %-14s %-24s %s bytes\n' "$abi" "$lib.so" "$(wc -c <"$so" | tr -d ' ')"
    done
done
for crate in $CRATES; do
    [[ -d "$OUT_DIR/kotlin/$crate" ]] || continue
    while IFS= read -r kt; do
        printf '  %-14s %-24s %s bytes\n' "kotlin" "${kt#"$OUT_DIR/kotlin/"}" "$(wc -c <"$kt" | tr -d ' ')"
    done < <(find "$OUT_DIR/kotlin/$crate" -name '*.kt' | sort)
done
echo
echo "To use these in the Android apps, copy them over the committed copies:"
echo "  <abi>/*.so            -> <app>/library/src/main/jniLibs/<abi>/"
echo "  kotlin/*/uniffi/      -> <app>/library/src/main/java/uniffi/"
