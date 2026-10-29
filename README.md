# mobile-sdk

Shared Rust client library powering Pingolin's mobile apps — Track (Android +
iOS) and Note (Android + iOS). It holds the end-to-end encryption primitives,
the location-streaming client, and the collaborative-editing CRDT, and it is
compiled into every app as a native library with generated Kotlin and Swift
bindings.

This repo is the source of the `.so` files the Android apps ship. If you are
looking at `libpingolin_mobile.so` or `libnote_collab_sdk.so` in track-android
or note-android and want to know what is in them, [build them yourself](#building-for-android)
and compare.

## Crates

- **`crates/mobile-sdk`** — the main UniFFI-bound library. A `CryptoManager`
  for E2EE primitives (XChaCha20-Poly1305, X25519, Ed25519, BLAKE3, Argon2id),
  a location-streaming client for Track, a server-blind geocoding cache, a
  boundary/inactivity monitor, and a canonical note-import provider list.
  Builds to `libpingolin_mobile.so` (Android) and `PingolinMobile.xcframework`
  (iOS), in the Kotlin/Swift namespace `pingolin_mobile`.

- **`crates/note-collab-sdk`** — Note's collaborative editing layer: a
  Yjs-compatible CRDT (`yrs`) wrapped in the AEAD framing that keeps the relay
  server blind, plus the per-note key wrapping and share-invite signatures.
  Builds to `libnote_collab_sdk.so`, in the namespace `collab`.

- **`crates/track-proto`** — protobuf definitions for Track's location-streaming
  gRPC channel. Both the client here and the server-side `track-ingest` crate
  depend on it, so the wire contract lives next to the client that speaks it.

## Layout: pingolin-crypto must be a sibling

`crates/mobile-sdk` depends on `pingolin-crypto` **by relative path**:

```toml
pingolin-crypto = { path = "../../../pingolin-crypto" }
```

so that repo has to be checked out next to this one. Three levels up from
`crates/mobile-sdk/` is the directory holding both:

```
<parent>/
  mobile-sdk/          <- this repository, cloned under this name
  pingolin-crypto/     <- https://github.com/pingolindev/pingolin-crypto-public
```

```sh
git clone https://github.com/pingolindev/mobile-sdk-public.git mobile-sdk
git clone https://github.com/pingolindev/pingolin-crypto-public.git pingolin-crypto
```

Nothing else about the parent directory matters — it does not have to be
called anything in particular.

## Prerequisites

| For | You need |
| --- | --- |
| Anything | Rust stable, via [rustup](https://rustup.rs) |
| Anything | `protoc` — `crates/track-proto` compiles `.proto` at build time (`apt install protobuf-compiler`, or `brew install protobuf`) |
| Android | Android NDK r26+ (tested against r27), and the Android Rust targets |
| iOS | Xcode (the full app, not just Command Line Tools), and the Apple Rust targets |

Android targets:

```sh
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
```

`build-android.sh` will try to add them for you, but says so clearly if it
cannot (a read-only rustup, for instance).

## Building for Android

```sh
./build-android.sh
```

That cross-compiles both libraries for all three ABIs and regenerates the
Kotlin bindings, into `build/android/`:

```
build/android/
  arm64-v8a/     libpingolin_mobile.so   libnote_collab_sdk.so
  armeabi-v7a/   libpingolin_mobile.so   libnote_collab_sdk.so
  x86_64/        libpingolin_mobile.so   libnote_collab_sdk.so
  kotlin/
    mobile-sdk/uniffi/pingolin_mobile/pingolin_mobile.kt
    note-collab-sdk/uniffi/collab/collab.kt
```

Useful options — `./build-android.sh --help` lists them all:

```sh
./build-android.sh --crate mobile-sdk            # one crate only
./build-android.sh --abi arm64-v8a               # one ABI only (much faster)
./build-android.sh --api-level 26 --out-dir /tmp/out
```

Set `ANDROID_NDK_HOME` if your NDK is not in one of the standard SDK
locations. The script does not need root and writes only inside this repo.

The three ABIs are arm64-v8a (phones and tablets), armeabi-v7a (older 32-bit
devices) and x86_64 (the emulator — without it an x86_64 AVD has to run the
ARM library through binary translation).

### Where the output goes in the apps

The Android apps carry committed copies of these artifacts, so that building
the app does not require a Rust toolchain:

```
<app>/library/src/main/jniLibs/<abi>/*.so
<app>/library/src/main/java/uniffi/
```

To check a shipped library against this source, build it and compare:

```sh
sha256sum build/android/arm64-v8a/libpingolin_mobile.so \
          ../track-android/library/src/main/jniLibs/arm64-v8a/libpingolin_mobile.so
```

Note that Rust and the NDK do not promise bit-identical output across
toolchain versions: a mismatch means "built with a different toolchain or a
different revision", not necessarily "built from different source".

## Building for iOS

iOS artifacts need Xcode, so that build lives in the app repos rather than
here — each one has a committed `build-ios.sh` that points at this repo:

```sh
# in track-ios
MOBILE_SDK_SRC=/path/to/mobile-sdk/crates/mobile-sdk ./build-ios.sh

# in note-ios
MOBILE_SDK_REPO=/path/to/mobile-sdk ./build-ios.sh
```

Each builds the device and simulator slices, lipos the simulator ones
together, generates the Swift bindings with `uniffi-bindgen`, and assembles an
XCFramework into the app's `lib/`.

## Tests

```sh
cd crates/mobile-sdk      && cargo test    # 235 tests
cd crates/note-collab-sdk && cargo test    # 34 tests, across 2 binaries
```

**`cargo test --workspace` does not test `crates/mobile-sdk`.** That crate is
deliberately excluded from the workspace in the root `Cargo.toml`:

```toml
exclude = ["crates/mobile-sdk"]
```

because its bundled-SQLite stack conflicts at link time with what the
workspace's other consumers want. It is a normal crate otherwise — it just has
to be built and tested from its own directory. Everything under
`crates/mobile-sdk/target/` is its own build directory, separate from the
workspace's `target/`.

## Generated bindings

UniFFI generates the Kotlin and Swift glue from the Rust source; it is not
written by hand and should not be edited. `build-android.sh` regenerates the
Kotlin side into `build/android/kotlin/`, and each app's `build-ios.sh`
regenerates the Swift side into the app.

The two crates pin different UniFFI versions and each builds its own
`uniffi-bindgen` binary, so their bindings are generated separately and are not
interchangeable.

## Third-party licences

[THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md) lists every third-party Rust
crate compiled into these libraries, with full licence texts. It is generated:

```sh
cargo install cargo-about
./generate-licenses.sh
```

Regenerate it whenever dependencies change. It fails rather than silently
accepting a licence not listed in `about.toml`.

## Contributing and security

This repository is published as one snapshot per release: each commit is a
shipped version, tagged with it, and the tree at a tag is the source that
version was built from. Development happens elsewhere, so this repository
takes no pull requests or issues.

Report security problems by email to **security@mail.pingolin.com**, not in
public.

## Licence

Pingolin Mobile SDK is free software: you can redistribute it and/or modify it under the
terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version. See [LICENSE](LICENSE).

The Pingolin name and logos are trademarks of Pingolin LLC and are not covered
by the licence. A modified version you distribute must not use them.
