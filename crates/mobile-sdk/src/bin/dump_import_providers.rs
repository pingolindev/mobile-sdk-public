// Copyright (c) 2026 Pingolin LLC
//
// This file is part of Pingolin Mobile SDK.
//
// Pingolin Mobile SDK is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Pingolin Mobile SDK is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Pingolin Mobile SDK. If not, see <https://www.gnu.org/licenses/>.

//! Dump the canonical note-import provider list as JSON.
//!
//! Run:
//!   cargo run -p mobile-sdk --bin dump-import-providers > providers.json
//!
//! The web client consumes the JSON directly, so it needs no wasm build of
//! this crate. `scripts/regen-provider-specs.sh` runs this binary and writes
//! the output into the client trees.

fn main() {
    let specs = pingolin_mobile::provider_specs();
    let json =
        serde_json::to_string_pretty(&specs).expect("provider specs serialize");
    println!("{}", json);
}
