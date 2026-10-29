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

# Regenerate the static note-import provider list checked into the Note
# Android app and the Note web editor from the canonical Rust definition in
# `src/import_providers.rs`.
#
# Run from anywhere; paths are resolved relative to this script.
#
# This does NOT rebuild libpingolin_mobile.so or regen the UniFFI Kotlin
# bindings — `provider_specs()` is also exposed via UniFFI for clients
# that want to call it natively, but the JSON output here is the
# zero-rebuild path, read by the Note web editor and Note Android.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${CRATE_DIR}/../../../" && pwd)"

ANDROID_DEST="${REPO_ROOT}/note-android/app/src/main/assets/import_providers.json"
WEB_DEST="${REPO_ROOT}/note/ui/src/lib/importers/provider-specs.json"

cd "${CRATE_DIR}"

echo "→ Building dump-import-providers..."
cargo build -p mobile-sdk --bin dump-import-providers --release --quiet

JSON="$(cargo run -p mobile-sdk --bin dump-import-providers --release --quiet)"

mkdir -p "$(dirname "${ANDROID_DEST}")"
mkdir -p "$(dirname "${WEB_DEST}")"

printf '%s\n' "${JSON}" > "${ANDROID_DEST}"
printf '%s\n' "${JSON}" > "${WEB_DEST}"

echo "✓ Wrote provider specs:"
echo "    ${ANDROID_DEST}"
echo "    ${WEB_DEST}"
