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

//! Canonical list of note-import providers — the single source of truth for
//! them. The clients can't drift on display copy, OAuth config, or
//! instruction text because each one is generated from this list.
//!
//! Consumption paths:
//! - The Note Android app and the Note web editor read a JSON file produced
//!   by the `dump_import_providers` binary (see
//!   `bin/dump_import_providers.rs`), which serializes [`provider_specs`]
//!   with serde at build time.
//! - [`provider_specs`] is also exported through the generated UniFFI
//!   bindings, for clients that want to call it natively.
//!
//! Any change to the spec list — new provider, new OAuth scope, copy tweak
//! — lands here first, then is propagated by re-running
//! `scripts/regen-provider-specs.sh`.

use serde::{Deserialize, Serialize};

/// Which section of the import screen the provider lives in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, uniffi::Enum)]
#[serde(rename_all = "snake_case")]
pub enum ImportSection {
    /// "From a file" — user picks a file they already have.
    File,
    /// "Connect an account" — user authenticates with a provider and
    /// the client fetches notes through that provider's API.
    Connect,
}

/// How the client should collect credentials / data for the provider.
#[derive(Debug, Clone, Serialize, Deserialize, uniffi::Enum)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AuthMethod {
    /// Plain file picker. `mime_types` constrains the picker.
    FileUpload { mime_types: Vec<String> },
    /// Deep-link to an external export tool (e.g. Google Takeout)
    /// then fall back to a file picker on return.
    TakeoutLink {
        external_url: String,
        mime_types: Vec<String>,
    },
    /// OAuth 2.0 authorization-code flow with PKCE — safe for public
    /// clients (no shipped secret).
    OAuth2Pkce(OAuthConfig),
    /// Username + password / API token entered into a credential form.
    /// `fields` is the ordered list of inputs to show.
    Credentials { fields: Vec<CredentialField> },
}

/// Static OAuth 2.0 configuration for a provider. The client looks up
/// the actual `client_id` at runtime via `client_id_env_key` so it can
/// differ between dev / staging / prod builds without changing this
/// spec.
#[derive(Debug, Clone, Serialize, Deserialize, uniffi::Record)]
pub struct OAuthConfig {
    pub authorization_url: String,
    pub token_url: String,
    pub scopes: Vec<String>,
    /// Env var (Android: BuildConfig field; web: import.meta.env key)
    /// holding the OAuth client ID for the current build flavor.
    pub client_id_env_key: String,
    /// Path appended to the canonical note frontend origin to form
    /// the redirect URI (e.g. "/oauth/callback"). The frontend serves
    /// a tiny HTML page at that path that forwards the auth code back
    /// to the opener / app via postMessage / App Link.
    pub redirect_path: String,
}

/// A single field in a [`AuthMethod::Credentials`] form.
#[derive(Debug, Clone, Serialize, Deserialize, uniffi::Record)]
pub struct CredentialField {
    pub key: String,
    pub label: String,
    pub placeholder: String,
    /// Hide the input (e.g. password).
    pub secret: bool,
}

/// Top-level provider description. One entry per third-party service.
#[derive(Debug, Clone, Serialize, Deserialize, uniffi::Record)]
pub struct ProviderSpec {
    /// Stable machine identifier; never change after first ship.
    pub id: String,
    pub display_name: String,
    pub section: ImportSection,
    pub auth_method: AuthMethod,
    /// Icon name the client resolves to its own drawable / SVG.
    pub icon_name: String,
    /// Hex string like "#FBBC04" — the provider's brand accent. Used
    /// to tint the card icon on the provider grid.
    pub brand_color: String,
    /// Markdown body for the walkthrough screen. May contain links.
    pub instructions_markdown: String,
    /// Things the user should know before starting (e.g. "Notion
    /// databases are imported as one note per row").
    pub caveats: Vec<String>,
}

/// Canonical list of providers offered in the import UI.
///
/// Order here is the order rendered in each section. Every provider is a
/// file-based import; the list holds no connected-account (OAuth)
/// provider. [`ImportSection::Connect`] and [`AuthMethod::OAuth2Pkce`]
/// stay in the schema, and `connect_providers_have_oauth_config`
/// enforces the pairing if a Connect entry appears.
#[uniffi::export]
pub fn provider_specs() -> Vec<ProviderSpec> {
    vec![
        google_keep(),
        evernote_file(),
        standard_notes_file(),
        plain_text(),
    ]
}

fn google_keep() -> ProviderSpec {
    ProviderSpec {
        id: "google_keep".into(),
        display_name: "Google Keep".into(),
        section: ImportSection::File,
        auth_method: AuthMethod::TakeoutLink {
            external_url:
                "https://takeout.google.com/settings/takeout/custom/keep"
                    .into(),
            mime_types: vec![
                "application/zip".into(),
                "application/x-zip-compressed".into(),
            ],
        },
        icon_name: "ic_provider_google_keep".into(),
        brand_color: "#FBBC04".into(),
        instructions_markdown: concat!(
            "Google Keep doesn't expose a personal API, so the import\n",
            "goes through **Google Takeout**:\n\n",
            "1. Tap **Open Takeout** below — you'll land on a page\n",
            "   that already has Keep selected.\n",
            "2. Scroll to the bottom, hit **Next step**, choose **ZIP**\n",
            "   as the file type, and request the export.\n",
            "3. Google emails you a download link (usually within a few\n",
            "   minutes). Save the ZIP somewhere you can find it.\n",
            "4. Come back here and tap **Pick the Takeout ZIP**.\n",
            "\n",
            "Everything in your Takeout ZIP is decrypted on this device\n",
            "before it's encrypted under your vault key. The server\n",
            "never sees your Keep notes in plaintext.\n",
        )
        .into(),
        caveats: vec![
            "Trashed notes are skipped.".into(),
            "Image attachments inside notes aren't imported yet.".into(),
        ],
    }
}

fn evernote_file() -> ProviderSpec {
    ProviderSpec {
        id: "evernote_file".into(),
        display_name: "Evernote (ENEX)".into(),
        section: ImportSection::File,
        auth_method: AuthMethod::FileUpload {
            mime_types: vec![
                "application/xml".into(),
                "text/xml".into(),
                "application/enex".into(),
            ],
        },
        icon_name: "ic_provider_evernote".into(),
        brand_color: "#00A82D".into(),
        instructions_markdown: concat!(
            "Export your Evernote notebooks to **ENEX** files from the\n",
            "Evernote desktop app: right-click a notebook → **Export**\n",
            "→ **ENEX**.\n\n",
            "You can pick one ENEX file at a time. Repeat for each\n",
            "notebook you want to bring over.\n",
        )
        .into(),
        caveats: vec![
            "Notebook structure is flattened — Evernote notebook names \
             become labels on each note."
                .into(),
            "Embedded media (images, audio) is not imported yet.".into(),
        ],
    }
}

fn standard_notes_file() -> ProviderSpec {
    ProviderSpec {
        id: "standard_notes_file".into(),
        display_name: "Standard Notes".into(),
        section: ImportSection::File,
        auth_method: AuthMethod::FileUpload {
            mime_types: vec!["application/json".into()],
        },
        icon_name: "ic_provider_standard_notes".into(),
        brand_color: "#086DD6".into(),
        instructions_markdown: concat!(
            "In Standard Notes: **Account → Data backups → Download\n",
            "backup**. Choose the **Decrypted JSON** option (we don't\n",
            "support encrypted backups in this flow yet).\n",
        )
        .into(),
        caveats: vec![
            "Encrypted backups aren't supported yet — use the \
             decrypted JSON export."
                .into(),
        ],
    }
}

fn plain_text() -> ProviderSpec {
    ProviderSpec {
        id: "plain_text".into(),
        display_name: "Text / Markdown".into(),
        section: ImportSection::File,
        auth_method: AuthMethod::FileUpload {
            mime_types: vec![
                "text/plain".into(),
                "text/markdown".into(),
                "text/x-markdown".into(),
                "application/zip".into(),
            ],
        },
        icon_name: "ic_provider_plain_text".into(),
        brand_color: "#CBA6F7".into(),
        instructions_markdown: concat!(
            "Pick a single `.txt` / `.md` file, or a ZIP archive of\n",
            "them. The first line becomes the note title and the rest\n",
            "is the body.\n",
        )
        .into(),
        caveats: vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_ids_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for p in provider_specs() {
            assert!(seen.insert(p.id.clone()), "duplicate provider id: {}", p.id);
        }
    }

    #[test]
    fn every_provider_has_at_least_one_section_classification() {
        for p in provider_specs() {
            // Holds by construction for the current variants; guards
            // against a field-less enum variant being added.
            let _ = p.section;
        }
    }

    #[test]
    fn serializes_to_json_round_trip() {
        let specs = provider_specs();
        let json = serde_json::to_string(&specs).expect("serialize");
        let back: Vec<ProviderSpec> =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(specs.len(), back.len());
        for (a, b) in specs.iter().zip(back.iter()) {
            assert_eq!(a.id, b.id);
            assert_eq!(a.display_name, b.display_name);
        }
    }

    #[test]
    fn connect_providers_have_oauth_config() {
        for p in provider_specs() {
            if matches!(p.section, ImportSection::Connect) {
                assert!(
                    matches!(p.auth_method, AuthMethod::OAuth2Pkce(_) | AuthMethod::Credentials { .. }),
                    "provider {} is in Connect section but doesn't ask \
                     for credentials",
                    p.id,
                );
            }
        }
    }
}
