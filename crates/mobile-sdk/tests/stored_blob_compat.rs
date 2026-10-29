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

//! The key store across SDK versions. A store blob written by an earlier SDK
//! reads whole and is written back whole, and a blob that doesn't decode is an
//! error that keeps every write away from it, never an empty state a later
//! persist writes over the stored copy.
//!
//! The fixtures (`store_written_by_*.json`) were WRITTEN by two earlier SDK
//! versions, the second later than the first, each from its own source with a
//! dump test.
//! - Both hold a legacy circle with two members' keys pinned, the identity key
//!   and the signing seed.
//! - The later one also holds a recorded circle (its genesis: head, facts,
//!   anchor, history, S) and a circle a head latched with no record held.
//! Test keys only: they belong to no account.

use pingolin_mobile::{CryptoManager, KeyStorageCallback, KeyStoreLoad, MobileError, PinRecord, PinState, StorageCallbackError, StoredKeyData};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
struct Mem(Arc<Mutex<Option<StoredKeyData>>>);

impl KeyStorageCallback for Mem {
    fn store_keys(&self, data: StoredKeyData) -> Result<(), StorageCallbackError> {
        *self.0.lock().unwrap() = Some(data);
        Ok(())
    }
    fn load_keys(&self) -> Result<Option<StoredKeyData>, StorageCallbackError> {
        Ok(self.0.lock().unwrap().clone())
    }
    fn delete_keys(&self) -> Result<(), StorageCallbackError> {
        *self.0.lock().unwrap() = None;
        Ok(())
    }
}

impl Mem {
    fn holding(data: StoredKeyData) -> Self {
        Mem(Arc::new(Mutex::new(Some(data))))
    }
    fn held(&self) -> StoredKeyData {
        self.0.lock().unwrap().clone().expect("something stored")
    }
}

fn fixture(sdk: &str) -> (StoredKeyData, Value) {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data");
    let data = serde_json::from_str(&std::fs::read_to_string(format!("{dir}/store_written_by_{sdk}.json")).unwrap()).unwrap();
    let expect = serde_json::from_str(&std::fs::read_to_string(format!("{dir}/store_written_by_{sdk}.expect.json")).unwrap()).unwrap();
    (data, expect)
}

fn manager_on(store: &Mem) -> Arc<CryptoManager> {
    let cm = CryptoManager::new();
    cm.register_secure_storage(Box::new(store.clone()));
    cm
}

fn pins_of(data: &StoredKeyData) -> HashMap<String, PinRecord> {
    serde_json::from_str(data.pinned_keys_json.as_deref().expect("a pins blob")).unwrap()
}

fn json(text: &str) -> Value {
    serde_json::from_str(text).unwrap()
}

/// Everything the fixture's SDK stored is there once loaded.
fn holds_everything(cm: &CryptoManager, data: &StoredKeyData, expect: &Value) {
    assert_eq!(cm.export_public_key().unwrap(), expect["own_public_key"].as_str().unwrap());
    assert_eq!(cm.signing_public_key_hex().unwrap(), expect["signing_public_key_hex"].as_str().unwrap());
    let legacy = expect["legacy_circle"].as_str().unwrap().to_string();
    assert!(cm.has_circle_key(legacy.clone()));
    assert_eq!(cm.get_active_version(legacy.clone()).unwrap(), 1);
    // Each pinned member's keys still match their pin.
    for (key, record) in pins_of(data).iter().filter(|(key, _)| key.starts_with(&legacy)) {
        let user = key.rsplit(':').next().unwrap().to_string();
        let result = cm
            .pin_member_keys(legacy.clone(), user, record.sharing_pubkey_hex.clone(), record.signing_pubkey_hex.clone())
            .unwrap();
        assert!(matches!(result.state, PinState::Matched), "{key}: {:?}", result.state);
    }
    if let Some(recorded) = expect["recorded_circle"].as_str() {
        assert!(cm.circle_has_refresh_records(recorded.to_string()));
        assert_eq!(cm.get_active_version(recorded.to_string()).unwrap(), 1, "its genesis, accepted and sealed under");
    }
    if let Some(latched) = expect["latched_circle"].as_str() {
        assert!(cm.circle_has_refresh_records(latched.to_string()), "the latch");
        assert!(cm.get_active_version(latched.to_string()).is_err(), "nothing sealed");
    }
}

/// Load `sdk`'s blob, write it back at once, and compare: nothing lost or
/// changed. Then everything is there, before and after a reload of the
/// written copy.
fn reads_and_writes_back_whole(sdk: &str) {
    let (data, expect) = fixture(sdk);
    let store = Mem::holding(data.clone());
    let cm = manager_on(&store);
    assert!(cm.load_persisted_keys().unwrap());
    cm.persist_keys().unwrap();
    let written = store.held();
    // Compared without printing: the three hold (test) secrets.
    assert!(written.private_key == data.private_key, "the identity key changed");
    assert!(written.signing_private_key_b64 == data.signing_private_key_b64, "the signing seed changed");
    assert!(json(&written.circle_keys_json) == json(&data.circle_keys_json), "the circle keys changed");
    let (before, after) = (pins_of(&data), pins_of(&written));
    for (key, record) in &before {
        let kept = after.get(key).unwrap_or_else(|| panic!("{key} lost"));
        assert_eq!(serde_json::to_value(kept).unwrap(), serde_json::to_value(record).unwrap(), "{key}");
    }
    // Added on read, for a store written before them: each stored
    // fact's keyed parts (`~rrk:`), bound to the fact and
    // fail-closed (an inclusion only if the fact is one, spent at
    // its version).
    let added: Vec<&String> = after.keys().filter(|key| !before.contains_key(*key)).collect();
    assert_eq!(added.len(), before.keys().filter(|key| key.starts_with("~rrm:")).count(), "{added:?}");
    for key in added {
        let fact = &before[&key.replacen("~rrk:", "~rrm:", 1)];
        let keyed = &after[key];
        let included = (fact.last_verified_at >> 4) & 0xf == 1;
        assert_eq!(
            (keyed.first_pinned_at, &keyed.signing_pubkey_hex, keyed.last_verified_at, keyed.user_approved_change_at),
            (fact.first_pinned_at, &fact.signing_pubkey_hex, fact.first_pinned_at, Some(if included { fact.first_pinned_at } else { 0 })),
            "{key}"
        );
    }
    holds_everything(&cm, &data, &expect);
    let reloaded = manager_on(&store);
    assert!(reloaded.load_persisted_keys().unwrap());
    holds_everything(&reloaded, &data, &expect);
}

#[test]
fn a_store_written_by_the_earlier_sdk_reads_whole_and_is_written_back_whole() {
    reads_and_writes_back_whole("the_earlier_sdk");
}

#[test]
fn a_store_written_by_the_later_sdk_reads_whole_and_is_written_back_whole() {
    reads_and_writes_back_whole("the_later_sdk");
}

/// A blob that doesn't decode: the load errors, no persist writes over it
/// (not even with keys imported since), and a successful load or clearing the
/// keys lifts that.
fn undecodable(garble: impl Fn(&mut StoredKeyData)) {
    let (mut data, _) = fixture("the_later_sdk");
    garble(&mut data);
    let store = Mem::holding(data.clone());
    let cm = manager_on(&store);
    assert!(cm.load_persisted_keys().is_err());
    cm.generate_keypair();
    assert!(cm.persist_keys().is_err(), "never written over");
    let held = store.held();
    assert!(
        (held.private_key, held.circle_keys_json, held.pinned_keys_json)
            == (data.private_key.clone(), data.circle_keys_json.clone(), data.pinned_keys_json.clone()),
        "written over"
    );
    cm.clear_all_keys();
    cm.generate_keypair();
    cm.persist_keys().unwrap();
}

#[test]
fn an_undecodable_pins_blob_is_an_error_and_never_written_over() {
    undecodable(|data| data.pinned_keys_json = Some("{\"b1b1\": {\"cut short".into()));
}

#[test]
fn an_undecodable_circle_keys_blob_is_an_error_and_never_written_over() {
    undecodable(|data| data.circle_keys_json = "[".into());
}

#[test]
fn an_undecodable_identity_key_is_an_error_and_never_written_over() {
    undecodable(|data| data.private_key = "not base64!".into());
}

#[test]
fn a_store_that_turns_up_undecodable_before_the_first_write_is_never_written_over() {
    // Nothing was stored at load (as a keychain before its first unlock can
    // report). By the first write the store holds this identity's blob with
    // circle keys that don't decode, or a blob whose identity key doesn't: an
    // error, never "another identity" to replace.
    let (fixture_data, _) = fixture("the_later_sdk");
    let identity = fixture_data.private_key.clone();
    for garble in [
        (|data: &mut StoredKeyData| data.circle_keys_json = "[".into()) as fn(&mut StoredKeyData),
        |data: &mut StoredKeyData| data.private_key = "not base64!".into(),
    ] {
        let store = Mem::default();
        let cm = manager_on(&store);
        assert!(!cm.load_persisted_keys().unwrap());
        let mut data = fixture_data.clone();
        garble(&mut data);
        *store.0.lock().unwrap() = Some(data.clone());
        let _ = cm.import_private_key(identity.clone());
        assert!(cm.persist_keys().is_err());
        let held = store.held();
        assert!((held.private_key, held.circle_keys_json) == (data.private_key.clone(), data.circle_keys_json.clone()), "written over");
        assert!(cm.persist_keys().is_err(), "still refused");
    }
}

/// Stored signing seeds that don't install: not base64, and base64 of neither
/// 32 nor 64 bytes.
const SEEDS_THAT_DONT_INSTALL: [&str; 2] = ["not base64!", "AAAA"];

/// The later fixture's store with `seed` as its seed, loaded.
fn loaded_with_seed(seed: &str) -> (Mem, Arc<CryptoManager>) {
    let (mut data, _) = fixture("the_later_sdk");
    data.signing_private_key_b64 = Some(seed.into());
    let store = Mem::holding(data);
    let cm = manager_on(&store);
    assert!(cm.load_persisted_keys().unwrap(), "the rest of the store loads");
    (store, cm)
}

fn stored_seed(store: &Mem) -> Option<String> {
    store.held().signing_private_key_b64
}

#[test]
fn a_stored_seed_that_doesnt_install_is_written_back_unchanged_until_one_is_imported() {
    for seed in SEEDS_THAT_DONT_INSTALL {
        let (store, cm) = loaded_with_seed(seed);
        assert!(cm.signing_public_key_hex().is_err(), "{seed}: runs without a signing key");
        cm.persist_keys().unwrap();
        assert!(stored_seed(&store).as_deref() == Some(seed), "{seed}: written back as stored");
        // And by a process that loads what was written.
        let reloaded = manager_on(&store);
        assert!(reloaded.load_persisted_keys().unwrap());
        reloaded.persist_keys().unwrap();
        assert!(stored_seed(&store).as_deref() == Some(seed), "{seed}: again");
        // An import replaces it.
        let imported = CryptoManager::new().generate_signing_keypair().secret_seed_b64;
        reloaded.import_signing_private_key(imported.clone()).unwrap();
        assert!(stored_seed(&store) == Some(imported), "{seed}: the imported seed");
        // So does a seed generated here.
        let (store, cm) = loaded_with_seed(seed);
        let generated = cm.generate_signing_keypair().secret_seed_b64;
        assert!(stored_seed(&store) == Some(generated), "{seed}: the generated seed");
    }
}

#[test]
fn a_stored_seed_that_doesnt_install_goes_back_only_with_its_own_identity() {
    for seed in SEEDS_THAT_DONT_INSTALL {
        let (store, cm) = loaded_with_seed(seed);
        let identity = store.held().private_key;
        // Another identity in its place: none of the first one's seed.
        cm.generate_keypair();
        assert!(store.held().private_key != identity);
        assert!(stored_seed(&store).is_none(), "{seed}: not written with another identity");
        // Cleared: nothing kept, for any identity.
        let (store, cm) = loaded_with_seed(seed);
        cm.clear_all_keys();
        cm.import_private_key(identity.clone()).unwrap();
        assert!(store.held().private_key == identity);
        assert!(stored_seed(&store).is_none(), "{seed}: dropped with the keys");
    }
}

#[test]
fn the_first_write_keeps_a_stored_seed_that_doesnt_install() {
    // Nothing was stored at load; by the first write the store holds this
    // identity's blob with a seed that doesn't install. The write keeps it.
    for seed in SEEDS_THAT_DONT_INSTALL {
        let (mut data, _) = fixture("the_later_sdk");
        data.signing_private_key_b64 = Some(seed.into());
        let store = Mem::default();
        let cm = manager_on(&store);
        assert!(!cm.load_persisted_keys().unwrap());
        *store.0.lock().unwrap() = Some(data.clone());
        cm.import_private_key(data.private_key.clone()).unwrap();
        assert!(stored_seed(&store).as_deref() == Some(seed), "{seed}: kept at the first write");
        assert!(cm.signing_public_key_hex().is_err());
        cm.persist_keys().unwrap();
        assert!(stored_seed(&store).as_deref() == Some(seed), "{seed}: and after it");
    }
}

/// A store whose platform read fails.
struct ReadFails;

impl KeyStorageCallback for ReadFails {
    fn store_keys(&self, _: StoredKeyData) -> Result<(), StorageCallbackError> {
        panic!("written over a store that couldn't be read");
    }
    fn load_keys(&self) -> Result<Option<StoredKeyData>, StorageCallbackError> {
        Err(StorageCallbackError::Failed)
    }
    fn delete_keys(&self) -> Result<(), StorageCallbackError> {
        Ok(())
    }
}

fn status(cm: &CryptoManager) -> (KeyStoreLoad, bool, bool) {
    let status = cm.key_store_status();
    (status.load, status.signing_seed_unreadable, status.entries_unreadable)
}

/// `key_store_status` says what the last load found, and whether a seed or
/// other entries that didn't read are kept.
#[test]
fn the_key_store_status_says_what_the_load_found() {
    use KeyStoreLoad::*;
    assert_eq!(status(&CryptoManager::new()), (NotLoaded, false, false));
    let empty = manager_on(&Mem::default());
    assert!(!empty.load_persisted_keys().unwrap());
    assert_eq!(status(&empty), (NothingStored, false, false));

    let (data, _) = fixture("the_later_sdk");
    let loaded = manager_on(&Mem::holding(data.clone()));
    assert!(loaded.load_persisted_keys().unwrap());
    assert_eq!(status(&loaded), (Loaded, false, false));

    let unreadable = CryptoManager::new();
    unreadable.register_secure_storage(Box::new(ReadFails));
    assert!(unreadable.load_persisted_keys().is_err());
    assert_eq!(status(&unreadable), (ReadFailed, false, false));

    let mut garbled = data.clone();
    garbled.pinned_keys_json = Some("{\"cut short".into());
    let undecodable = manager_on(&Mem::holding(garbled));
    assert!(undecodable.load_persisted_keys().is_err());
    assert_eq!(status(&undecodable), (DoesNotDecode, false, false));
    // Found at the first write's re-read too.
    let (store, late) = (Mem::default(), CryptoManager::new());
    late.register_secure_storage(Box::new(store.clone()));
    assert!(!late.load_persisted_keys().unwrap());
    let mut garbled = data.clone();
    garbled.circle_keys_json = "[".into();
    *store.0.lock().unwrap() = Some(garbled);
    let _ = late.import_private_key(data.private_key.clone());
    assert_eq!(status(&late).0, DoesNotDecode);

    // A seed that doesn't install, then an import.
    let (_, seedless) = loaded_with_seed("AAAA");
    assert_eq!(status(&seedless), (Loaded, true, false));
    seedless.import_signing_private_key(CryptoManager::new().generate_signing_keypair().secret_seed_b64).unwrap();
    assert_eq!(status(&seedless), (Loaded, false, false));

    // An entry that doesn't read: a circle mark.
    let mut pins = pins_of(&data);
    let mark = pins.values().next().unwrap().clone();
    pins.insert("~ctrust:not a mark".into(), mark);
    let mut marked = data.clone();
    marked.pinned_keys_json = Some(serde_json::to_string(&pins).unwrap());
    let with_entry = manager_on(&Mem::holding(marked));
    assert!(with_entry.load_persisted_keys().unwrap());
    assert_eq!(status(&with_entry), (Loaded, false, true));

    // Cleared: known (nothing), nothing kept.
    for cm in [&unreadable, &undecodable, &seedless, &with_entry] {
        cm.clear_all_keys();
        assert_eq!(status(cm), (Loaded, false, false));
    }
}

/// While the store can't be read, this device doesn't know what it holds:
/// nobody is taken on first contact, every circle counts as having
/// records, and no pins are exported. Clearing the keys ends it. Here a
/// reload (keys held from the first load) finds the store doesn't decode.
#[test]
fn while_the_store_cant_be_read_nothing_is_taken_on_first_contact_and_every_circle_waits() {
    use pingolin_mobile::EligibilityPurpose;
    let (data, expect) = fixture("the_later_sdk");
    let legacy = expect["legacy_circle"].as_str().unwrap().to_string();
    let pinned = expect["pinned_users"][0].as_str().unwrap().to_string();
    let stranger = "e5e5e5e5-5555-4555-8555-555555555555".to_string();
    let store = Mem::holding(data.clone());
    let cm = manager_on(&store);
    assert!(cm.load_persisted_keys().unwrap());
    let pin_of = |user: &str| pins_of(&data).get(&format!("{legacy}:{user}")).cloned().expect("pinned");
    let a_key = || "ab".repeat(32);
    // Readable: first contact, a legacy circle seals, the pins export.
    assert_eq!(cm.get_active_version(legacy.clone()).unwrap(), 1);
    assert!(!cm.circle_has_refresh_records(legacy.clone()));
    assert!(cm.export_member_pins(pinned.clone()).is_ok());

    let mut garbled = data.clone();
    garbled.pinned_keys_json = Some("{\"cut short".into());
    *store.0.lock().unwrap() = Some(garbled);
    assert!(cm.load_persisted_keys().is_err());
    assert_eq!(cm.key_store_status().load, KeyStoreLoad::DoesNotDecode);

    // No first contact; a held pin still matches.
    let refused = cm.pin_member_keys(legacy.clone(), stranger.clone(), a_key(), a_key());
    assert!(matches!(refused, Err(MobileError::StorageError(_))), "{refused:?}");
    let known = pin_of(&pinned);
    assert!(matches!(
        cm.pin_member_keys(legacy.clone(), pinned.clone(), known.sharing_pubkey_hex, known.signing_pubkey_hex).unwrap().state,
        PinState::Matched
    ));
    // Every circle counts as having records: nothing seals, delivers or rotates.
    assert!(cm.circle_has_refresh_records(legacy.clone()));
    assert!(cm.get_active_version(legacy.clone()).is_err());
    assert!(matches!(
        cm.refresh_eligibility(legacy.clone(), vec![], EligibilityPurpose::Deliver),
        Err(MobileError::StorageError(_))
    ));
    assert!(matches!(
        cm.prepare_key_rotation(legacy.clone(), pinned.clone(), vec![], vec![], vec![], String::new()),
        Err(MobileError::StorageError(_))
    ));
    assert!(matches!(cm.create_key_chain_link(legacy.clone()), Err(MobileError::StorageError(_))));
    assert!(matches!(
        cm.import_key_chain_link(legacy.clone(), 2, 1, "00".repeat(48), "00".repeat(24)),
        Err(MobileError::InvalidInput(ref why)) if why.contains("can't be read")
    ));
    assert!(matches!(
        cm.finalize_circle_creation("temp_x".into(), "f6f6f6f6-6666-4666-8666-666666666666".into()),
        Err(MobileError::StorageError(_))
    ));
    assert!(matches!(
        cm.prepare_recorded_circle_creation(pinned.clone(), "a7a7a7a7-7777-4777-8777-777777777777".into()),
        Err(MobileError::StorageError(ref why)) if why.contains("can't be told")
    ));
    assert!(!cm.has_circle_key("a7a7a7a7-7777-4777-8777-777777777777".into()), "nothing created");
    // The personal key slots are no circles: they count as nothing of the kind.
    assert!(!cm.circle_has_refresh_records("00000000-0000-0000-0000-000000000000".into()));
    // No pins exported.
    assert!(matches!(cm.export_member_pins(pinned.clone()), Err(MobileError::StorageError(_))));

    // Cleared: a fresh install again.
    cm.clear_all_keys();
    cm.generate_keypair();
    assert!(matches!(
        cm.pin_member_keys(legacy.clone(), stranger, a_key(), a_key()).unwrap().state,
        PinState::NewPinning
    ));
    assert!(!cm.circle_has_refresh_records(legacy));
    assert!(cm.export_member_pins(pinned).is_ok());
}

/// A stored identity key that isn't a key (a half-written store: "" or the
/// wrong length) doesn't decode; it is never "another identity" whose store
/// the next write replaces. At a reload and at the first write's re-read.
#[test]
fn a_stored_identity_that_isnt_a_key_doesnt_decode_and_is_never_written_over() {
    use base64::Engine as _;
    let (data, _) = fixture("the_later_sdk");
    for identity in [String::new(), base64::engine::general_purpose::STANDARD.encode([7u8; 16])] {
        // A reload, with the identity held from the first load.
        let store = Mem::holding(data.clone());
        let cm = manager_on(&store);
        assert!(cm.load_persisted_keys().unwrap());
        let mut half = data.clone();
        half.private_key = identity.clone();
        *store.0.lock().unwrap() = Some(half.clone());
        assert!(cm.load_persisted_keys().is_err());
        assert_eq!(cm.key_store_status().load, KeyStoreLoad::DoesNotDecode);
        assert!(cm.persist_keys().is_err());
        assert!(store.held().circle_keys_json == half.circle_keys_json, "never written over");
        // The first write's re-read (nothing stored at load).
        let store = Mem::default();
        let cm = manager_on(&store);
        assert!(!cm.load_persisted_keys().unwrap());
        *store.0.lock().unwrap() = Some(half.clone());
        let _ = cm.import_private_key(data.private_key.clone());
        assert_eq!(cm.key_store_status().load, KeyStoreLoad::DoesNotDecode);
        assert!(store.held().circle_keys_json == half.circle_keys_json, "never written over");
    }
}

fn circle_keys_of(data: &StoredKeyData) -> HashMap<String, HashMap<String, String>> {
    serde_json::from_str(&data.circle_keys_json).unwrap()
}

/// `drop_unreadable_entries`: the entries that didn't read go, and only
/// those; everything else is written back as it was. A circle whose record
/// state didn't read keeps its latch alone. A store with nothing unreadable
/// is untouched, and a store that can't be read refuses.
#[test]
fn dropping_the_unreadable_entries_takes_them_and_only_them() {
    let (data, expect) = fixture("the_later_sdk");
    let legacy = expect["legacy_circle"].as_str().unwrap().to_string();
    let recorded = expect["recorded_circle"].as_str().unwrap().to_string();
    let some_pin = pins_of(&data).values().next().unwrap().clone();

    // A mark, a key, and a circle's record state that don't read.
    let mut mark = data.clone();
    let mut pins = pins_of(&data);
    pins.insert("~ctrust:not a mark".into(), some_pin.clone());
    mark.pinned_keys_json = Some(serde_json::to_string(&pins).unwrap());
    let mut key = data.clone();
    let mut keys = circle_keys_of(&data);
    keys.get_mut(&legacy).unwrap().insert("9".into(), "AAAA".into());
    key.circle_keys_json = serde_json::to_string(&keys).unwrap();
    let mut state = data.clone();
    let mut pins = pins_of(&data);
    let fact = pins.keys().find(|k| k.starts_with(&format!("~rrm:{recorded}:"))).unwrap().clone();
    pins.get_mut(&fact).unwrap().sharing_pubkey_hex = "zz".into();
    state.pinned_keys_json = Some(serde_json::to_string(&pins).unwrap());

    for (stored, what) in [(mark, "mark"), (key, "key"), (state, "record state")] {
        let store = Mem::holding(stored.clone());
        let cm = manager_on(&store);
        assert!(cm.load_persisted_keys().unwrap());
        assert!(cm.key_store_status().entries_unreadable, "{what}");
        let dropped = cm.drop_unreadable_entries().unwrap();
        assert!(!cm.key_store_status().entries_unreadable, "{what}");
        let written = store.held();
        let (before, after) = (pins_of(&stored), pins_of(&written));
        match what {
            "mark" => {
                assert_eq!(dropped, 1);
                assert!(!after.contains_key("~ctrust:not a mark"));
            }
            "key" => {
                assert_eq!(dropped, 1);
                assert!(circle_keys_of(&written) == circle_keys_of(&data), "only that key went");
            }
            _ => {
                let of_circle = |pins: &HashMap<String, PinRecord>| {
                    pins.keys().filter(|k| k.starts_with("~rr") && k.contains(&recorded)).cloned().collect::<Vec<_>>()
                };
                assert_eq!(dropped as usize, of_circle(&before).len());
                assert_eq!(of_circle(&after), vec![format!("~rrh:{recorded}")], "its latch alone");
                assert!(cm.circle_has_refresh_records(recorded.clone()));
            }
        }
        // Every other entry went back as it was.
        for (k, record) in before.iter().filter(|(k, _)| k.as_str() != "~ctrust:not a mark" && !(k.starts_with("~rr") && k.contains(&recorded) && what == "record state")) {
            let kept = after.get(k).unwrap_or_else(|| panic!("{what}: {k} lost"));
            assert_eq!(serde_json::to_value(kept).unwrap(), serde_json::to_value(record).unwrap(), "{what}: {k}");
        }
        if what != "key" {
            // The waiting circle's secret was set aside at the load (it has no
            // anchor to belong to, and is derived again).
            let mut expected = circle_keys_of(&stored);
            if what == "record state" {
                assert!(expected.remove(&format!("~rrs:{recorded}")).is_some());
            }
            assert!(circle_keys_of(&written) == expected, "{what}: circle keys as they were");
        }
        assert!(written.private_key == stored.private_key && written.signing_private_key_b64 == stored.signing_private_key_b64);
    }

    // Nothing unreadable: nothing dropped, nothing written.
    let store = Mem::holding(data.clone());
    let cm = manager_on(&store);
    assert!(cm.load_persisted_keys().unwrap());
    *store.0.lock().unwrap() = None;
    assert_eq!(cm.drop_unreadable_entries().unwrap(), 0);
    assert!(store.0.lock().unwrap().is_none(), "no write");

    // A store that can't be read: refused.
    let unreadable = CryptoManager::new();
    unreadable.register_secure_storage(Box::new(ReadFails));
    assert!(unreadable.load_persisted_keys().is_err());
    assert!(matches!(unreadable.drop_unreadable_entries(), Err(MobileError::StorageError(_))));
}

/// A store whose delete can be made to fail.
#[derive(Clone, Default)]
struct DeleteFails(Mem, Arc<std::sync::atomic::AtomicBool>);

impl KeyStorageCallback for DeleteFails {
    fn store_keys(&self, data: StoredKeyData) -> Result<(), StorageCallbackError> {
        self.0.store_keys(data)
    }
    fn load_keys(&self) -> Result<Option<StoredKeyData>, StorageCallbackError> {
        self.0.load_keys()
    }
    fn delete_keys(&self) -> Result<(), StorageCallbackError> {
        if self.1.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(StorageCallbackError::Failed);
        }
        self.0.delete_keys()
    }
}

/// A clear whose platform delete fails: memory is cleared, the status says
/// `DeleteFailed`, and nothing is written or loaded until a clear succeeds,
/// so what the store still holds is never merged back nor mixed with a new
/// sign-in's keys.
#[test]
fn a_clear_whose_delete_fails_writes_and_loads_nothing_until_a_clear_succeeds() {
    let (data, _) = fixture("the_later_sdk");
    let store = DeleteFails(Mem::holding(data.clone()), Arc::default());
    let cm = CryptoManager::new();
    cm.register_secure_storage(Box::new(store.clone()));
    assert!(cm.load_persisted_keys().unwrap());
    store.1.store(true, std::sync::atomic::Ordering::SeqCst);
    cm.clear_all_keys();
    assert_eq!(cm.key_store_status().load, KeyStoreLoad::DeleteFailed);
    assert!(cm.export_public_key().is_err(), "memory is cleared");
    // A sign-in meanwhile: its keys stay in memory; nothing is written.
    cm.generate_keypair();
    assert!(matches!(cm.persist_keys(), Err(MobileError::StorageError(_))));
    assert!(store.0.held().private_key == data.private_key, "the store is as it was");
    // Nor is the store loaded back.
    let fresh_identity = cm.export_public_key().unwrap();
    assert!(matches!(cm.load_persisted_keys(), Err(MobileError::StorageError(_))));
    assert!(cm.export_public_key().unwrap() == fresh_identity && !cm.has_circle_key("b1b1b1b1-1111-4111-8111-111111111111".into()));
    // The wipe owed: a clear that succeeds ends it.
    store.1.store(false, std::sync::atomic::Ordering::SeqCst);
    cm.clear_all_keys();
    assert_eq!(cm.key_store_status().load, KeyStoreLoad::Loaded);
    assert!(store.0 .0.lock().unwrap().is_none(), "deleted");
    cm.generate_keypair();
    cm.persist_keys().unwrap();
    assert!(store.0 .0.lock().unwrap().is_some());
}
