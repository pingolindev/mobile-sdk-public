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

//! Packed binary encoding for the LOCATION PLAINTEXT — the bytes handed to the
//! AEAD on every location write, and the bytes it returns on every read.
//!
//! # Why
//!
//! The legacy plaintext is `serde_json::to_string(&location)` — a ~170-230
//! byte JSON document for nine small numeric fields, where the field NAMES are
//! ~40% of the bytes and every f64 is spelled out in decimal. The packed form is
//! 18-35 bytes. This module touches only the plaintext bytes, never a key, a
//! nonce, or an AAD.
//!
//! # Wire layout (format version 1, magic `0xB1`)
//!
//! ```text
//!   off  size  field
//!   ---  ----  ---------------------------------------------------------------
//!    0    1    magic/format version: 0xB1
//!    1    1    presence bitmap (see FLAG_* below)
//!    2    4    latitude   i32 LE, degrees x 1e7
//!    6    4    longitude  i32 LE, degrees x 1e7
//!   10    8    timestamp  i64 LE, Unix milliseconds
//!   18   ...   present optional fields, in THIS order, nothing for absent ones:
//!               altitude  f32 LE (4)   if FLAG_ALTITUDE
//!               speed     f32 LE (4)   if FLAG_SPEED
//!               heading   f32 LE (4)   if FLAG_HEADING
//!               accuracy  f32 LE (4)   if FLAG_ACCURACY
//!               battery   u8     (1)   if FLAG_BATTERY
//!               is_charging carries NO payload — its value is FLAG_IS_CHARGING_VALUE
//! ```
//!
//! Minimum 18 bytes (no optionals), maximum 35 bytes (all present).
//!
//! # Why these representations
//!
//! * **latitude/longitude as i32 at 1e-7 degrees.** One unit is ~1.1 cm at the
//!   equator, four orders of magnitude finer than the best consumer GPS fix, and
//!   it is the same fixed-point grid Android's `Location` and NMEA already use.
//!   i32 spans +/-214.7 degrees, so every legal coordinate fits with room to
//!   spare. Round-tripping a value that already sits on the 1e-7 grid is EXACT
//!   (see `latlon_round_trip_is_exact_on_the_grid`); anything else moves by at
//!   most 5e-8 degrees (~5.5 mm), which no user can see.
//! * **timestamp as a plain i64 LE.** A varint would save 2 bytes and buy a
//!   cross-language parity risk for no real gain.
//! * **altitude/speed/heading/accuracy as f32.** ~7 significant decimal digits,
//!   which is far beyond what any of these sensors resolve, and — unlike a
//!   per-field fixed-point scheme — needs no range cap, no saturation rule and no
//!   unit negotiation between Rust and JavaScript. `as f32` in Rust and
//!   `DataView.setFloat32` in JS are both IEEE-754 round-to-nearest-even, so they
//!   agree bit for bit.
//! * **A presence bitmap, not sentinels.** `is_charging` needs three states
//!   (absent / false / true) and gets two bits, costing no payload byte at all.
//!
//! # Cross-language parity
//!
//! The web client has a TypeScript twin of this codec. Both assert the SAME
//! locked vectors — `VECTOR_A_HEX` / `VECTOR_B_HEX` below and the matching
//! constants on the web side. If either side drifts, a location written on one
//! client becomes unreadable on the other, so those tests are the guard.
//!
//! One subtlety worth stating out loud: Rust's `f64::round` rounds half AWAY FROM
//! ZERO while JavaScript's `Math.round` rounds half toward +infinity, so they
//! disagree at exact .5 boundaries on negative numbers. The TypeScript side
//! therefore implements half-away-from-zero explicitly rather than calling
//! `Math.round` directly.
//!
//! # Reading older rows
//!
//! `decode_location` accepts BOTH forms. A payload starting with `0xB1` is
//! packed; anything else is parsed as the legacy UTF-8 JSON document. `0xB1` is a
//! UTF-8 continuation byte, so it can never begin a well-formed UTF-8 string —
//! the two forms cannot be confused in either direction.

use crate::types::{Location, MobileError};

/// Format version / magic for the packed encoding. A future layout change takes
/// the next value (0xB2) and decoders accept the set they know.
pub(crate) const PACKED_MAGIC_V1: u8 = 0xB1;

/// Fixed header: magic + bitmap + lat + lon + timestamp.
const HEADER_LEN: usize = 18;

/// Header plus every optional field present.
const MAX_PACKED_LEN: usize = HEADER_LEN + 4 + 4 + 4 + 4 + 1;

const FLAG_ALTITUDE: u8 = 0b0000_0001;
const FLAG_SPEED: u8 = 0b0000_0010;
const FLAG_HEADING: u8 = 0b0000_0100;
const FLAG_ACCURACY: u8 = 0b0000_1000;
const FLAG_BATTERY: u8 = 0b0001_0000;
const FLAG_IS_CHARGING: u8 = 0b0010_0000;
const FLAG_IS_CHARGING_VALUE: u8 = 0b0100_0000;
/// Must be zero. Reserved so a future version can extend the bitmap without a
/// silent misparse by a decoder that predates the extension.
const FLAG_RESERVED: u8 = 0b1000_0000;

/// Write the packed form. This is the ONLY encoder used on the write path once
/// `PACKED_LOCATION_WRITE_ENABLED` is set in `crypto.rs`.
///
/// Errors only on a non-finite latitude or longitude. The JSON form would
/// serialise a NaN f64 as `null`, which cannot deserialise back into a
/// non-optional `f64`, so such a row would be written successfully and then
/// fail forever on read. Failing at encode surfaces the bad fix at its source
/// instead.
pub(crate) fn encode_location(location: &Location) -> Result<Vec<u8>, MobileError> {
    let lat_e7 = to_e7(location.latitude, 90.0, "latitude")?;
    let lon_e7 = to_e7(location.longitude, 180.0, "longitude")?;

    // A non-finite optional is treated as ABSENT, which is exactly what the JSON
    // encoding did: serde_json wrote NaN/Infinity as `null`, and `null` reads
    // back into `Option<f64>` as `None`.
    let altitude = finite(location.altitude);
    let speed = finite(location.speed);
    let heading = finite(location.heading);
    let accuracy = finite(location.accuracy);

    let mut flags = 0u8;
    if altitude.is_some() {
        flags |= FLAG_ALTITUDE;
    }
    if speed.is_some() {
        flags |= FLAG_SPEED;
    }
    if heading.is_some() {
        flags |= FLAG_HEADING;
    }
    if accuracy.is_some() {
        flags |= FLAG_ACCURACY;
    }
    if location.battery_level.is_some() {
        flags |= FLAG_BATTERY;
    }
    if let Some(charging) = location.is_charging {
        flags |= FLAG_IS_CHARGING;
        if charging {
            flags |= FLAG_IS_CHARGING_VALUE;
        }
    }

    let mut out = Vec::with_capacity(MAX_PACKED_LEN);
    out.push(PACKED_MAGIC_V1);
    out.push(flags);
    out.extend_from_slice(&lat_e7.to_le_bytes());
    out.extend_from_slice(&lon_e7.to_le_bytes());
    out.extend_from_slice(&location.timestamp.to_le_bytes());
    for value in [altitude, speed, heading, accuracy].into_iter().flatten() {
        out.extend_from_slice(&(value as f32).to_le_bytes());
    }
    if let Some(battery) = location.battery_level {
        out.push(battery);
    }
    Ok(out)
}

/// Read a location plaintext in EITHER form: packed (leading `PACKED_MAGIC_V1`)
/// or the legacy UTF-8 JSON document every pre-existing row holds.
pub(crate) fn decode_location(bytes: &[u8]) -> Result<Location, MobileError> {
    if bytes.first() == Some(&PACKED_MAGIC_V1) {
        return decode_packed_v1(bytes);
    }
    // Legacy JSON. Invalid UTF-8 is `DecryptionFailed`, the error callers
    // already handle for a payload that cannot be read.
    let text = std::str::from_utf8(bytes).map_err(|_| MobileError::DecryptionFailed)?;
    Ok(serde_json::from_str(text)?)
}

fn decode_packed_v1(bytes: &[u8]) -> Result<Location, MobileError> {
    if bytes.len() < HEADER_LEN {
        return Err(malformed("packed location shorter than its fixed header"));
    }
    let flags = bytes[1];
    if flags & FLAG_RESERVED != 0 {
        return Err(malformed("packed location sets a reserved bitmap bit"));
    }

    let lat_e7 = i32::from_le_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]);
    let lon_e7 = i32::from_le_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]);
    let timestamp = i64::from_le_bytes([
        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15], bytes[16], bytes[17],
    ]);

    let mut offset = HEADER_LEN;
    let altitude = read_opt_f32(bytes, &mut offset, flags, FLAG_ALTITUDE)?;
    let speed = read_opt_f32(bytes, &mut offset, flags, FLAG_SPEED)?;
    let heading = read_opt_f32(bytes, &mut offset, flags, FLAG_HEADING)?;
    let accuracy = read_opt_f32(bytes, &mut offset, flags, FLAG_ACCURACY)?;

    let battery_level = if flags & FLAG_BATTERY != 0 {
        let byte = *bytes
            .get(offset)
            .ok_or_else(|| malformed("packed location truncated before battery_level"))?;
        offset += 1;
        Some(byte)
    } else {
        None
    };

    let is_charging = if flags & FLAG_IS_CHARGING != 0 {
        Some(flags & FLAG_IS_CHARGING_VALUE != 0)
    } else {
        None
    };

    // Exact-length check: a payload longer than its bitmap describes is
    // malformed, not something to read the prefix of and ignore the rest.
    if offset != bytes.len() {
        return Err(malformed("packed location has trailing bytes"));
    }

    Ok(Location {
        latitude: f64::from(lat_e7) / 1e7,
        longitude: f64::from(lon_e7) / 1e7,
        altitude,
        speed,
        heading,
        accuracy,
        timestamp,
        battery_level,
        is_charging,
    })
}

fn read_opt_f32(
    bytes: &[u8],
    offset: &mut usize,
    flags: u8,
    flag: u8,
) -> Result<Option<f64>, MobileError> {
    if flags & flag == 0 {
        return Ok(None);
    }
    let end = *offset + 4;
    if end > bytes.len() {
        return Err(malformed("packed location truncated mid-field"));
    }
    let value = f32::from_le_bytes([
        bytes[*offset],
        bytes[*offset + 1],
        bytes[*offset + 2],
        bytes[*offset + 3],
    ]);
    *offset = end;
    Ok(Some(f64::from(value)))
}

/// Degrees to the 1e-7 fixed-point grid. Rounds HALF AWAY FROM ZERO — the
/// TypeScript twin implements the same rule by hand, because `Math.round` there
/// rounds half toward +infinity and would disagree on negative half-values.
fn to_e7(degrees: f64, limit: f64, field: &str) -> Result<i32, MobileError> {
    if !degrees.is_finite() {
        return Err(MobileError::InvalidInput(format!(
            "location {} is not a finite number",
            field
        )));
    }
    // Guards the i32 range only; a real coordinate is never outside this.
    let clamped = degrees.clamp(-limit, limit);
    Ok((clamped * 1e7).round() as i32)
}

fn finite(value: Option<f64>) -> Option<f64> {
    value.filter(|v| v.is_finite())
}

fn malformed(what: &str) -> MobileError {
    MobileError::SerializationError(what.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// LOCKED cross-language vector A — every optional field present.
    /// The web client's TypeScript twin asserts the identical string. If
    /// these two ever differ, a location written on one client is
    /// unreadable on the other.
    const VECTOR_A_HEX: &str =
        "b17fcf244e16c0753bb700f87821990100000000f4410000a03f00c089430000904057";
    /// LOCKED cross-language vector B — every optional field absent (18 bytes).
    const VECTOR_B_HEX: &str = "b1003b07d0eb1bb5205a00f8782199010000";

    fn vector_a() -> Location {
        Location {
            latitude: 37.4219983,
            longitude: -122.084,
            altitude: Some(30.5),
            speed: Some(1.25),
            heading: Some(275.5),
            accuracy: Some(4.5),
            timestamp: 1_757_203_200_000,
            battery_level: Some(87),
            is_charging: Some(true),
        }
    }

    fn vector_b() -> Location {
        Location {
            latitude: -33.8688197,
            longitude: 151.2092955,
            altitude: None,
            speed: None,
            heading: None,
            accuracy: None,
            timestamp: 1_757_203_200_000,
            battery_level: None,
            is_charging: None,
        }
    }

    fn assert_same(left: &Location, right: &Location) {
        assert_eq!(left.latitude, right.latitude, "latitude");
        assert_eq!(left.longitude, right.longitude, "longitude");
        assert_eq!(left.altitude, right.altitude, "altitude");
        assert_eq!(left.speed, right.speed, "speed");
        assert_eq!(left.heading, right.heading, "heading");
        assert_eq!(left.accuracy, right.accuracy, "accuracy");
        assert_eq!(left.timestamp, right.timestamp, "timestamp");
        assert_eq!(left.battery_level, right.battery_level, "battery_level");
        assert_eq!(left.is_charging, right.is_charging, "is_charging");
    }

    #[test]
    fn cross_language_vector_a_all_fields_present() {
        let encoded = encode_location(&vector_a()).expect("encode");
        assert_eq!(hex::encode(&encoded), VECTOR_A_HEX);
        assert_eq!(encoded.len(), MAX_PACKED_LEN);
        assert_same(&vector_a(), &decode_location(&encoded).expect("decode"));
    }

    #[test]
    fn cross_language_vector_b_no_optional_fields() {
        let encoded = encode_location(&vector_b()).expect("encode");
        assert_eq!(hex::encode(&encoded), VECTOR_B_HEX);
        assert_eq!(encoded.len(), HEADER_LEN);
        assert_same(&vector_b(), &decode_location(&encoded).expect("decode"));
    }

    /// A coordinate that already sits on the 1e-7 grid must come back BIT
    /// IDENTICAL — this is the property that makes the fixed-point choice safe.
    #[test]
    fn latlon_round_trip_is_exact_on_the_grid() {
        for (lat, lon) in [
            (0.0_f64, 0.0_f64),
            (37.4219983, -122.084),
            (-33.8688197, 151.2092955),
            (89.9999999, 179.9999999),
            (-89.9999999, -179.9999999),
            (-0.0000001, 0.0000001),
            (51.5074, -0.1278),
        ] {
            let source = Location {
                latitude: lat,
                longitude: lon,
                altitude: None,
                speed: None,
                heading: None,
                accuracy: None,
                timestamp: 0,
                battery_level: None,
                is_charging: None,
            };
            let decoded = decode_location(&encode_location(&source).expect("encode")).expect("decode");
            assert_eq!(decoded.latitude, lat, "latitude {} did not round-trip exactly", lat);
            assert_eq!(decoded.longitude, lon, "longitude {} did not round-trip exactly", lon);
        }
    }

    /// An arbitrary f64 coordinate (more digits than the grid holds) must land
    /// within half a grid step — 5e-8 degrees, about 5.5 mm.
    #[test]
    fn latlon_off_grid_error_is_below_a_centimetre() {
        for (lat, lon) in [
            (37.42199827194214_f64, -122.08400123456789_f64),
            (-33.86881970123456, 151.20929551234567),
            (1.0 / 3.0, -2.0 / 7.0),
        ] {
            let source = Location {
                latitude: lat,
                longitude: lon,
                altitude: None,
                speed: None,
                heading: None,
                accuracy: None,
                timestamp: 1,
                battery_level: None,
                is_charging: None,
            };
            let decoded = decode_location(&encode_location(&source).expect("encode")).expect("decode");
            assert!(
                (decoded.latitude - lat).abs() <= 5e-8,
                "latitude {} moved by {}",
                lat,
                (decoded.latitude - lat).abs()
            );
            assert!(
                (decoded.longitude - lon).abs() <= 5e-8,
                "longitude {} moved by {}",
                lon,
                (decoded.longitude - lon).abs()
            );
        }
    }

    /// Every one of the 2^6 present/absent combinations of the six optional
    /// fields must round-trip, and must produce the length the bitmap implies.
    #[test]
    fn every_optional_field_combination_round_trips() {
        for mask in 0u8..64 {
            let source = Location {
                latitude: 12.3456789,
                longitude: -98.7654321,
                altitude: (mask & 1 != 0).then_some(-30.5),
                speed: (mask & 2 != 0).then_some(1.25),
                heading: (mask & 4 != 0).then_some(275.5),
                accuracy: (mask & 8 != 0).then_some(4.5),
                timestamp: -1_757_203_200_000,
                battery_level: (mask & 16 != 0).then_some(87),
                is_charging: (mask & 32 != 0).then_some(mask % 3 == 0),
            };
            let encoded = encode_location(&source).expect("encode");
            let expected_len = HEADER_LEN
                + 4 * (mask & 0b1111).count_ones() as usize
                + usize::from(mask & 16 != 0);
            assert_eq!(encoded.len(), expected_len, "length for mask {:#08b}", mask);
            assert_same(&source, &decode_location(&encoded).expect("decode"));
        }
    }

    /// is_charging has THREE states and the bitmap must keep them apart.
    #[test]
    fn is_charging_absent_false_and_true_are_distinct() {
        let states = [None, Some(false), Some(true)];
        let mut encodings = Vec::new();
        for state in states {
            let source = Location {
                latitude: 1.0,
                longitude: 2.0,
                altitude: None,
                speed: None,
                heading: None,
                accuracy: None,
                timestamp: 7,
                battery_level: None,
                is_charging: state,
            };
            let encoded = encode_location(&source).expect("encode");
            assert_eq!(
                decode_location(&encoded).expect("decode").is_charging,
                state
            );
            encodings.push(encoded);
        }
        assert_ne!(encodings[0], encodings[1], "absent vs false");
        assert_ne!(encodings[1], encodings[2], "false vs true");
        assert_ne!(encodings[0], encodings[2], "absent vs true");
    }

    /// Rows written before the packed form hold a JSON plaintext. They must
    /// keep decoding, in both the fully-populated and the all-null shapes
    /// serde_json produces.
    #[test]
    fn legacy_json_plaintext_still_decodes() {
        let json = br#"{"latitude":37.4219983,"longitude":-122.084,"altitude":30.5,"speed":1.25,"heading":275.5,"accuracy":4.5,"timestamp":1757203200000,"battery_level":87,"is_charging":true}"#;
        assert_same(&vector_a(), &decode_location(json).expect("decode legacy"));

        let nulls = br#"{"latitude":-33.8688197,"longitude":151.2092955,"altitude":null,"speed":null,"heading":null,"accuracy":null,"timestamp":1757203200000,"battery_level":null,"is_charging":null}"#;
        assert_same(&vector_b(), &decode_location(nulls).expect("decode legacy nulls"));
    }

    /// The magic byte is a UTF-8 continuation byte, so a packed payload can
    /// never be mistaken for text and a JSON payload can never be mistaken for
    /// packed. This is what makes the two formats safely co-resident.
    #[test]
    fn magic_byte_cannot_begin_valid_utf8() {
        assert!(std::str::from_utf8(&[PACKED_MAGIC_V1]).is_err());
        assert_ne!(PACKED_MAGIC_V1, b'{');
        let packed = encode_location(&vector_a()).expect("encode");
        assert!(std::str::from_utf8(&packed).is_err());
    }

    #[test]
    fn malformed_packed_payloads_are_rejected() {
        let good = encode_location(&vector_a()).expect("encode");

        // Truncated header.
        assert!(decode_location(&good[..HEADER_LEN - 1]).is_err());
        // Truncated mid optional field.
        assert!(decode_location(&good[..HEADER_LEN + 2]).is_err());
        // Trailing junk.
        let mut long = good.clone();
        long.push(0);
        assert!(decode_location(&long).is_err());
        // Reserved bitmap bit set.
        let mut reserved = good.clone();
        reserved[1] |= FLAG_RESERVED;
        assert!(decode_location(&reserved).is_err());
        // Bare magic byte.
        assert!(decode_location(&[PACKED_MAGIC_V1]).is_err());
    }

    #[test]
    fn non_finite_coordinates_are_rejected_and_non_finite_optionals_drop_out() {
        let mut bad = vector_a();
        bad.latitude = f64::NAN;
        assert!(encode_location(&bad).is_err());

        let mut bad = vector_a();
        bad.longitude = f64::INFINITY;
        assert!(encode_location(&bad).is_err());

        // A non-finite OPTIONAL becomes absent — the same thing the JSON
        // encoding did (serde_json wrote `null`, which read back as None).
        let mut odd = vector_a();
        odd.altitude = Some(f64::NAN);
        odd.speed = Some(f64::NEG_INFINITY);
        let decoded = decode_location(&encode_location(&odd).expect("encode")).expect("decode");
        assert_eq!(decoded.altitude, None);
        assert_eq!(decoded.speed, None);
        assert_eq!(decoded.heading, Some(275.5));
    }

    /// The point of the packed form: it must be far smaller than the JSON,
    /// for a REALISTIC fix (full f64 precision, not a hand-rounded literal).
    #[test]
    fn packed_form_is_much_smaller_than_the_json_it_replaces() {
        let realistic = Location {
            latitude: 37.42199827194214,
            longitude: -122.08400123456789,
            altitude: Some(30.512340545654297),
            speed: Some(1.2534000873565674),
            heading: Some(275.5123291015625),
            accuracy: Some(4.512000560760498),
            timestamp: 1_757_203_200_123,
            battery_level: Some(87),
            is_charging: Some(true),
        };
        let json_len = serde_json::to_string(&realistic).expect("json").len();
        let packed_len = encode_location(&realistic).expect("encode").len();
        println!("PLAINTEXT SIZE: json={} packed={} saved={}", json_len, packed_len, json_len - packed_len);
        assert_eq!(packed_len, MAX_PACKED_LEN);
        assert!(
            json_len > 150,
            "representative JSON plaintext was only {} bytes",
            json_len
        );
        assert!(packed_len * 4 < json_len, "packed {} vs json {}", packed_len, json_len);
    }
}
