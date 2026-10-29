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

//! `srp_verify_server_proof` against the M2 that the auth server actually
//! sends. The vectors were made with the auth server's own proof check for a
//! minimal client (the srp crate's math, as `srp_compute_login_proof` runs
//! it) and a padding client (the portal's and the Android apps' encoding),
//! with and without a leading zero byte in A, B and S. No network, no
//! fixtures.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use pingolin_mobile::{srp_verify_server_proof, SrpProofEncoding};

// (name, the client's encoding, A, M1, S as that client holds them, the M2 the
// server sent, A short, S short, what the server's check said)
#[rustfmt::skip]
const VECTORS: [(&str, SrpProofEncoding, &str, &str, &str, &str, bool, bool, &str); 7] = [
    ("minimal_full_length", SrpProofEncoding::Minimal, "O7RdahpZcyewafz7esdlOT1vjjktEqIWf9e0p/KAkuJjG+Lp0nYYhHqZd5qLJLY8mUI15c8NqAB9NAIq7YcGLB+Zi/QqkZo2HGiU6uK5KSyauE9bdxHPRAPFKBfDDUxVCHV2c6f+2UxnjTgoexqrbgm7qAezV82/vddCkx2BgEEi7gRC4Ae4ZtUBbLr5cexHSx38z9IkyzORGTSSmy0X5el6epoykN905DBQZD0T/PO2ldRlVd1ev+PwR5GW+AxJxy9OkwA8/R0j+HE0Z9Bni5XqCD/tV403llDV+8EmBslz/nVdiNvA/fOEMiV8gp3TquuIa1IY/aQre2ZqRIYF6A==", "ybO4N41Z/qJ+3/X7y6Gq+r/yngMxSVQ/Atyc1JWfMtw=", "XyCMSpZFJEtop+KknJbpzICbssE4tIggUaIM0GxN2J/+rltNgc+cg23CqjZeqhi/ww/j8uBQCRK8nnpjGO4+uzO0MGH+r2exZc17kFkxBbbhvQ2jAXhSa8LqMjIWCxB8Zhs0TvAJTipKh5sY2fqeAgm0S6C7hvEdJ4lIujxnmEzHMJ+8egikgBBUjYf3qqmG/m5ewQL58lTq2MGa74udxARb+M+kzRsThdegwdaBu6QKKXsqK9wnm8hga/gnVfgGuDJ5/9oBrvHrte/Ks87FEi+i3zZR6X5WT78AthH36MmqUisdO1wOjtjtZyWoTPp48ig7hmZTwinYduZPX7K0WQ==", "R7dqhvMkDeuB2LtgjhlNAQQ4Wp5kiE4Ys6Mz8qAJvjg=", false, false, "Minimal"),
    ("minimal_short_a", SrpProofEncoding::Minimal, "ixMLQ2gfaXTfmxvmaXjsy7wujkY46iHC2n964etQU5u8JVaDzqoeaVVl0+1+A2v05UGh9aIyQccQ99PkFnK8jke91F7G9JboEQlh4b38mPEP3aMopXcqGpTbCSsxSZzdkUBzJoib+M7NDSkgz3hoeeKfAcCJmp3lIfp2MD12svRO5ThpQuPmrNpbGrkA4NqVR5ujiC066J6XS3Nf21xSbt7pB1RKu5io2ow4YOaGpkVQ89hTsnDgvpPYsZLahRNnllxXSw39vpaPbjnCiaz7SSN4LHnZLbtrZpSvURwesIpQ3dJofHOf03TyOQs1n+ltqm0pQqgpmsJs470M8oF2", "a9HmCfgRCQC+zq/g/m5pmUKXn21101hdFQ8p9YtBU50=", "Ymmhb+X4yKBoij1vDBz0unNOrCA0BvlFjc2n/vgg7tgMNXnibzQNYD05Cc7cFst0JU7Z6Uq2rm4jdK9HYrPSl2ft4AN6hiFkRUES8nNQvB8P6wEpNcu0AtuczYiT2MmWuy+V8Vw8mVxwMnFDhM+eu/gZsz/MnPFwYUU1fkMcadp+5MgVBRYNNwwS2hkkaM69aLFssVXoWeDxuPWtujFomKHmjHVR1EO8Yq6jww3vjcGEHL8TupPkEu69GAwVG0QLjAoxO21btst779SJnp0/uTJKaBD5pdQ17d3cX3kwcLorYDzfby0BvazZL1PnAyHZdOtriSh2YyO0evgSeINT3A==", "DqECA5Zm/9QW8+EYRqUGUYXt2sFEmI4jXB4/gxxkmGo=", true, false, "Minimal"),
    ("minimal_short_s", SrpProofEncoding::Minimal, "qQrJPtCnLVzCtKk2LyTegsKkkqLNfJVtBHFu5ZQQFXmqIPxFx/cljiDaSawyhP5n+7amdLcJ2cPQof1uSXQoKfjZnIoHBDOXL8rBHtBXDk2nL5Zy3hQlCYjh8vKe2qEvoD9qdycMP5jZ6WpQGK0NxmXQon+NYMtOInJtHmQTHfZbc2RdHO2XrAOlEn95kdmTuRk0cNYt6zKfL26zJVyqerGqQEBL7IFrrZqvwnAw70J6vQ9G4LFADHYtjqKHfcPyvMcOcPIj+GDXKFK/gBsSK+dWFkYA6F8/UjuF+ashcFbfSKlCS1Xme0gANbwRunV0xLBE/ioTDeVhf+mWD2qrKQ==", "xaaj1HimZzaqVJPSEQQ1729AULZyaAMpKLs/wNqQX4s=", "BNcC4xzdjit63Y1IUJdbw2qvbJztkQXlqGF/tevkHL0pe0YtGhDnn0BG5HgT4ddVfz1D7DkLvnrj072JswRnRTsKP28+90ymMVMyin4LrzdwQYwOGmrMCWNeLat8mVlVjEiKg8Gy0YJkahuGpsaK/4EyQZPARaJoKaK/lpcjKUXfu/bTQdl3KxXqbmR/e23VwuAkz4NgBAG2o/J2XiNCUGH0lS1nqIcXyP/lRUwNz+osVQ5fHzWlAkYvv2zED6yIKAik9DdnaXjmISegD4yk0OLCoBTkDp+LbQXcF8y3E2/SyRP0OplYkHn0PZOCpCB6FbY9Z4rKVuAjL4EEcgpz", "joh/2cWSX1GrMglxSG4JKYqfCskARMtAEkG+fFftE+Q=", false, true, "Minimal"),
    ("padded_full_length", SrpProofEncoding::Padded, "O7RdahpZcyewafz7esdlOT1vjjktEqIWf9e0p/KAkuJjG+Lp0nYYhHqZd5qLJLY8mUI15c8NqAB9NAIq7YcGLB+Zi/QqkZo2HGiU6uK5KSyauE9bdxHPRAPFKBfDDUxVCHV2c6f+2UxnjTgoexqrbgm7qAezV82/vddCkx2BgEEi7gRC4Ae4ZtUBbLr5cexHSx38z9IkyzORGTSSmy0X5el6epoykN905DBQZD0T/PO2ldRlVd1ev+PwR5GW+AxJxy9OkwA8/R0j+HE0Z9Bni5XqCD/tV403llDV+8EmBslz/nVdiNvA/fOEMiV8gp3TquuIa1IY/aQre2ZqRIYF6A==", "ybO4N41Z/qJ+3/X7y6Gq+r/yngMxSVQ/Atyc1JWfMtw=", "XyCMSpZFJEtop+KknJbpzICbssE4tIggUaIM0GxN2J/+rltNgc+cg23CqjZeqhi/ww/j8uBQCRK8nnpjGO4+uzO0MGH+r2exZc17kFkxBbbhvQ2jAXhSa8LqMjIWCxB8Zhs0TvAJTipKh5sY2fqeAgm0S6C7hvEdJ4lIujxnmEzHMJ+8egikgBBUjYf3qqmG/m5ewQL58lTq2MGa74udxARb+M+kzRsThdegwdaBu6QKKXsqK9wnm8hga/gnVfgGuDJ5/9oBrvHrte/Ks87FEi+i3zZR6X5WT78AthH36MmqUisdO1wOjtjtZyWoTPp48ig7hmZTwinYduZPX7K0WQ==", "R7dqhvMkDeuB2LtgjhlNAQQ4Wp5kiE4Ys6Mz8qAJvjg=", false, false, "Minimal"),
    ("padded_short_a", SrpProofEncoding::Padded, "AIsTC0NoH2l035sb5ml47Mu8Lo5GOOohwtp/euHrUFObvCVWg86qHmlVZdPtfgNr9OVBofWiMkHHEPfT5BZyvI5HvdRexvSW6BEJYeG9/JjxD92jKKV3KhqU2wkrMUmc3ZFAcyaIm/jOzQ0pIM94aHninwHAiZqd5SH6djA9drL0TuU4aULj5qzaWxq5AODalUebo4gtOuiel0tzX9tcUm7e6QdUSruYqNqMOGDmhqZFUPPYU7Jw4L6T2LGS2oUTZ5ZcV0sN/b6Wj245woms+0kjeCx52S27a2aUr1EcHrCKUN3SaHxzn9N08jkLNZ/pbaptKUKoKZrCbOO9DPKBdg==", "uq5L8qs3IweUCLuxI4RD5ktKU8KQ/OncNdnwU7l2Cf4=", "AKJRK1/SvSCMUHBEyHgtyuRITb0N69OQLafFcG/cMTgibD09zkv3Iiym5vAz+8x81VKjZQ6D74Ju9idWzDzreWcnsYoWYNX5QA38m/T0Vv5FfORqPQXgWN/crTGYnsh10ZUV5+ob6rgQjkGUwPfAcQw28lxDl1MyH/MsbmsOyFRrT6XkPCwwppHW5ylmFxcuuEqyhLkW9ODGXdbb6BJ7ecH7iO0OrY1p3vFZNjownTdRYgDzz6V6wgaJWpFQ5QaugAyHwHxJvEKeH0DF0wqv7bKCDiR1LVpDxx4DvIbNFWzCtEcBSH2nokEMEDwppoV2XwmLDcOb6wn6PVs19D6xJA==", "h04PP95JVjeigbPelFVTgG81d/tP0v09L5g4LXPS/fw=", true, true, "Padded"),
    ("padded_short_b", SrpProofEncoding::Padded, "O7RdahpZcyewafz7esdlOT1vjjktEqIWf9e0p/KAkuJjG+Lp0nYYhHqZd5qLJLY8mUI15c8NqAB9NAIq7YcGLB+Zi/QqkZo2HGiU6uK5KSyauE9bdxHPRAPFKBfDDUxVCHV2c6f+2UxnjTgoexqrbgm7qAezV82/vddCkx2BgEEi7gRC4Ae4ZtUBbLr5cexHSx38z9IkyzORGTSSmy0X5el6epoykN905DBQZD0T/PO2ldRlVd1ev+PwR5GW+AxJxy9OkwA8/R0j+HE0Z9Bni5XqCD/tV403llDV+8EmBslz/nVdiNvA/fOEMiV8gp3TquuIa1IY/aQre2ZqRIYF6A==", "Chg00XOhHQjCGxNPY5z8n/+fZHMZY6AIeg2O2edn0hQ=", "moIUG9SATUYIBts6A92XamqEwXx3rs04N7oUY7plNffNGJUF25D4kx4rpewMn9dl0bnKjyYeEr9pyCsAtxjdxCwxEXRTh/gi6MCA6waMpN1lKmvBsHAwtpKFj+pOKnZUKSsr+zzWOpFDz/PGkcFCtr8lVo10roBlUmM1cFJJzEyX0ooRYAawYPfxSWSWawaYbTUcmi9VlBrve9IFiBjsBiH2hDd1z4/w4W7yKvolijHbGU5zhF0xpG6Cp/fk12x6nM03WaV4lGsto8csYQwvAbeB2tNCjw9804JczgfcD8ArQdqSdMesWxnJWCCc2PlQrTkYZNW8k/F2YfTmP22otQ==", "AkUSUjcHFpDIi53rO7dz/YaaoMWcUNR1FIhMg8aGlP4=", false, false, "Padded"),
    ("padded_short_s", SrpProofEncoding::Padded, "qQrJPtCnLVzCtKk2LyTegsKkkqLNfJVtBHFu5ZQQFXmqIPxFx/cljiDaSawyhP5n+7amdLcJ2cPQof1uSXQoKfjZnIoHBDOXL8rBHtBXDk2nL5Zy3hQlCYjh8vKe2qEvoD9qdycMP5jZ6WpQGK0NxmXQon+NYMtOInJtHmQTHfZbc2RdHO2XrAOlEn95kdmTuRk0cNYt6zKfL26zJVyqerGqQEBL7IFrrZqvwnAw70J6vQ9G4LFADHYtjqKHfcPyvMcOcPIj+GDXKFK/gBsSK+dWFkYA6F8/UjuF+ashcFbfSKlCS1Xme0gANbwRunV0xLBE/ioTDeVhf+mWD2qrKQ==", "1eHcGyCMiGa+tnofE/Om6jEkwl4zn2HKYxkG/qr7T5Y=", "AATXAuMc3Y4ret2NSFCXW8Nqr2yc7ZEF5ahhf7Xr5By9KXtGLRoQ559ARuR4E+HXVX89Q+w5C75649O9ibMEZ0U7Cj9vPvdMpjFTMop+C683cEGMDhpqzAljXi2rfJlZVYxIioPBstGCZGobhqbGiv+BMkGTwEWiaCmiv5aXIylF37v200HZdysV6m5kf3tt1cLgJM+DYAQBtqPydl4jQlBh9JUtZ6iHF8j/5UVMDc/qLFUOXx81pQJGL79sxA+siCgIpPQ3Z2l45iEnoA+MpNDiwqAU5A6fi20F3BfMtxNv0skT9DqZWJB59D2TgqQgehW2PWeKylbgIy+BBHIKcw==", "eyFnTCcrMOwtZ8nhvnvEc1HrfTqFC9wFcFG3qfYMNEM=", false, true, "Padded"),
];

fn verify(a: &[u8], m1: &str, s: &[u8], m2: &str, encoding: SrpProofEncoding) -> bool {
    srp_verify_server_proof(B64.encode(a), m1.into(), B64.encode(s), m2.into(), encoding).unwrap()
}

fn other(encoding: SrpProofEncoding) -> SrpProofEncoding {
    match encoding {
        SrpProofEncoding::Minimal => SrpProofEncoding::Padded,
        SrpProofEncoding::Padded => SrpProofEncoding::Minimal,
    }
}

/// One number spelled three ways: minimal, padded to 256 bytes, and with one
/// more zero byte in front (like Java's `BigInteger.toByteArray` sign byte).
fn spellings(x: &[u8]) -> Vec<Vec<u8>> {
    let first = x.iter().position(|&b| b != 0).unwrap();
    let minimal = x[first..].to_vec();
    let mut padded = vec![0u8; 256 - minimal.len()];
    padded.extend(&minimal);
    let mut signed = vec![0u8];
    signed.extend(&padded);
    vec![minimal, padded, signed]
}

fn flip_last(x: &[u8]) -> Vec<u8> {
    let mut y = x.to_vec();
    let last = y.len() - 1;
    y[last] ^= 1;
    y
}

#[test]
fn the_m2_auth_sends_verifies_in_the_clients_own_encoding() {
    for (name, encoding, a, m1, s, m2, _, _, _) in VECTORS {
        let (a, s) = (B64.decode(a).unwrap(), B64.decode(s).unwrap());
        for a in spellings(&a) {
            for s in spellings(&s) {
                assert!(verify(&a, m1, &s, m2, encoding), "{name}: A {} bytes, S {} bytes", a.len(), s.len());
            }
        }
    }
}

/// M2 hashes A and S (not B), so the other encoding gives the same M2 exactly
/// when neither A nor S has a leading zero byte.
#[test]
fn the_other_encoding_verifies_only_when_a_and_s_are_full_length() {
    for (name, encoding, a, m1, s, m2, short_a, short_s, _) in VECTORS {
        let (a, s) = (B64.decode(a).unwrap(), B64.decode(s).unwrap());
        assert_eq!(verify(&a, m1, &s, m2, other(encoding)), !(short_a || short_s), "{name}");
    }
}

#[test]
fn a_wrong_m2_is_refused() {
    for (name, encoding, a, m1, s, m2, _, _, _) in VECTORS {
        let (a, s, sent) = (B64.decode(a).unwrap(), B64.decode(s).unwrap(), B64.decode(m2).unwrap());
        for i in 0..sent.len() {
            for bit in [0x01u8, 0x80] {
                let mut wrong = sent.clone();
                wrong[i] ^= bit;
                assert!(!verify(&a, m1, &s, &B64.encode(&wrong), encoding), "{name}: byte {i} bit {bit:#x}");
            }
        }
        let mut long = sent.clone();
        long.push(0);
        for wrong in [B64.encode(&sent[..31]), B64.encode(&long), String::new(), "%%%%".into(), B64.encode([0u8; 32])] {
            assert!(!verify(&a, m1, &s, &wrong, encoding), "{name}: {wrong:?}");
        }
        // Another vector's M2 verifies only if it is the same bytes: the two
        // full-length vectors are one session (nothing short), so theirs are.
        for (other_name, .., other_m2, _, _, _) in VECTORS {
            assert_eq!(verify(&a, m1, &s, other_m2, encoding), other_m2 == m2, "{name}: {other_name}'s M2");
        }
    }
}

#[test]
fn m2_is_bound_to_this_clients_a_m1_and_s() {
    for (name, encoding, a, m1, s, m2, _, _, _) in VECTORS {
        let (a, m1_bytes, s) = (B64.decode(a).unwrap(), B64.decode(m1).unwrap(), B64.decode(s).unwrap());
        assert!(!verify(&flip_last(&a), m1, &s, m2, encoding), "{name}: another A");
        assert!(!verify(&a, &B64.encode(flip_last(&m1_bytes)), &s, m2, encoding), "{name}: another M1");
        assert!(!verify(&a, m1, &flip_last(&s), m2, encoding), "{name}: another S");
    }
}
