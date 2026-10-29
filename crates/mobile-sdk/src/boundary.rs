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

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Boundary/geofence definition
#[derive(Debug, Clone, uniffi::Record)]
pub struct Boundary {
    /// The server-side place_id this geofence came from
    pub id: String,
    pub circle_id: String,
    /// Centre, in decimal degrees
    pub center_lat: f64,
    pub center_lng: f64,
    /// Radius in metres
    pub radius_meters: u32,
    pub name: String,
}

/// Boundary crossing event
#[derive(Debug, Clone, uniffi::Enum)]
pub enum BoundaryCrossingType {
    Enter,
    Exit,
}

/// Result of a boundary crossing check
#[derive(Debug, Clone, uniffi::Record)]
pub struct BoundaryCrossing {
    pub boundary_id: String,
    pub crossing_type: BoundaryCrossingType,
    pub distance_meters: f64,
    pub boundary_name: String,
}

/// Callback interface for boundary crossing events
#[uniffi::export(callback_interface)]
pub trait BoundaryCallback: Send + Sync {
    /// Called when a boundary crossing is detected
    fn on_boundary_crossing(&self, crossing: BoundaryCrossing);
    /// Called when boundaries are loaded/updated
    fn on_boundaries_updated(&self, count: u32);
}

/// Client-side boundary checker for real-time geofence detection
#[derive(uniffi::Object)]
pub struct BoundaryChecker {
    boundaries: Arc<RwLock<HashMap<String, Boundary>>>,
    states: Arc<RwLock<HashMap<String, bool>>>, // boundary_id -> is_inside
    callback: Arc<RwLock<Option<Box<dyn BoundaryCallback>>>>,
}

#[uniffi::export]
impl BoundaryChecker {
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self {
            boundaries: Arc::new(RwLock::new(HashMap::new())),
            states: Arc::new(RwLock::new(HashMap::new())),
            callback: Arc::new(RwLock::new(None)),
        }
    }

    /// Set the callback for boundary crossing events
    pub async fn set_callback(&self, callback: Box<dyn BoundaryCallback>) {
        *self.callback.write().await = Some(callback);
    }

    pub async fn clear_callback(&self) {
        *self.callback.write().await = None;
    }

    /// Replace the whole boundary set (typically the places just fetched from
    /// the server). Inside/outside state is deliberately NOT cleared: clearing
    /// it would re-prime every boundary (see `check_location`) and re-announce
    /// an arrival for anyone sitting inside a place, on every reload.
    pub async fn load_boundaries(&self, boundaries: Vec<Boundary>) {
        let count = boundaries.len() as u32;
        let mut map = self.boundaries.write().await;
        map.clear();
        for boundary in boundaries {
            map.insert(boundary.id.clone(), boundary);
        }

        if let Some(cb) = &*self.callback.read().await {
            cb.on_boundaries_updated(count);
        }
    }

    pub async fn add_boundary(&self, boundary: Boundary) {
        self.boundaries.write().await.insert(boundary.id.clone(), boundary);
    }

    /// Remove a boundary and forget its inside/outside state
    pub async fn remove_boundary(&self, boundary_id: String) {
        self.boundaries.write().await.remove(&boundary_id);
        self.states.write().await.remove(&boundary_id);
    }

    /// Drop every boundary and all inside/outside state
    pub async fn clear_boundaries(&self) {
        self.boundaries.write().await.clear();
        self.states.write().await.clear();
    }

    /// Check one fix against every loaded boundary and return the crossings it
    /// produced. Stateful: each call updates the remembered inside/outside flag
    /// per boundary, so fixes must be fed in the order they were observed.
    ///
    /// `accuracy_meters` is the fix's reported horizontal accuracy. It is
    /// OPTIONAL and defaults to `None`, which means "unknown" and treats the fix
    /// as usable — so a caller that does not pass it gets ungated evaluation.
    ///
    /// Why it exists: a fix rougher than a boundary's own radius decides
    /// nothing about it, and the crossing this function reports is broadcast to
    /// the mover's circle. See [`can_resolve`] for the rule and why it is
    /// per-boundary rather than per-call.
    ///
    /// Coarse fixes are routine, not theoretical. iOS requests
    /// `kCLLocationAccuracyHundredMeters` in its battery-saver configuration.
    /// On Android, the periodic heartbeat asks for balanced accuracy for every
    /// user, and how coarse that gets depends on the location provider:
    ///
    ///   Play services  `FusedLocationProvider` -> `PRIORITY_BALANCED_POWER_ACCURACY`,
    ///                  documented as roughly 100 m — and place-alert rings START at
    ///                  100 m, so the nominal figure sits exactly on the smallest
    ///                  ring. Nominal is a target, not a bound.
    ///   no Play        `NETWORK_PROVIDER` FIRST, then GPS. Wifi/cell positioning,
    ///                  routinely hundreds of metres: a 500 m fix meets a 100 m
    ///                  geofence.
    ///
    /// A high-accuracy request can still be served a coarse fused result, so the
    /// gate is a DEFENCE against what the platform may return, not a harvest of
    /// fixes we asked to be rough.
    ///
    /// A boundary the fix cannot resolve is skipped ENTIRELY — no crossing, and
    /// its remembered state is left untouched. Advancing state from a fix we
    /// declined to trust is the trap: a suppressed ENTER would leave the checker
    /// believing the device is inside, and the next genuine EXIT would announce
    /// a departure from somewhere it never arrived.
    #[uniffi::method(default(accuracy_meters = None))]
    pub async fn check_location(
        &self,
        lat: f64,
        lng: f64,
        accuracy_meters: Option<f64>,
    ) -> Vec<BoundaryCrossing> {
        let boundaries = self.boundaries.read().await;
        let mut states = self.states.write().await;
        let callback = self.callback.read().await;

        let mut crossings = Vec::new();

        for (id, boundary) in boundaries.iter() {
            let distance = haversine_distance(lat, lng, boundary.center_lat, boundary.center_lng);
            let radius = boundary.radius_meters as f64;

            // Too rough to decide this ring: report nothing AND leave the state
            // alone, so a later usable fix is still judged against the last
            // position we actually believed. `continue` before the priming
            // branch below is deliberate — priming from an untrusted fix would
            // bake a guess in as the baseline.
            if !can_resolve(radius, accuracy_meters) {
                continue;
            }

            // Asymmetric thresholds. You ARRIVE at the true radius, but you have
            // to get clearly clear of it before we call it a departure. A bare
            // `distance <= radius` flips on one bad fix, and because the detector
            // is a state machine, that costs the user BOTH a spurious departure
            // and a spurious arrival when the next fix lands back inside — two
            // false alerts from one wobble. Standard GPS error at the edge of a
            // 150 m geofence is easily enough to do it. `exit_margin_meters`
            // sizes the margin.
            //
            // The platform clients run this same rule for their own local place
            // alerts and MUST use identical thresholds: the mover judges its own
            // crossings and the subscriber judges everyone else's from the same
            // fixes, so a margin on one side only makes the two disagree about
            // whether a member is inside a place.
            //
            // The margin widens to the fix's own accuracy when that is rougher
            // than the geometric one. A fix precise enough to be evaluated at
            // all can still be rougher than the 20 m floor, and a departure
            // declared on that noise costs the user two false alerts. Only ever
            // WIDENS (`max`), so a precise fix gets the geometric margin alone.
            //
            // ARRIVAL keeps the true radius, unwidened — arriving early is a
            // worse failure than flapping, and the platform mirrors of this rule
            // take the same position.
            let is_inside = match states.get(id) {
                Some(&true) => {
                    let margin = exit_margin_meters(radius).max(accuracy_meters.unwrap_or(0.0));
                    distance <= radius + margin
                }
                _ => distance <= radius,
            };

            // First observation of this boundary PRIMES the state and reports
            // nothing. `states` is in-memory and dies with the process, so
            // defaulting an unknown boundary to "outside" makes every cold start
            // while standing inside a place look like an arrival: the app
            // restarts, the first fix lands inside, false != true, and the device
            // announces to the circle that you have just arrived somewhere you
            // never left — an `enter` the server accepts as a real crossing.
            //
            // The cost is a genuine arrival that happens to coincide with the very
            // first fix after a cold start, which the mover then doesn't report.
            // That is the better direction to fail, and it is not a silent loss:
            // the subscriber's own device evaluates the same arrival from the
            // member locations it already holds, and ITS state is persisted on
            // disk, so it survives the restart this path cannot. A false arrival
            // broadcast to a circle has no such backstop.
            let Some(&was_inside) = states.get(id) else {
                states.insert(id.clone(), is_inside);
                continue;
            };

            if is_inside != was_inside {
                let crossing = BoundaryCrossing {
                    boundary_id: id.clone(),
                    crossing_type: if is_inside { BoundaryCrossingType::Enter } else { BoundaryCrossingType::Exit },
                    distance_meters: distance,
                    boundary_name: boundary.name.clone(),
                };

                crossings.push(crossing.clone());

                if let Some(ref cb) = *callback {
                    cb.on_boundary_crossing(crossing);
                }
            }

            states.insert(id.clone(), is_inside);
        }

        crossings
    }

    /// Metres from the fix to the boundary's CENTRE (not to its edge), or `None`
    /// if no such boundary is loaded.
    pub async fn distance_to_boundary(&self, boundary_id: String, lat: f64, lng: f64) -> Option<f64> {
        let boundaries = self.boundaries.read().await;
        boundaries.get(&boundary_id).map(|b| {
            haversine_distance(lat, lng, b.center_lat, b.center_lng)
        })
    }

    /// Last known inside/outside state, or `None` if no fix has been checked
    /// against this boundary yet — an unprimed boundary is not "outside".
    pub async fn is_inside_boundary(&self, boundary_id: String) -> Option<bool> {
        self.states.read().await.get(&boundary_id).copied()
    }

    /// Get all boundary IDs the user is currently inside
    pub async fn get_boundaries_inside(&self) -> Vec<String> {
        self.states.read().await
            .iter()
            .filter_map(|(id, &inside)| if inside { Some(id.clone()) } else { None })
            .collect()
    }

    pub async fn boundary_count(&self) -> u32 {
        self.boundaries.read().await.len() as u32
    }
}

impl Default for BoundaryChecker {
    fn default() -> Self {
        Self::new()
    }
}

/// Extra distance beyond the radius a device must travel before an EXIT is
/// declared. Prevents one noisy fix at the edge producing a spurious departure
/// immediately followed by a spurious arrival.
///
/// 20% of the radius, floored at 20 m so small geofences still get a usable
/// buffer, capped at 100 m so a large one doesn't swallow genuine departures.
/// MUST match the exit-margin constants in the platform clients' own
/// place-alert rules, or the two detectors disagree about who is inside.
pub(crate) fn exit_margin_meters(radius_meters: f64) -> f64 {
    (radius_meters * 0.20).clamp(20.0, 100.0)
}

/// Whether a fix of this accuracy can say anything at all about a ring of this
/// radius.
///
/// A fix whose own error exceeds the radius carries NO information about the
/// boundary: the true position is somewhere in a circle larger than the feature
/// being tested, so "inside" and "outside" are both consistent with the
/// measurement. A crossing reported from one is a guess, and this one is
/// broadcast — `report_crossing` tells the mover's whole circle.
///
/// PER-BOUNDARY, and that is the point. The same 500 m fix is useless against a
/// 100 m ring and perfectly usable against a 2 km one, so only rings smaller
/// than the fix's own error stop being evaluated. Gating the whole CALL on the
/// smallest loaded ring — the alternative that needs no new argument — would
/// silently stop evaluating large boundaries whenever a small one happened to be
/// loaded.
///
/// `None` means the caller did not report an accuracy, and is treated as
/// USABLE. A platform that gives no accuracy must not have its crossings
/// silently disabled; unknown is not the same as too coarse. Every client mirror
/// of this rule takes the same position, including `PlaceAlertRules.canResolve`
/// in the Track Android and iOS apps.
///
/// The gate matters most in APPROXIMATE (bubble) sharing, where the sender
/// floors reported accuracy to the bubble cell precisely so a reader can tell
/// the point is coarse: an evaluator without it would judge a grid-snapped
/// point against the true ring as though it were exact.
pub(crate) fn can_resolve(radius_meters: f64, accuracy_meters: Option<f64>) -> bool {
    match accuracy_meters {
        None => true,
        Some(a) => a <= radius_meters,
    }
}

/// Great-circle distance in metres between two points (Haversine)
fn haversine_distance(lat1: f64, lng1: f64, lat2: f64, lng2: f64) -> f64 {
    const EARTH_RADIUS_METERS: f64 = 6_371_000.0;

    let lat1_rad = lat1.to_radians();
    let lat2_rad = lat2.to_radians();
    let delta_lat = (lat2 - lat1).to_radians();
    let delta_lng = (lng2 - lng1).to_radians();

    let a = (delta_lat / 2.0).sin().powi(2)
        + lat1_rad.cos() * lat2_rad.cos() * (delta_lng / 2.0).sin().powi(2);
    let c = 2.0 * a.sqrt().asin();

    EARTH_RADIUS_METERS * c
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_haversine_distance() {
        // ~100m apart
        let lat1 = 51.5074;
        let lng1 = -0.1278;
        let lat2 = 51.5083;
        let lng2 = -0.1278;

        let distance = haversine_distance(lat1, lng1, lat2, lng2);
        assert!((distance - 100.0).abs() < 10.0);
    }

    #[tokio::test]
    async fn test_boundary_crossing() {
        let checker = BoundaryChecker::new();

        let boundary = Boundary {
            id: "test-1".to_string(),
            circle_id: "circle-1".to_string(),
            center_lat: 51.5074,
            center_lng: -0.1278,
            radius_meters: 100,
            name: "Test Place".to_string(),
        };

        checker.add_boundary(boundary).await;

        // Start outside
        let crossings = checker.check_location(51.5174, -0.1278, None).await;
        assert!(crossings.is_empty());

        // Move inside
        let crossings = checker.check_location(51.5074, -0.1278, None).await;
        assert_eq!(crossings.len(), 1);
        assert!(matches!(crossings[0].crossing_type, BoundaryCrossingType::Enter));

        // Stay inside
        let crossings = checker.check_location(51.5075, -0.1279, None).await;
        assert!(crossings.is_empty());

        // Move outside
        let crossings = checker.check_location(51.5174, -0.1278, None).await;
        assert_eq!(crossings.len(), 1);
        assert!(matches!(crossings[0].crossing_type, BoundaryCrossingType::Exit));
    }
}

#[cfg(test)]
mod cold_start_tests {
    use super::*;

    fn place() -> Boundary {
        Boundary {
            id: "place-1".to_string(),
            circle_id: "circle-1".to_string(),
            name: "Home".to_string(),
            center_lat: 37.7699,
            center_lng: -122.4469,
            radius_meters: 150,
        }
    }

    /// `states` is in-memory, so a cold start has no prior state. An unknown
    /// boundary defaulting to "outside" would make a first fix landing INSIDE
    /// report an arrival — the device announcing you just arrived somewhere you
    /// never left, on every app restart.
    #[tokio::test]
    async fn a_cold_start_inside_a_place_reports_no_arrival() {
        let checker = BoundaryChecker::new();
        checker.load_boundaries(vec![place()]).await;

        let crossings = checker.check_location(37.7699, -122.4469, None).await;
        assert!(
            crossings.is_empty(),
            "cold start while inside reported {:?} — this is the restart false-arrival",
            crossings.iter().map(|c| &c.boundary_id).collect::<Vec<_>>()
        );
    }

    /// Priming must not swallow the NEXT real transition.
    #[tokio::test]
    async fn a_real_exit_after_a_primed_cold_start_still_reports() {
        let checker = BoundaryChecker::new();
        checker.load_boundaries(vec![place()]).await;

        checker.check_location(37.7699, -122.4469, None).await; // primes: inside
        let crossings = checker.check_location(37.7799, -122.4469, None).await; // ~1.1km away
        assert_eq!(crossings.len(), 1);
        assert!(matches!(crossings[0].crossing_type, BoundaryCrossingType::Exit));
    }

    /// A cold start OUTSIDE primes too, and the later arrival still reports —
    /// the common case must be unaffected.
    #[tokio::test]
    async fn a_cold_start_outside_still_reports_the_later_arrival() {
        let checker = BoundaryChecker::new();
        checker.load_boundaries(vec![place()]).await;

        checker.check_location(37.7799, -122.4469, None).await; // primes: outside
        let crossings = checker.check_location(37.7699, -122.4469, None).await;
        assert_eq!(crossings.len(), 1);
        assert!(matches!(crossings[0].crossing_type, BoundaryCrossingType::Enter));
    }

    /// Reloading boundaries must NOT re-prime: `load_boundaries` runs on a
    /// 2-minute cadence, so if it dropped state every reload would re-announce an
    /// arrival for anyone sitting inside a place.
    #[tokio::test]
    async fn a_boundary_reload_does_not_re_announce_an_arrival() {
        let checker = BoundaryChecker::new();
        checker.load_boundaries(vec![place()]).await;
        checker.check_location(37.7699, -122.4469, None).await; // primes: inside

        checker.load_boundaries(vec![place()]).await; // the 2-minute reload
        let crossings = checker.check_location(37.7699, -122.4469, None).await;
        assert!(crossings.is_empty(), "a reload re-announced an arrival");
    }
}

#[cfg(test)]
mod hysteresis_tests {
    use super::*;

    // radius 150 m -> margin = clamp(150*0.20, 20, 100) = 30 m, so exit at >180 m.
    fn place() -> Boundary {
        Boundary {
            id: "place-1".to_string(),
            circle_id: "circle-1".to_string(),
            center_lat: 37.7699,
            center_lng: -122.4469,
            radius_meters: 150,
            name: "Home".to_string(),
        }
    }

    /// ~1 degree of latitude is ~111.32 km.
    fn north_of_centre(metres: f64) -> f64 {
        37.7699 + metres / 111_320.0
    }

    async fn settled_inside() -> BoundaryChecker {
        let checker = BoundaryChecker::new();
        checker.load_boundaries(vec![place()]).await;
        checker.check_location(37.7699, -122.4469, None).await; // primes: inside
        checker
    }

    #[test]
    fn the_margin_is_proportional_but_bounded() {
        assert_eq!(exit_margin_meters(150.0), 30.0);
        assert_eq!(exit_margin_meters(50.0), 20.0, "small geofences still get a usable floor");
        assert_eq!(exit_margin_meters(5000.0), 100.0, "large ones are capped");
    }

    /// A fix just past the radius must not flip the state on its own.
    #[tokio::test]
    async fn a_fix_just_outside_the_radius_does_not_report_a_departure() {
        let checker = settled_inside().await;
        let crossings = checker.check_location(north_of_centre(165.0), -122.4469, None).await;
        assert!(
            crossings.is_empty(),
            "165 m is past the 150 m radius but inside the 30 m margin — reported {:?}",
            crossings.iter().map(|c| &c.boundary_id).collect::<Vec<_>>()
        );
    }

    /// The whole point: one wobble must not cost the user TWO false alerts — a
    /// departure on the way out and an arrival on the way back.
    #[tokio::test]
    async fn a_wobble_out_and_back_produces_no_alerts_at_all() {
        let checker = settled_inside().await;
        let out = checker.check_location(north_of_centre(165.0), -122.4469, None).await;
        let back = checker.check_location(37.7699, -122.4469, None).await;
        assert!(out.is_empty() && back.is_empty(), "a wobble produced {out:?} then {back:?}");
    }

    /// Hysteresis must not swallow a real departure.
    #[tokio::test]
    async fn leaving_properly_still_reports_a_departure() {
        let checker = settled_inside().await;
        let crossings = checker.check_location(north_of_centre(250.0), -122.4469, None).await;
        assert_eq!(crossings.len(), 1);
        assert!(matches!(crossings[0].crossing_type, BoundaryCrossingType::Exit));
    }

    /// The asymmetry: arrival is judged at the TRUE radius, departure at
    /// radius + margin. The margin must never widen the arrival test — that
    /// would have people arriving early, which is worse than the flapping the
    /// margin exists to fix.
    #[tokio::test]
    async fn arrival_still_happens_at_the_true_radius() {
        let checker = BoundaryChecker::new();
        checker.load_boundaries(vec![place()]).await;
        checker.check_location(north_of_centre(400.0), -122.4469, None).await; // primes: outside

        // Inside the margin band but OUTSIDE the radius: still not an arrival.
        assert!(checker.check_location(north_of_centre(165.0), -122.4469, None).await.is_empty());
        // Within the radius: arrival.
        let crossings = checker.check_location(north_of_centre(120.0), -122.4469, None).await;
        assert_eq!(crossings.len(), 1);
        assert!(matches!(crossings[0].crossing_type, BoundaryCrossingType::Enter));
    }
}

/// The accuracy gate: a fix rougher than a ring decides nothing about that ring.
///
/// Kept in step with `PlaceAlertRules.canResolve` / `isInside` on Android. The two
/// detectors judge the same fixes — the mover for its own crossings here, the
/// subscriber for everyone else's there — so a rule that holds on one side only
/// makes them disagree about who is inside.
#[cfg(test)]
mod accuracy_gate_tests {
    use super::*;

    fn ring(radius_meters: u32) -> Boundary {
        Boundary {
            id: format!("place-{radius_meters}"),
            circle_id: "circle-1".to_string(),
            center_lat: 37.7699,
            center_lng: -122.4469,
            radius_meters,
            name: format!("Ring {radius_meters}"),
        }
    }

    /// ~1 degree of latitude is ~111.32 km.
    fn north_of_centre(metres: f64) -> f64 {
        37.7699 + metres / 111_320.0
    }

    #[test]
    fn a_fix_rougher_than_the_radius_resolves_nothing() {
        // 500 m is what track-android's battery-saver filter ACCEPTS
        // (LocationPolicy.MIN_ACCURACY_BALANCED) — not what it requests; see
        // check_location's note on where Android's coarse fixes really come from.
        assert!(!can_resolve(100.0, Some(500.0)));
        assert!(!can_resolve(100.0, Some(100.001)));
    }

    #[test]
    fn a_fix_at_or_inside_the_radius_resolves_it() {
        assert!(can_resolve(100.0, Some(100.0)), "inclusive at the boundary");
        assert!(can_resolve(100.0, Some(12.0)));
    }

    #[test]
    fn unknown_accuracy_is_usable_not_too_coarse() {
        // A platform that reports no accuracy must not have its crossings
        // silently disabled. Unknown means evaluate.
        assert!(can_resolve(50.0, None));
    }

    /// Why the gate is per-boundary and not per-call: only rings SMALLER than the
    /// fix's own error go dark. Gating the whole call on the smallest loaded ring
    /// would take the 2 km one down with the 100 m one.
    #[tokio::test]
    async fn a_coarse_fix_still_judges_a_large_ring_beside_a_small_one() {
        let checker = BoundaryChecker::new();
        checker.load_boundaries(vec![ring(100), ring(2000)]).await;

        // Prime both from well outside, precisely.
        checker.check_location(north_of_centre(5000.0), -122.4469, Some(5.0)).await;

        // A 500 m fix at the centre: cannot resolve the 100 m ring, CAN resolve
        // the 2 km one. Exactly one arrival, and it is the large ring's.
        let crossings = checker
            .check_location(37.7699, -122.4469, Some(500.0))
            .await;
        assert_eq!(crossings.len(), 1, "got {crossings:?}");
        assert_eq!(crossings[0].boundary_id, "place-2000");
        assert!(matches!(crossings[0].crossing_type, BoundaryCrossingType::Enter));
    }

    /// The trap this ordering exists to avoid. A skipped fix must not prime or
    /// advance state, or a suppressed ENTER leaves the checker believing the
    /// device is inside — and the next genuine EXIT announces a departure from
    /// somewhere it never arrived.
    #[tokio::test]
    async fn a_skipped_fix_neither_primes_nor_advances_state() {
        let checker = BoundaryChecker::new();
        checker.load_boundaries(vec![ring(100)]).await;

        // An unusable fix at the centre must not prime the boundary at all.
        assert!(checker
            .check_location(37.7699, -122.4469, Some(500.0))
            .await
            .is_empty());
        assert_eq!(
            checker.is_inside_boundary("place-100".to_string()).await,
            None,
            "an unusable fix must leave the boundary UNPRIMED, not 'inside'",
        );

        // Prime properly from outside, then a usable arrival still fires.
        checker.check_location(north_of_centre(500.0), -122.4469, Some(10.0)).await;
        let crossings = checker
            .check_location(37.7699, -122.4469, Some(10.0))
            .await;
        assert_eq!(crossings.len(), 1);
        assert!(matches!(crossings[0].crossing_type, BoundaryCrossingType::Enter));
    }

    /// A departure declared on noise costs the user two false alerts — the
    /// departure, then the arrival when the next fix lands back inside.
    #[tokio::test]
    async fn a_rough_but_usable_fix_widens_the_margin_instead_of_departing() {
        let checker = BoundaryChecker::new();
        checker.load_boundaries(vec![ring(150)]).await; // geometric margin = 30 m
        checker.check_location(37.7699, -122.4469, Some(10.0)).await; // primes: inside

        // 200 m out is past radius+30 but inside radius+120: no departure.
        assert!(
            checker
                .check_location(north_of_centre(200.0), -122.4469, Some(120.0))
                .await
                .is_empty(),
            "a 120 m-accurate fix 200 m out must not read as a departure",
        );
    }

    /// The same geometry, precisely measured, IS a departure — so the test above
    /// is not passing because the fix was ignored.
    #[tokio::test]
    async fn the_same_geometry_precisely_measured_is_a_departure() {
        let checker = BoundaryChecker::new();
        checker.load_boundaries(vec![ring(150)]).await;
        checker.check_location(37.7699, -122.4469, Some(5.0)).await; // primes: inside

        let crossings = checker
            .check_location(north_of_centre(200.0), -122.4469, Some(5.0))
            .await;
        assert_eq!(crossings.len(), 1);
        assert!(matches!(crossings[0].crossing_type, BoundaryCrossingType::Exit));
    }

    /// Widening must never NARROW: a precise fix has to behave exactly as one
    /// with no accuracy at all.
    #[tokio::test]
    async fn a_precise_fix_behaves_exactly_as_an_unknown_one() {
        for distance in [10.0, 149.0, 175.0, 179.0, 181.0, 400.0] {
            let with_none = {
                let c = BoundaryChecker::new();
                c.load_boundaries(vec![ring(150)]).await;
                c.check_location(37.7699, -122.4469, None).await;
                c.check_location(north_of_centre(distance), -122.4469, None).await
            };
            let with_zero = {
                let c = BoundaryChecker::new();
                c.load_boundaries(vec![ring(150)]).await;
                c.check_location(37.7699, -122.4469, Some(0.0)).await;
                c.check_location(north_of_centre(distance), -122.4469, Some(0.0)).await
            };
            assert_eq!(
                with_none.len(),
                with_zero.len(),
                "accuracy 0 moved the boundary at {distance} m",
            );
        }
    }

    /// Arrival is deliberately NOT widened — arriving early is a worse failure
    /// than flapping, and the Android mirror takes the same position.
    #[tokio::test]
    async fn widening_does_not_move_arrival() {
        let checker = BoundaryChecker::new();
        checker.load_boundaries(vec![ring(150)]).await;
        checker.check_location(north_of_centre(400.0), -122.4469, Some(5.0)).await; // primes: outside

        // 200 m out with 140 m accuracy: usable (140 <= 150), but still outside
        // the true radius, so it must not read as an arrival.
        assert!(
            checker
                .check_location(north_of_centre(200.0), -122.4469, Some(140.0))
                .await
                .is_empty(),
            "a 140 m-accurate fix 200 m out must not read as an arrival",
        );
    }
}
