//! Reusable, per-user timing profiles — the *shape* of a scan's target-facing
//! pacing.
//!
//! Pacing today is a single uniform delay window; a **timing profile** makes the
//! shape a first-class, reusable choice. A profile pairs a name with a
//! [`PacingPolicy`] (the delay distribution the rate limiter draws from), spanning
//! from fast to highly cautious and including an **organic**, heavy-tailed shape
//! whose gaps imitate irregular, non-periodic traffic.
//!
//! Profiles are **owned by a user** and private to them (like scan sessions and
//! annotations): each user's set is seeded from the [built-in library](builtin_library)
//! on first use and is extendable — a user can add their own or adjust one. The
//! store enforces ownership on every read and write, so one user never sees or
//! edits another's profiles.
//!
//! A profile only parameterizes the base-delay draw and its floor. The adaptive
//! backoff and the target-distress halt live in the [`RateLimiter`] outside any
//! policy and apply under every profile (see [`RateLimiter::acquire_with`]), so no
//! profile — not even the fast one — can turn the scanner into something that
//! keeps hammering a target through distress signals.
//!
//! [`RateLimiter`]: crate::rate_limiter::RateLimiter
//! [`RateLimiter::acquire_with`]: crate::rate_limiter::RateLimiter::acquire_with

use crate::error::{Error, Result, db_err};
use crate::persistence::DatabaseManager;
use crate::rate_limiter::PacingPolicy;

/// The per-scan option key carrying the **resolved** pacing policy a scan runs
/// under (a JSON-encoded [`PacingPolicy`]). A surface resolves the operator's
/// profile selection to a concrete policy at scan start and records it here; the
/// orchestrator reads it back and hands it to the rate limiter for target traffic.
/// Absent ⇒ the conservative default applies.
pub const TIMING_POLICY_OPTION: &str = "timing_policy";

/// The name of the conservative default profile (today's uniform 1–3s pacing).
/// Applied when a scan selects no profile.
pub const DEFAULT_PROFILE_NAME: &str = "Steady";

/// A named, reusable pacing shape owned by one user.
#[derive(Debug, Clone, PartialEq)]
pub struct TimingProfile {
    /// Stable per-row id (owner-scoped when addressed).
    pub id: i64,
    /// The owning user's id. A profile is only ever visible/editable by its owner.
    pub owner_user_id: i64,
    /// Human-facing name, unique within the owner's set.
    pub name: String,
    /// The delay distribution the rate limiter draws from for this profile.
    pub policy: PacingPolicy,
    /// Whether this row came from the seeded built-in library (vs. user-created).
    /// The management UI uses it to label built-ins; ownership/visibility do not
    /// depend on it.
    pub built_in: bool,
}

/// The built-in library: a small, opinionated set spanning the finish-fast ↔
/// stay-invisible axis, including the organic thesis profile and the conservative
/// [default](DEFAULT_PROFILE_NAME). Every user's set is seeded from this.
///
/// Exact names/parameters are guidance (the spec pins the *shape*): a spectrum
/// from faster to more cautious, an organic model, and a conservative default.
pub fn builtin_library() -> Vec<(&'static str, PacingPolicy)> {
    vec![
        // Small delay for authorized / lab targets where speed wins.
        ("Fast", PacingPolicy::uniform(0.2, 0.8)),
        // Today's conservative uniform 1–3s window — the default.
        (DEFAULT_PROFILE_NAME, PacingPolicy::uniform(1.0, 3.0)),
        // A wider, slower window.
        ("Cautious", PacingPolicy::uniform(3.0, 8.0)),
        // Irregular, non-periodic, heavy-tailed gaps — the "looks organic" shape.
        (
            "Organic",
            PacingPolicy::Organic {
                min_secs: 0.75,
                median_secs: 2.5,
                max_secs: 7.0,
                long_pause_prob: 0.12,
                long_pause_secs: 30.0,
            },
        ),
        // Long organic gaps with a heavy tail — the most sensitive engagements.
        (
            "Paranoid",
            PacingPolicy::Organic {
                min_secs: 4.0,
                median_secs: 12.0,
                max_secs: 30.0,
                long_pause_prob: 0.15,
                long_pause_secs: 120.0,
            },
        ),
    ]
}

/// The per-user timing-profile authority over the shared store. Cheap to clone
/// (the inner [`DatabaseManager`] is a reference-counted pool).
#[derive(Debug, Clone)]
pub struct TimingProfileStore {
    db: DatabaseManager,
}

impl TimingProfileStore {
    /// Build over a [`DatabaseManager`] (the store must already be migrated, which
    /// it is after [`DatabaseManager::connect`]).
    pub fn from_database(db: &DatabaseManager) -> Self {
        Self { db: db.clone() }
    }

    /// Ensure `user_id`'s built-in profiles exist, idempotently. Seeds any missing
    /// library entry (keyed by `(owner, name)`) and never overwrites one the user
    /// has since adjusted — re-running against a fully seeded set touches nothing.
    /// Called on the read/resolve paths so every user has the library on first use
    /// without a registration-time hook.
    pub async fn ensure_seeded_for_user(&self, user_id: i64) -> Result<()> {
        let mut tx = self.db.pool().begin().await.map_err(db_err)?;
        for (name, policy) in builtin_library() {
            let policy_json = serde_json::to_string(&policy).map_err(db_err)?;
            sqlx::query(
                "INSERT OR IGNORE INTO timing_profiles \
                   (owner_user_id, name, policy_json, built_in) \
                 VALUES (?, ?, ?, 1)",
            )
            .bind(user_id)
            .bind(name)
            .bind(policy_json)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
        }
        tx.commit().await.map_err(db_err)?;
        Ok(())
    }

    /// Every profile owned by `user_id`, seeding the built-ins first so a fresh
    /// user always has the library. Ordered by id (built-ins first, in library
    /// order, then the user's additions).
    pub async fn list_for_user(&self, user_id: i64) -> Result<Vec<TimingProfile>> {
        self.ensure_seeded_for_user(user_id).await?;
        let rows = sqlx::query(
            "SELECT id, owner_user_id, name, policy_json, built_in \
             FROM timing_profiles WHERE owner_user_id = ? ORDER BY id ASC",
        )
        .bind(user_id)
        .fetch_all(self.db.pool())
        .await
        .map_err(db_err)?;
        rows.iter().map(row_to_profile).collect()
    }

    /// One profile by id, **owner-scoped**: a row owned by another user (or an
    /// absent id) yields `None`, never the row. This is the ownership gate — a
    /// caller can never resolve a profile it does not own.
    pub async fn get_for_user(&self, user_id: i64, id: i64) -> Result<Option<TimingProfile>> {
        let row = sqlx::query(
            "SELECT id, owner_user_id, name, policy_json, built_in \
             FROM timing_profiles WHERE id = ? AND owner_user_id = ?",
        )
        .bind(id)
        .bind(user_id)
        .fetch_optional(self.db.pool())
        .await
        .map_err(db_err)?;
        row.as_ref().map(row_to_profile).transpose()
    }

    /// Add a profile owned by `user_id`. The name is trimmed and must be non-empty
    /// and unique within the owner's set (a duplicate is rejected). Returns the
    /// created profile.
    pub async fn create(
        &self,
        user_id: i64,
        name: &str,
        policy: &PacingPolicy,
    ) -> Result<TimingProfile> {
        self.ensure_seeded_for_user(user_id).await?;
        let name = validate_name(name)?;
        let policy_json = serde_json::to_string(policy).map_err(db_err)?;

        let existing: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM timing_profiles WHERE owner_user_id = ? AND name = ?",
        )
        .bind(user_id)
        .bind(&name)
        .fetch_one(self.db.pool())
        .await
        .map_err(db_err)?;
        if existing > 0 {
            return Err(Error::Other(format!(
                "a timing profile named {name:?} already exists"
            )));
        }

        let id = sqlx::query(
            "INSERT INTO timing_profiles (owner_user_id, name, policy_json, built_in) \
             VALUES (?, ?, ?, 0)",
        )
        .bind(user_id)
        .bind(&name)
        .bind(&policy_json)
        .execute(self.db.pool())
        .await
        .map_err(db_err)?
        .last_insert_rowid();

        Ok(TimingProfile {
            id,
            owner_user_id: user_id,
            name,
            policy: policy.clone(),
            built_in: false,
        })
    }

    /// Adjust an existing profile's name and/or policy, **owner-scoped**: updating
    /// a row the user does not own affects nothing and returns `Error::Other`. The
    /// new name must be non-empty and not collide with another of the user's
    /// profiles. A built-in the user adjusts keeps its `built_in` flag (so it is
    /// still labeled as such) but carries the user's parameters thereafter.
    pub async fn update(
        &self,
        user_id: i64,
        id: i64,
        name: &str,
        policy: &PacingPolicy,
    ) -> Result<TimingProfile> {
        let current = self
            .get_for_user(user_id, id)
            .await?
            .ok_or_else(|| Error::Other("timing profile not found".to_string()))?;
        let name = validate_name(name)?;
        let policy_json = serde_json::to_string(policy).map_err(db_err)?;

        // Reject a rename that would collide with a *different* profile of the user.
        let clash: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM timing_profiles \
             WHERE owner_user_id = ? AND name = ? AND id <> ?",
        )
        .bind(user_id)
        .bind(&name)
        .bind(id)
        .fetch_one(self.db.pool())
        .await
        .map_err(db_err)?;
        if clash > 0 {
            return Err(Error::Other(format!(
                "a timing profile named {name:?} already exists"
            )));
        }

        sqlx::query(
            "UPDATE timing_profiles SET name = ?, policy_json = ? \
             WHERE id = ? AND owner_user_id = ?",
        )
        .bind(&name)
        .bind(&policy_json)
        .bind(id)
        .bind(user_id)
        .execute(self.db.pool())
        .await
        .map_err(db_err)?;

        Ok(TimingProfile {
            id,
            owner_user_id: user_id,
            name,
            policy: policy.clone(),
            built_in: current.built_in,
        })
    }
}

/// Trim + validate a profile name: non-empty after trimming, bounded length.
fn validate_name(name: &str) -> Result<String> {
    let name = name.trim();
    if name.is_empty() {
        return Err(Error::Other("timing profile name is required".to_string()));
    }
    if name.chars().count() > 60 {
        return Err(Error::Other(
            "timing profile name is too long (max 60 characters)".to_string(),
        ));
    }
    Ok(name.to_string())
}

/// Map a `timing_profiles` row into a [`TimingProfile`], decoding its policy JSON.
fn row_to_profile(row: &sqlx::sqlite::SqliteRow) -> Result<TimingProfile> {
    use sqlx::Row;
    let policy_json: String = row.try_get("policy_json").map_err(db_err)?;
    let policy: PacingPolicy = serde_json::from_str(&policy_json).map_err(db_err)?;
    Ok(TimingProfile {
        id: row.try_get("id").map_err(db_err)?,
        owner_user_id: row.try_get("owner_user_id").map_err(db_err)?,
        name: row.try_get("name").map_err(db_err)?,
        policy,
        built_in: row.try_get::<i64, _>("built_in").map_err(db_err)? != 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn library_spans_fast_to_cautious_and_includes_organic_and_default() {
        let lib = builtin_library();
        assert!(lib.len() >= 4, "library should offer several profiles");

        // A conservative default is present.
        assert!(
            lib.iter().any(|(name, _)| *name == DEFAULT_PROFILE_NAME),
            "the conservative default profile must be in the library"
        );

        // At least one organic (heavy-tailed) profile is present.
        assert!(
            lib.iter()
                .any(|(_, p)| matches!(p, PacingPolicy::Organic { .. })),
            "the library must include an organic profile"
        );

        // The spectrum spans faster→cautious: the fastest floor is well below the
        // slowest floor.
        let floors: Vec<f64> = lib
            .iter()
            .map(|(_, p)| match p {
                PacingPolicy::Uniform { min_secs, .. } => *min_secs,
                PacingPolicy::Organic { min_secs, .. } => *min_secs,
            })
            .collect();
        let min = floors.iter().cloned().fold(f64::INFINITY, f64::min);
        let max = floors.iter().cloned().fold(0.0_f64, f64::max);
        assert!(max > min, "library should span a range of pacing floors");
    }

    #[test]
    fn name_validation_trims_and_rejects_empty() {
        assert_eq!(validate_name("  Fast  ").unwrap(), "Fast");
        assert!(validate_name("   ").is_err());
        assert!(validate_name(&"x".repeat(61)).is_err());
    }

    // The web layer serializes a resolved policy into the `TIMING_POLICY_OPTION`
    // scan option and the orchestrator deserializes it back; every built-in shape
    // must survive that round-trip so a selected profile actually reaches pacing.
    #[test]
    fn policy_round_trips_through_the_option_value() {
        for (_, policy) in builtin_library() {
            let json = serde_json::to_string(&policy).unwrap();
            let back: PacingPolicy = serde_json::from_str(&json).unwrap();
            assert_eq!(back, policy, "policy did not survive the option round-trip");
        }
    }
}
