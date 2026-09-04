//! The `time_entry` table: one row per user per calendar day.
//!
//! `body` is an **opaque string** to this module and to every caller above
//! it. Nothing here parses, validates, or inspects it — phase 2 stores
//! ciphertext in this column and the server will not hold the key
//! (spec section 9.1).
//!
//! `entry_date` is TEXT holding `YYYY-MM-DD`, which sorts lexically in the
//! same order it sorts chronologically. That is what lets range queries use
//! a plain inclusive `BETWEEN` and still come back date-ordered.

use anyhow::{Context, Result};
use chrono::{NaiveDate, Utc};
use diesel::prelude::*;

use crate::date::{parse_iso, to_iso};
use crate::db::DbConn;
use crate::schema::time_entry;

#[derive(Insertable)]
#[diesel(table_name = time_entry)]
struct NewEntry<'a> {
    user_id: i32,
    entry_date: &'a str,
    body: &'a str,
    updated_at: chrono::NaiveDateTime,
}

/// Reads one day's stored body.
pub fn load(conn: &mut DbConn, user_id: i32, date: NaiveDate) -> Result<Option<String>> {
    time_entry::table
        .filter(time_entry::user_id.eq(user_id))
        .filter(time_entry::entry_date.eq(to_iso(date)))
        .select(time_entry::body)
        .first::<String>(conn)
        .optional()
        .context("select time_entry")
}

/// Writes one day's body, replacing any previous value for that day.
pub fn save(conn: &mut DbConn, user_id: i32, date: NaiveDate, body: &str) -> Result<()> {
    let iso = to_iso(date);
    let now = Utc::now().naive_utc();
    diesel::insert_into(time_entry::table)
        .values(NewEntry {
            user_id,
            entry_date: &iso,
            body,
            updated_at: now,
        })
        .on_conflict((time_entry::user_id, time_entry::entry_date))
        .do_update()
        .set((time_entry::body.eq(body), time_entry::updated_at.eq(now)))
        .execute(conn)
        .context("upsert time_entry")?;
    Ok(())
}

/// The days in `[from, to]` that have an entry. **Dates only** — the calendar
/// needs to place dots, and shipping every body in the month to answer that
/// would leak far more than the question asks.
pub fn dates_in_range(
    conn: &mut DbConn,
    user_id: i32,
    from: NaiveDate,
    to: NaiveDate,
) -> Result<Vec<NaiveDate>> {
    let rows: Vec<String> = time_entry::table
        .filter(time_entry::user_id.eq(user_id))
        .filter(time_entry::entry_date.between(to_iso(from), to_iso(to)))
        .order(time_entry::entry_date.asc())
        .select(time_entry::entry_date)
        .load(conn)
        .context("select entry dates in range")?;
    // A row whose date fails to parse would mean a corrupt write; skipping it
    // beats failing the whole range and blanking the calendar.
    Ok(rows.iter().filter_map(|s| parse_iso(s)).collect())
}

/// Every entry in `[from, to]`, bodies included and opaque.
pub fn entries_in_range(
    conn: &mut DbConn,
    user_id: i32,
    from: NaiveDate,
    to: NaiveDate,
) -> Result<Vec<(NaiveDate, String)>> {
    let rows: Vec<(String, String)> = time_entry::table
        .filter(time_entry::user_id.eq(user_id))
        .filter(time_entry::entry_date.between(to_iso(from), to_iso(to)))
        .order(time_entry::entry_date.asc())
        .select((time_entry::entry_date, time_entry::body))
        .load(conn)
        .context("select entries in range")?;
    Ok(rows
        .into_iter()
        .filter_map(|(d, b)| parse_iso(&d).map(|d| (d, b)))
        .collect())
}

#[cfg(all(test, feature = "ssr"))]
mod tests {
    use super::*;
    use crate::auth::user;
    use crate::db::{DbConn, test_pool};

    fn d(y: i32, m: u32, day: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(y, m, day).expect("valid date")
    }

    fn user_id(conn: &mut DbConn, email: &str) -> i32 {
        user::find_or_create(conn, email).expect("create user").id
    }

    #[test]
    fn save_then_load_round_trips() {
        let pool = test_pool();
        let mut conn = pool.get().expect("checkout");
        let uid = user_id(&mut conn, "alice@example.com");
        save(&mut conn, uid, d(2026, 9, 4), "body-text").expect("save");
        assert_eq!(
            load(&mut conn, uid, d(2026, 9, 4)).expect("load"),
            Some("body-text".to_string())
        );
    }

    #[test]
    fn load_misses_cleanly() {
        let pool = test_pool();
        let mut conn = pool.get().expect("checkout");
        let uid = user_id(&mut conn, "alice@example.com");
        assert_eq!(load(&mut conn, uid, d(2026, 9, 4)).expect("load"), None);
    }

    /// Saving the same day twice must update, not accumulate rows or fail on
    /// the composite primary key.
    #[test]
    fn save_is_an_upsert() {
        let pool = test_pool();
        let mut conn = pool.get().expect("checkout");
        let uid = user_id(&mut conn, "alice@example.com");
        save(&mut conn, uid, d(2026, 9, 4), "first").expect("save");
        save(&mut conn, uid, d(2026, 9, 4), "second").expect("save");
        assert_eq!(
            load(&mut conn, uid, d(2026, 9, 4)).expect("load"),
            Some("second".to_string())
        );
        assert_eq!(
            dates_in_range(&mut conn, uid, d(2026, 9, 1), d(2026, 9, 30))
                .expect("range")
                .len(),
            1
        );
    }

    /// Range bounds are inclusive on both ends. An exclusive upper bound
    /// silently drops the last day of every week and month view.
    #[test]
    fn range_bounds_are_inclusive() {
        let pool = test_pool();
        let mut conn = pool.get().expect("checkout");
        let uid = user_id(&mut conn, "alice@example.com");
        for day in [31, 1, 2, 6, 7] {
            let date = if day == 31 {
                d(2026, 8, 31)
            } else {
                d(2026, 9, day)
            };
            save(&mut conn, uid, date, "x").expect("save");
        }
        let got = dates_in_range(&mut conn, uid, d(2026, 8, 31), d(2026, 9, 6)).expect("range");
        assert_eq!(
            got,
            vec![d(2026, 8, 31), d(2026, 9, 1), d(2026, 9, 2), d(2026, 9, 6)]
        );
    }

    #[test]
    fn range_results_are_date_ordered() {
        let pool = test_pool();
        let mut conn = pool.get().expect("checkout");
        let uid = user_id(&mut conn, "alice@example.com");
        for date in [d(2026, 9, 9), d(2026, 9, 2), d(2026, 9, 30), d(2026, 9, 10)] {
            save(&mut conn, uid, date, "x").expect("save");
        }
        let got = dates_in_range(&mut conn, uid, d(2026, 9, 1), d(2026, 9, 30)).expect("range");
        assert_eq!(
            got,
            vec![d(2026, 9, 2), d(2026, 9, 9), d(2026, 9, 10), d(2026, 9, 30)],
            "TEXT dates must sort chronologically, not 10 before 2"
        );
    }

    #[test]
    fn entries_in_range_returns_bodies() {
        let pool = test_pool();
        let mut conn = pool.get().expect("checkout");
        let uid = user_id(&mut conn, "alice@example.com");
        save(&mut conn, uid, d(2026, 9, 1), "one").expect("save");
        save(&mut conn, uid, d(2026, 9, 3), "three").expect("save");
        assert_eq!(
            entries_in_range(&mut conn, uid, d(2026, 9, 1), d(2026, 9, 7)).expect("range"),
            vec![
                (d(2026, 9, 1), "one".to_string()),
                (d(2026, 9, 3), "three".to_string())
            ]
        );
    }

    /// Pins invariant I7 for reads. Every query is scoped by user_id; a user
    /// must never observe another user's rows through any range or point read.
    #[test]
    fn reads_are_scoped_to_the_owning_user() {
        let pool = test_pool();
        let mut conn = pool.get().expect("checkout");
        let alice = user_id(&mut conn, "alice@example.com");
        let mallory = user_id(&mut conn, "mallory@example.com");
        save(&mut conn, alice, d(2026, 9, 4), "alice-secret").expect("save");

        assert_eq!(load(&mut conn, mallory, d(2026, 9, 4)).expect("load"), None);
        assert!(
            dates_in_range(&mut conn, mallory, d(2026, 1, 1), d(2026, 12, 31))
                .expect("range")
                .is_empty()
        );
        assert!(
            entries_in_range(&mut conn, mallory, d(2026, 1, 1), d(2026, 12, 31))
                .expect("range")
                .is_empty()
        );
    }

    /// A write by one user must not overwrite another's row for the same day.
    #[test]
    fn writes_are_scoped_to_the_owning_user() {
        let pool = test_pool();
        let mut conn = pool.get().expect("checkout");
        let alice = user_id(&mut conn, "alice@example.com");
        let mallory = user_id(&mut conn, "mallory@example.com");
        save(&mut conn, alice, d(2026, 9, 4), "alice-body").expect("save");
        save(&mut conn, mallory, d(2026, 9, 4), "mallory-body").expect("save");
        assert_eq!(
            load(&mut conn, alice, d(2026, 9, 4)).expect("load"),
            Some("alice-body".to_string())
        );
    }

    /// Deleting a user must take their entries with them, which only works
    /// if the foreign_keys PRAGMA is actually on.
    #[test]
    fn deleting_a_user_cascades_to_entries() {
        use crate::schema::user as user_table;
        let pool = test_pool();
        let mut conn = pool.get().expect("checkout");
        let uid = user_id(&mut conn, "alice@example.com");
        save(&mut conn, uid, d(2026, 9, 4), "x").expect("save");
        diesel::delete(user_table::table.find(uid))
            .execute(&mut conn)
            .expect("delete user");
        assert!(
            entries_in_range(&mut conn, uid, d(2026, 1, 1), d(2026, 12, 31))
                .expect("range")
                .is_empty()
        );
    }
}
