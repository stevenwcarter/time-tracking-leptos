//! Calendar arithmetic shared by both targets.
//!
//! Weeks run Monday to Sunday (ISO 8601). The URL carries dates as
//! `YYYY-MM-DD`, which sorts lexically — that is why `time_entry.entry_date`
//! is TEXT and why range queries can use a plain `BETWEEN`.

use chrono::{Datelike, Days, NaiveDate};

/// Parses a `YYYY-MM-DD` URL segment. Strict: anything else is `None`.
///
/// `chrono`'s `%m`/`%d` accept non-zero-padded input (`"2026-9-4"` parses as
/// 2026-09-04), which is too lenient for a value coming straight off the
/// URL. The round trip through [`to_iso`] catches that: a loosely-formatted
/// input reformats to something other than what was typed.
pub fn parse_iso(raw: &str) -> Option<NaiveDate> {
    let date = NaiveDate::parse_from_str(raw, "%Y-%m-%d").ok()?;
    (to_iso(date) == raw).then_some(date)
}

/// Renders a date the way the URL and the database both store it.
pub fn to_iso(date: NaiveDate) -> String {
    date.format("%Y-%m-%d").to_string()
}

/// The Monday and Sunday bracketing `date`, inclusive.
pub fn week_bounds(date: NaiveDate) -> (NaiveDate, NaiveDate) {
    let from_monday = date.weekday().num_days_from_monday() as u64;
    let start = date - Days::new(from_monday);
    let end = start + Days::new(6);
    (start, end)
}

/// The first and last day of `date`'s month, inclusive.
pub fn month_bounds(date: NaiveDate) -> (NaiveDate, NaiveDate) {
    let start = date.with_day(1).expect("day 1 exists in every month");
    // Walk to the first of the next month, then step back one day. Avoids a
    // per-month length table and gets February right in leap years.
    let next_month = if start.month() == 12 {
        NaiveDate::from_ymd_opt(start.year() + 1, 1, 1)
    } else {
        NaiveDate::from_ymd_opt(start.year(), start.month() + 1, 1)
    }
    .expect("first of next month is a valid date");
    (start, next_month - Days::new(1))
}

/// The label shown in the header, e.g. "Friday, Sep 4".
pub fn format_long(date: NaiveDate) -> String {
    date.format("%A, %b %-d").to_string()
}

/// The browser's local calendar date.
///
/// Only the browser can answer this: the server does not know the visitor's
/// timezone, which is why `/` renders its date slot blank and the client
/// replaces the URL after hydration (spec §8.1).
#[cfg(feature = "hydrate")]
pub fn today_local() -> NaiveDate {
    chrono::Local::now().date_naive()
}

/// The server's UTC date. Used only where a date is needed for logging or a
/// token expiry — never to decide which day a user is looking at.
#[cfg(feature = "ssr")]
pub fn today_utc() -> NaiveDate {
    chrono::Utc::now().date_naive()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(y: i32, m: u32, day: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(y, m, day).expect("valid date")
    }

    #[test]
    fn parses_and_formats_iso() {
        assert_eq!(parse_iso("2026-09-04"), Some(d(2026, 9, 4)));
        assert_eq!(to_iso(d(2026, 9, 4)), "2026-09-04");
    }

    /// The date segment comes straight off the URL, so every junk shape a
    /// user or crawler can put there must be rejected rather than panic.
    #[test]
    fn rejects_non_dates() {
        for junk in [
            "", "account", "favicon.ico", "2026-13-01", "2026-02-30",
            "2026-9-4", "20260904", "2026-09-04T00:00:00",
        ] {
            assert_eq!(parse_iso(junk), None, "{junk:?} must not parse");
        }
    }

    #[test]
    fn week_runs_monday_to_sunday() {
        // 2026-09-04 is a Friday.
        let (start, end) = week_bounds(d(2026, 9, 4));
        assert_eq!(start, d(2026, 8, 31), "week starts Monday");
        assert_eq!(end, d(2026, 9, 6), "week ends Sunday");
    }

    #[test]
    fn week_bounds_are_stable_at_the_edges() {
        // A Monday is its own week start; a Sunday is its own week end.
        let (mon_start, _) = week_bounds(d(2026, 8, 31));
        assert_eq!(mon_start, d(2026, 8, 31));
        let (_, sun_end) = week_bounds(d(2026, 9, 6));
        assert_eq!(sun_end, d(2026, 9, 6));
    }

    /// A week spanning a year boundary is the case an off-by-one hides in.
    #[test]
    fn week_spans_a_year_boundary() {
        // 2027-01-01 is a Friday.
        let (start, end) = week_bounds(d(2027, 1, 1));
        assert_eq!(start, d(2026, 12, 28));
        assert_eq!(end, d(2027, 1, 3));
    }

    #[test]
    fn month_bounds_cover_the_whole_month() {
        assert_eq!(month_bounds(d(2026, 9, 4)), (d(2026, 9, 1), d(2026, 9, 30)));
        assert_eq!(month_bounds(d(2026, 12, 9)), (d(2026, 12, 1), d(2026, 12, 31)));
        // February in a leap year — the case a naive "day 28" gets wrong.
        assert_eq!(month_bounds(d(2028, 2, 5)), (d(2028, 2, 1), d(2028, 2, 29)));
    }

    #[test]
    fn formats_a_human_label() {
        assert_eq!(format_long(d(2026, 9, 4)), "Friday, Sep 4");
    }
}
