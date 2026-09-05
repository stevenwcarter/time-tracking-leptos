//! `localStorage` backend.
//!
//! The `web_sys` calls are deliberately thin wrappers around the pure
//! decision functions below, which are host-testable. There is no wasm test
//! runner in this project, so anything with real logic has to live on this
//! side of that line.

use chrono::NaiveDate;

use super::{LEGACY_KEY, StorageError, codec, envelope};
use crate::date::parse_iso;

/// Which key a day's value was found under.
///
/// The two are read and decoded differently — the legacy blob predates
/// envelopes — so the scan that finds a day has to say which one it found,
/// not just that it found something.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// The dated key, `time_entry:YYYY-MM-DD`.
    Dated,
    /// The undated [`LEGACY_KEY`] blob, aliased to today.
    Legacy,
}

/// Whether the undated legacy blob stands in for `requested`'s value.
///
/// The single source of truth for the alias rule, shared by both readers:
/// [`resolve_load`] for one day's value, and [`dates_on_device`] for the
/// range scan behind the calendar, the week view, and the first-sign-in
/// import offer. Two copies of this rule would let those disagree about
/// whether a device holds anything — which, for a user whose whole dataset
/// is the undated blob, is the difference between being offered an import
/// and watching their history disappear on sign-in.
pub fn legacy_stands_in_for(requested: NaiveDate, today: NaiveDate, has_dated_value: bool) -> bool {
    requested == today && !has_dated_value
}

/// Decides what a read returns, given the raw values found at the dated key
/// and at [`LEGACY_KEY`].
///
/// `dated_raw` has already had its codec layer peeled off by the caller
/// (see [`browser::decode_stored`]), so a present dated value is returned
/// exactly as given. `legacy_raw` has not: the pre-dated `time_entry` blob
/// predates envelopes *and* the codec layer, so decoding it is part of the
/// decision this function makes.
///
/// The legacy blob is treated as **today's** entry, and only when today has
/// nothing of its own. Filing it under today is a guess — the text was
/// typed on some earlier day — but it is a *visible* guess: the user opens
/// the app and sees their work where they left it, and can move it.
/// Silently migrating it at boot would make the same guess on whatever day
/// they next happen to visit, which may be weeks later, with nothing on
/// screen to explain it.
///
/// Returns an envelope string, so the caller's unwrap path is uniform.
pub fn resolve_load(
    requested: NaiveDate,
    today: NaiveDate,
    dated_raw: Option<String>,
    legacy_raw: Option<String>,
) -> Result<Option<String>, StorageError> {
    if !legacy_stands_in_for(requested, today, dated_raw.is_some()) {
        // Either the day has its own value, or the alias does not reach it.
        // Both answers are just "whatever the dated key held".
        return Ok(dated_raw);
    }
    let Some(raw) = legacy_raw else {
        return Ok(None);
    };
    // The legacy value predates envelopes: it is a bare codec-encoded string.
    let body: String = codec::decode(&raw).map_err(|source| StorageError::Decode {
        key: LEGACY_KEY.to_string(),
        source,
    })?;
    Ok(Some(envelope::wrap(&body)))
}

/// Whether writing `written` supersedes the legacy alias.
///
/// Only a write to *today* does. Writing to another day leaves the legacy
/// value alone, because it is still aliasing today and deleting it there
/// would destroy data the user has not seen yet.
pub fn should_clear_legacy(written: NaiveDate, today: NaiveDate) -> bool {
    written == today
}

/// Picks the dated keys falling inside `[from, to]`.
///
/// Ignores the undated legacy key — [`dates_on_device`] layers that back on
/// — and anything that is not ours: a browser profile holds keys from every
/// app on the origin.
pub fn dates_from_keys(keys: &[String], from: NaiveDate, to: NaiveDate) -> Vec<NaiveDate> {
    let prefix = format!("{LEGACY_KEY}:");
    let mut out: Vec<NaiveDate> = keys
        .iter()
        .filter_map(|k| k.strip_prefix(&prefix))
        .filter_map(parse_iso)
        .filter(|d| *d >= from && *d <= to)
        .collect();
    out.sort_unstable();
    out
}

/// Every day in `[from, to]` this device holds a value for, and where each
/// one lives.
///
/// The dated keys, plus **today** when the legacy blob is aliasing it
/// (spec §7.5 step 1: the scan covers `time_entry:*` *plus the legacy key*).
/// Filtering on the `time_entry:` prefix alone cannot see the bare
/// `time_entry` key, so a user whose entire dataset is the undated blob —
/// every user who predates dated entries — would scan as holding nothing:
/// no import offer on first sign-in, no calendar dot, no week row, and their
/// history apparently gone the moment the backend flips to `Remote`.
///
/// Pure, over the key list rather than the store, so the decision this makes
/// is host-testable — there is no wasm test runner in this project, and the
/// `web_sys` callers above are only as good as this.
pub fn dates_on_device(
    keys: &[String],
    legacy_present: bool,
    today: NaiveDate,
    from: NaiveDate,
    to: NaiveDate,
) -> Vec<(NaiveDate, Source)> {
    let dated = dates_from_keys(keys, from, to);
    // `today >= from` is what keeps the alias out of a range that does not
    // contain it: the blob is attributed to today and nowhere else, so a
    // query for last week must not surface it.
    let today_in_range = today >= from && today <= to;
    // Same rule `resolve_load` applies, asked of today — the day the alias
    // points at.
    let aliased = legacy_present
        && today_in_range
        && legacy_stands_in_for(today, today, dated.contains(&today));

    let mut out: Vec<(NaiveDate, Source)> = dated
        .into_iter()
        .map(|date| (date, Source::Dated))
        .collect();
    if aliased {
        out.push((today, Source::Legacy));
        out.sort_unstable_by_key(|(date, _)| *date);
    }
    out
}

#[cfg(feature = "hydrate")]
mod browser {
    use leptos::logging::error;

    use super::*;
    use crate::date::today_local;
    use crate::storage::StorageKey;

    fn storage() -> Result<web_sys::Storage, StorageError> {
        web_sys::window()
            .and_then(|w| w.local_storage().ok().flatten())
            .ok_or(StorageError::Unavailable)
    }

    fn read(store: &web_sys::Storage, key: &str) -> Result<Option<String>, StorageError> {
        store.get_item(key).map_err(|_| StorageError::Unavailable)
    }

    /// Every key currently in the store, in whatever order the browser
    /// enumerates them. Shared by every range query, which each then filter
    /// down to the dates they care about.
    fn all_keys(store: &web_sys::Storage) -> Result<Vec<String>, StorageError> {
        let len = store.length().map_err(|_| StorageError::Unavailable)?;
        let mut keys = Vec::with_capacity(len as usize);
        for i in 0..len {
            if let Ok(Some(k)) = store.key(i) {
                keys.push(k);
            }
        }
        Ok(keys)
    }

    /// Peels the codec layer off a raw dated value, leaving the envelope
    /// string for [`super::resolve_load`] (and ultimately the seam in
    /// `mod.rs`) to unwrap.
    fn decode_stored(raw: &str, key: &str) -> Result<String, StorageError> {
        codec::decode(raw).map_err(|source| StorageError::Decode {
            key: key.to_string(),
            source,
        })
    }

    pub async fn load(key: StorageKey) -> Result<Option<String>, StorageError> {
        let store = storage()?;
        let dated = read(&store, &key.as_key())?
            .map(|raw| decode_stored(&raw, &key.as_key()))
            .transpose()?;
        let legacy = read(&store, LEGACY_KEY)?;
        resolve_load(key.date(), today_local(), dated, legacy)
    }

    pub async fn store_value(key: StorageKey, wrapped: &str) -> Result<(), StorageError> {
        let store = storage()?;
        store
            .set_item(&key.as_key(), &codec::encode(&wrapped))
            .map_err(|_| StorageError::Write { key: key.as_key() })?;

        // The alias has now been superseded for today. Removing it is what
        // makes it self-erasing after exactly one edit.
        if should_clear_legacy(key.date(), today_local()) {
            let _ = store.remove_item(LEGACY_KEY);
        }
        Ok(())
    }

    pub async fn clear(key: StorageKey) -> Result<(), StorageError> {
        let store = storage()?;
        store
            .remove_item(&key.as_key())
            .map_err(|_| StorageError::Write { key: key.as_key() })
    }

    pub async fn dates_with_entries(
        from: NaiveDate,
        to: NaiveDate,
    ) -> Result<Vec<NaiveDate>, StorageError> {
        let store = storage()?;
        let keys = all_keys(&store)?;
        let legacy_present = read(&store, LEGACY_KEY)?.is_some();
        Ok(
            dates_on_device(&keys, legacy_present, today_local(), from, to)
                .into_iter()
                .map(|(date, _)| date)
                .collect(),
        )
    }

    /// The envelope string for one day, or `None` if the key it names has
    /// since gone.
    ///
    /// Returns an envelope in both cases, so the caller's unwrap path is
    /// uniform: [`super::resolve_load`] is the one place that knows how to
    /// normalize the pre-envelope legacy blob, so the legacy branch goes
    /// through it rather than repeating that decode here.
    fn body_for(
        store: &web_sys::Storage,
        date: NaiveDate,
        source: Source,
        legacy_raw: Option<&str>,
    ) -> Result<Option<String>, StorageError> {
        match source {
            Source::Dated => {
                let key = StorageKey::TimeEntry(date).as_key();
                read(store, &key)?
                    .map(|raw| decode_stored(&raw, &key))
                    .transpose()
            }
            // `date` is today here by construction — `dates_on_device` emits
            // `Legacy` for no other day — so passing it as both arguments
            // asks exactly the question the alias rule answers.
            Source::Legacy => resolve_load(date, date, None, legacy_raw.map(str::to_owned)),
        }
    }

    /// Reads every entry in `[from, to]`, skipping days that were never
    /// written, and including the legacy blob under today when it is
    /// aliasing (see [`super::dates_on_device`]).
    pub async fn bodies_in_range(
        from: NaiveDate,
        to: NaiveDate,
    ) -> Result<Vec<(NaiveDate, String)>, StorageError> {
        let store = storage()?;
        let keys = all_keys(&store)?;
        let legacy_raw = read(&store, LEGACY_KEY)?;
        let mut out = Vec::new();
        for (date, source) in dates_on_device(&keys, legacy_raw.is_some(), today_local(), from, to)
        {
            // Logged and skipped, never propagated: `?` here would scope one
            // undecodable day to the whole range, and the week view would
            // render "Nothing logged this week." over six good days. Mirrors
            // `storage::unwrap_bodies`, which makes the same call one layer
            // up at the envelope.
            match body_for(&store, date, source, legacy_raw.as_deref()) {
                Ok(Some(body)) => out.push((date, body)),
                Ok(None) => {}
                Err(err) => error!("skipping {date}: {err}"),
            }
        }
        Ok(out)
    }
}

#[cfg(feature = "hydrate")]
pub use browser::{bodies_in_range, clear, dates_with_entries, load, store_value as store};

#[cfg(test)]
mod tests {
    use super::*;

    fn d(y: i32, m: u32, day: u32) -> chrono::NaiveDate {
        chrono::NaiveDate::from_ymd_opt(y, m, day).expect("valid date")
    }
    const TODAY: fn() -> chrono::NaiveDate =
        || chrono::NaiveDate::from_ymd_opt(2026, 9, 4).expect("valid date");

    /// A dated value always wins, and comes back as-is.
    #[test]
    fn dated_value_is_used_when_present() {
        let dated = Some(envelope::wrap("dated-body"));
        let legacy = Some("\"legacy-body\"".to_string());
        let got = resolve_load(d(2026, 9, 4), TODAY(), dated.clone(), legacy).expect("resolve");
        assert_eq!(got, dated);
    }

    /// Invariant I3: the legacy blob surfaces for today when nothing dated
    /// exists — this is what makes an existing user's data appear where they
    /// left it rather than vanishing.
    #[test]
    fn legacy_value_surfaces_for_today() {
        let legacy = Some("\"legacy-body\"".to_string());
        let got = resolve_load(d(2026, 9, 4), TODAY(), None, legacy).expect("resolve");
        assert_eq!(
            got,
            Some(envelope::wrap("legacy-body")),
            "the legacy value must be normalized into an envelope"
        );
    }

    /// Invariant I3: and only for today. Attributing it to every empty day
    /// would show the same text on every date in the calendar.
    #[test]
    fn legacy_value_does_not_surface_for_another_day() {
        let legacy = Some("\"legacy-body\"".to_string());
        assert_eq!(
            resolve_load(d(2026, 9, 3), TODAY(), None, legacy).expect("resolve"),
            None
        );
    }

    /// Invariant I3: once today has its own value the alias is finished,
    /// even if the legacy key has not been cleaned up yet.
    #[test]
    fn legacy_value_is_ignored_once_a_dated_value_exists() {
        let dated = Some(envelope::wrap(""));
        let legacy = Some("\"legacy-body\"".to_string());
        let got = resolve_load(d(2026, 9, 4), TODAY(), dated.clone(), legacy).expect("resolve");
        assert_eq!(got, dated, "an empty-but-present dated value still wins");
    }

    #[test]
    fn absent_everywhere_is_none() {
        assert_eq!(
            resolve_load(d(2026, 9, 4), TODAY(), None, None).expect("resolve"),
            None
        );
    }

    /// A corrupt legacy value must be an error the caller can log, not a
    /// silent "you have no data".
    #[test]
    fn undecodable_legacy_value_is_an_error() {
        let legacy = Some("this is not codec-encoded".to_string());
        assert!(resolve_load(d(2026, 9, 4), TODAY(), None, legacy).is_err());
    }

    /// Invariant I3: the alias is self-erasing, but only when the write that
    /// supersedes it is today's. Writing to yesterday must leave the legacy
    /// value intact, because it still aliases today.
    #[test]
    fn legacy_is_cleared_only_by_writing_today() {
        assert!(should_clear_legacy(d(2026, 9, 4), TODAY()));
        assert!(!should_clear_legacy(d(2026, 9, 3), TODAY()));
        assert!(!should_clear_legacy(d(2026, 9, 5), TODAY()));
    }

    #[test]
    fn key_scan_selects_dates_in_range_only() {
        let keys = vec![
            "time_entry:2026-08-31".to_string(),
            "time_entry:2026-09-04".to_string(),
            "time_entry:2026-09-30".to_string(),
            "time_entry".to_string(), // legacy, undated
            "some_other_key".to_string(),
            "time_entry:not-a-date".to_string(),
        ];
        let got = dates_from_keys(&keys, d(2026, 9, 1), d(2026, 9, 10));
        assert_eq!(got, vec![d(2026, 9, 4)]);
    }

    /// Invariant I3, at range width. The regression this guards against is
    /// the one that strands every pre-dating user: their whole dataset is
    /// the bare `time_entry` key, which no `time_entry:` prefix filter can
    /// see. A scan that misses it reports the device as empty, so
    /// `ImportBanner` never offers the import (spec §7.5 step 1) and their
    /// history vanishes when sign-in flips the backend to `Remote`.
    #[test]
    fn a_legacy_only_device_holds_today() {
        let got = dates_on_device(&[], true, TODAY(), d(2026, 9, 1), d(2026, 9, 30));
        assert_eq!(
            got,
            vec![(TODAY(), Source::Legacy)],
            "the undated blob must be offered under today"
        );
    }

    /// The other half of the alias rule: once today has a dated value the
    /// blob is finished, and reporting it too would double-count today.
    #[test]
    fn the_legacy_blob_is_not_offered_when_today_is_already_dated() {
        let keys = vec!["time_entry:2026-09-04".to_string()];
        let got = dates_on_device(&keys, true, TODAY(), d(2026, 9, 1), d(2026, 9, 30));
        assert_eq!(got, vec![(TODAY(), Source::Dated)]);
    }

    /// The blob is attributed to today and to nowhere else, so a range that
    /// does not reach today must not surface it — otherwise last week's view
    /// would show today's text under a day the user never typed it on.
    #[test]
    fn the_legacy_blob_is_not_offered_outside_the_range() {
        let got = dates_on_device(&[], true, TODAY(), d(2026, 8, 1), d(2026, 8, 31));
        assert!(got.is_empty(), "today is not in [Aug 1, Aug 31]");
    }

    /// With no legacy key the scan is exactly the dated scan it always was.
    #[test]
    fn without_a_legacy_key_the_scan_is_unchanged() {
        let keys = vec![
            "time_entry:2026-09-03".to_string(),
            "time_entry:2026-09-04".to_string(),
            "some_other_key".to_string(),
        ];
        let got = dates_on_device(&keys, false, TODAY(), d(2026, 9, 1), d(2026, 9, 30));
        assert_eq!(
            got,
            vec![(d(2026, 9, 3), Source::Dated), (TODAY(), Source::Dated)]
        );
    }

    /// A part-migrated device: some dated days, plus the blob still aliasing
    /// today. The result must stay sorted, because the week view renders it
    /// in order.
    #[test]
    fn the_legacy_day_sorts_in_with_the_dated_ones() {
        let keys = vec![
            "time_entry:2026-09-05".to_string(),
            "time_entry:2026-09-02".to_string(),
        ];
        let got = dates_on_device(&keys, true, TODAY(), d(2026, 9, 1), d(2026, 9, 30));
        assert_eq!(
            got,
            vec![
                (d(2026, 9, 2), Source::Dated),
                (TODAY(), Source::Legacy),
                (d(2026, 9, 5), Source::Dated),
            ]
        );
    }
}
