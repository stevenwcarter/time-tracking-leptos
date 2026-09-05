//! `localStorage` backend.
//!
//! The `web_sys` calls are deliberately thin wrappers around the pure
//! decision functions below, which are host-testable. There is no wasm test
//! runner in this project, so anything with real logic has to live on this
//! side of that line.

use chrono::NaiveDate;

use super::{LEGACY_KEY, StorageError, codec, envelope};
use crate::date::parse_iso;

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
    if let Some(raw) = dated_raw {
        return Ok(Some(raw));
    }
    if requested != today {
        return Ok(None);
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
/// Ignores the undated legacy key and anything that is not ours: a browser
/// profile holds keys from every app on the origin.
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

#[cfg(feature = "hydrate")]
mod browser {
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
        Ok(dates_from_keys(&keys, from, to))
    }

    /// Reads every dated entry in `[from, to]`, skipping days that were
    /// never written. Like [`dates_with_entries`], this only ever sees the
    /// dated keys — the undated legacy alias for today is not considered,
    /// the same limitation `dates_with_entries` already has.
    pub async fn bodies_in_range(
        from: NaiveDate,
        to: NaiveDate,
    ) -> Result<Vec<(NaiveDate, String)>, StorageError> {
        let store = storage()?;
        let keys = all_keys(&store)?;
        let mut out = Vec::new();
        for date in dates_from_keys(&keys, from, to) {
            let key = StorageKey::TimeEntry(date).as_key();
            if let Some(raw) = read(&store, &key)? {
                out.push((date, decode_stored(&raw, &key)?));
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
}
