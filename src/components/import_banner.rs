//! "Import N days from this device?" — shown once, after a first sign-in on
//! a browser that has local entries the account does not.
//!
//! Signing in switches the storage backend from `Local` to `Remote`, which
//! would otherwise make a user's on-device work appear to vanish.

use chrono::NaiveDate;
use leptos::prelude::*;

#[cfg(feature = "hydrate")]
use chrono::Days;
#[cfg(feature = "hydrate")]
use leptos::task::spawn_local;

#[cfg(feature = "hydrate")]
use crate::auth_ctx::AuthCtx;
#[cfg(feature = "hydrate")]
use crate::date::today_local;
#[cfg(feature = "hydrate")]
use crate::storage::{Backend, Generation, StorageKey, bodies_in_range, dates_with_entries, store};

/// Per-device marker so the banner appears at most once.
///
/// Device-scoped rather than account-scoped because it describes *this
/// browser's* leftovers, not a fact about the account.
pub const DONE_FLAG_KEY: &str = "time_entry_import_done";

/// How far back a first sign-in looks for local entries.
///
/// One less than `server_fns::entries`'s `MAX_RANGE_DAYS` (366), so a
/// single range query against either backend covers the whole lookback in
/// one request.
#[cfg(feature = "hydrate")]
const LOOKBACK_DAYS: u64 = 365;

/// The local days worth offering: those the server does not already have.
///
/// Excluding days the server already holds is what makes the import safe to
/// run from a single button with no confirmation dialog — a second device
/// signing in cannot clobber the first device's work with a stale local
/// copy (invariant I9).
pub fn importable(local: &[NaiveDate], remote: &[NaiveDate]) -> Vec<NaiveDate> {
    local
        .iter()
        .filter(|day| !remote.contains(day))
        .copied()
        .collect()
}

/// Whether an import of `total` offered days that landed `copied` of them
/// may settle this device, and the status line to show for it.
///
/// Pure — no `web_sys` dependency — so unlike the `spawn_local` loop that
/// calls it, this is host-tested directly (mirrors `storage::unwrap_bodies`:
/// pull the decision out of the code a wasm-only harness would be needed to
/// exercise, not the arithmetic itself).
///
/// Settling requires *every* offered day to have landed. A partial or total
/// failure — offline, a transient 5xx, a session that expired between the
/// offer and the click — must not mark this device done: that would strand
/// the un-copied days in `localStorage` with no way back short of
/// hand-editing it, which is exactly the "your work vanished" outcome this
/// feature exists to prevent. Leaving the flag unset needs no bookkeeping
/// of *which* days still need it, either: `importable` already filters
/// against what the server has, so the next time this runs, the days that
/// did land are naturally excluded and only the genuine remainder is
/// re-offered.
#[cfg(any(feature = "hydrate", test))]
fn import_outcome(copied: usize, total: usize) -> (bool, String) {
    let fully_succeeded = copied == total;
    let message = if fully_succeeded {
        format!(
            "Imported {copied} {}.",
            if copied == 1 { "day" } else { "days" }
        )
    } else {
        format!(
            "Imported {copied} of {total} {}.",
            if total == 1 { "day" } else { "days" }
        )
    };
    (fully_succeeded, message)
}

/// Offers to copy a signed-out user's local entries into their account, the
/// first time they sign in on a browser that has any this account lacks.
#[component]
pub fn ImportBanner() -> impl IntoView {
    let candidates = RwSignal::new(Vec::<NaiveDate>::new());
    let status = RwSignal::new(Option::<String>::None);

    // Scoped to the whole `hydrate` feature, unlike every other component
    // that reads `AuthCtx`: `today_local()` has no server-side meaning (the
    // server does not know the visitor's clock — see `date::today_local`),
    // so the fetch below cannot run during SSR regardless. `Effect::new`
    // never fires there either (see `storage::hook`), so this just avoids
    // compiling a fetch, a context lookup, and a staleness guard that would
    // have nothing to do.
    #[cfg(feature = "hydrate")]
    {
        let auth = use_context::<AuthCtx>().expect("AuthCtx provided by App");
        let generation = StoredValue::new(Generation::default());

        Effect::new(move |_| {
            // Tracked (not `get_untracked`): signing in is the entire
            // trigger for this feature, so this effect must re-run when it
            // happens.
            let signed_in = auth.is_signed_in();

            // Bumped on *every* run, including the early return just below:
            // sign-out is a live, no-reload toggle (`AccountMenu` flips
            // `AuthCtx::user` in place), so this effect can re-run — and
            // must invalidate an in-flight fetch — while that fetch is
            // still awaiting a response. Capturing the token now, rather
            // than after the await, is what stops that fetch racing a
            // sign-out for the increment.
            let token = generation
                .try_update_value(Generation::next)
                .unwrap_or_default();

            if !signed_in || already_done() {
                candidates.set(Vec::new());
                return;
            }

            spawn_local(async move {
                let today = today_local();
                let from = today - Days::new(LOOKBACK_DAYS);
                let local = dates_with_entries(Backend::Local, from, today)
                    .await
                    .unwrap_or_default();

                let offer = if local.is_empty() {
                    Vec::new()
                } else {
                    let remote = dates_with_entries(Backend::Remote, from, today)
                        .await
                        .unwrap_or_default();
                    importable(&local, &remote)
                };

                // `try_with_value`, not the panicking form: this
                // component's owner — and so this `StoredValue` — can
                // already be disposed by the time this resolves, e.g. the
                // user navigated away while the fetch was in flight. And
                // only publish if this is still the newest fetch: a slow
                // response landing after sign-out must not repopulate the
                // banner against an account that is no longer signed in.
                let is_current = generation
                    .try_with_value(|g| g.is_current(token))
                    .unwrap_or(false);
                if !is_current {
                    return;
                }
                if offer.is_empty() {
                    mark_done();
                }
                candidates.set(offer);
            });
        });
    }

    let dismiss = move |_| {
        #[cfg(feature = "hydrate")]
        mark_done();
        candidates.set(Vec::new());
    };

    let import = move |_| {
        #[cfg(feature = "hydrate")]
        {
            let days = candidates.get_untracked();
            let total = days.len();
            spawn_local(async move {
                let (Some(&first), Some(&last)) = (days.first(), days.last()) else {
                    return;
                };
                let bodies = bodies_in_range(Backend::Local, first, last)
                    .await
                    .unwrap_or_default();

                let mut copied = 0;
                for (date, body) in bodies {
                    if !days.contains(&date) {
                        continue;
                    }
                    // Local copies are deliberately left in place: a failed
                    // import then loses nothing, and signing out still
                    // leaves the user their data.
                    if store(Backend::Remote, StorageKey::TimeEntry(date), &body)
                        .await
                        .is_ok()
                    {
                        copied += 1;
                    }
                }
                let (fully_succeeded, message) = import_outcome(copied, total);
                if fully_succeeded {
                    mark_done();
                }
                candidates.set(Vec::new());
                status.set(Some(message));
            });
        }
    };

    view! {
        {move || {
            let pending = candidates.get();
            (!pending.is_empty()).then(|| view! {
                <div class="mb-6 flex flex-wrap items-center gap-3 bg-blue-50 border border-blue-200 rounded-lg px-4 py-3">
                    <p class="text-sm text-blue-900 flex-1">
                        {format!(
                            "This device has {} {} saved locally that your account doesn't. Import them?",
                            pending.len(),
                            if pending.len() == 1 { "day" } else { "days" },
                        )}
                    </p>
                    <button
                        type="button"
                        class="text-sm bg-blue-600 text-white rounded px-3 py-1.5 font-medium hover:bg-blue-700"
                        on:click=import
                    >
                        "Import"
                    </button>
                    <button
                        type="button"
                        class="text-sm text-blue-700 px-2 py-1.5 hover:underline"
                        on:click=dismiss
                    >
                        "No thanks"
                    </button>
                </div>
            })
        }}
        {move || status.get().map(|s| view! {
            <p class="mb-6 text-sm text-gray-600">{s}</p>
        })}
    }
}

#[cfg(feature = "hydrate")]
fn flag_storage() -> Option<web_sys::Storage> {
    web_sys::window()?.local_storage().ok().flatten()
}

/// Whether this device has already been offered (and settled) the import.
#[cfg(feature = "hydrate")]
fn already_done() -> bool {
    flag_storage()
        .and_then(|storage| storage.get_item(DONE_FLAG_KEY).ok().flatten())
        .is_some()
}

/// Marks this device's import as settled — imported or dismissed — so the
/// banner never appears again on this browser.
#[cfg(feature = "hydrate")]
fn mark_done() {
    if let Some(storage) = flag_storage() {
        let _ = storage.set_item(DONE_FLAG_KEY, "1");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(y: i32, m: u32, day: u32) -> chrono::NaiveDate {
        chrono::NaiveDate::from_ymd_opt(y, m, day).expect("valid date")
    }

    /// Pins invariant I9. A day that already exists server-side is never
    /// offered, so importing can never overwrite work done on another
    /// device — which is what makes the one-click offer safe.
    #[test]
    fn days_already_on_the_server_are_excluded() {
        let local = vec![d(2026, 9, 1), d(2026, 9, 2), d(2026, 9, 3)];
        let remote = vec![d(2026, 9, 2)];
        assert_eq!(
            importable(&local, &remote),
            vec![d(2026, 9, 1), d(2026, 9, 3)]
        );
    }

    #[test]
    fn nothing_local_means_nothing_to_import() {
        assert!(importable(&[], &[d(2026, 9, 1)]).is_empty());
    }

    #[test]
    fn every_local_day_is_offered_when_the_server_is_empty() {
        let local = vec![d(2026, 9, 1), d(2026, 9, 2)];
        assert_eq!(importable(&local, &[]), local);
    }

    #[test]
    fn a_fully_covered_device_offers_nothing() {
        let days = vec![d(2026, 9, 1), d(2026, 9, 2)];
        assert!(importable(&days, &days).is_empty());
    }

    /// The flag is per-device, and its key is a compatibility surface like
    /// every other storage key.
    #[test]
    fn done_flag_key_is_pinned() {
        assert_eq!(DONE_FLAG_KEY, "time_entry_import_done");
    }

    #[test]
    fn a_full_import_is_settled() {
        let (fully_succeeded, message) = import_outcome(3, 3);
        assert!(fully_succeeded, "every offered day landed");
        assert_eq!(message, "Imported 3 days.");
    }

    #[test]
    fn a_single_day_import_uses_singular_wording() {
        let (fully_succeeded, message) = import_outcome(1, 1);
        assert!(fully_succeeded);
        assert_eq!(message, "Imported 1 day.");
    }

    /// The regression this guards against: a partial import must not settle
    /// this device, or the days that failed would be stranded in
    /// `localStorage` with no way back short of hand-editing it.
    #[test]
    fn a_partial_import_is_not_settled() {
        let (fully_succeeded, message) = import_outcome(3, 5);
        assert!(!fully_succeeded, "a partial import must be re-offered");
        assert_eq!(message, "Imported 3 of 5 days.");
    }

    /// The extreme case of the same regression: every write failing must
    /// not look like success just because nothing panicked.
    #[test]
    fn a_total_failure_is_not_settled() {
        let (fully_succeeded, message) = import_outcome(0, 5);
        assert!(!fully_succeeded);
        assert_eq!(message, "Imported 0 of 5 days.");
    }

    #[test]
    fn a_failed_single_day_import_uses_singular_wording() {
        let (fully_succeeded, message) = import_outcome(0, 1);
        assert!(!fully_succeeded);
        assert_eq!(message, "Imported 0 of 1 day.");
    }
}
