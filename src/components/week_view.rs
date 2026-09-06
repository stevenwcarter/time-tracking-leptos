//! `/week/{date}` — a read-only weekly summary.
//!
//! Every total on this page is computed **in the browser**, from bodies the
//! server hands over uninterpreted. That is not an optimization: phase 2
//! encrypts bodies client-side, so a server-side weekly total could not
//! survive it (spec section 9.1).

use chrono::{Days, NaiveDate};
use leptos::either::{Either, EitherOf3};
use leptos::logging::error;
use leptos::prelude::*;
use leptos::task::spawn_local;
use leptos_meta::Title;
use leptos_router::components::A;
use leptos_router::hooks::use_params_map;
use time_tracking_parser::{Time, parse_time_tracking_data};

use crate::auth_ctx::AuthCtx;
use crate::components::header::AppHeader;
use crate::components::unlock::{UnlockPrompt, UnlockReason};
use crate::date::{parse_iso, to_iso, week_bounds};
use crate::encryption_ctx::{EncryptionCtx, EncryptionState};
use crate::storage::hook::session_identity;
use crate::storage::{Backend, Generation, RangeRead, StorageError, bodies_in_range};

/// A week's totals, ready to render.
///
/// `Clone` is load-bearing, not incidental: `RwSignal::get()` clones the
/// value out of the signal, which is how the render closure gets an owned
/// `WeekTotals` to hand to `WeekTables` without holding the signal borrowed.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct WeekTotals {
    pub total_minutes: u32,
    /// `(date, minutes)`, chronological. Days with no work are absent.
    pub per_day: Vec<(NaiveDate, u32)>,
    /// `(project, minutes)`, largest first.
    pub per_project: Vec<(String, u32)>,
}

/// Parses each day and combines the results.
pub fn aggregate(rows: &[(NaiveDate, String)]) -> WeekTotals {
    use std::collections::HashMap;

    let mut per_project: HashMap<String, u32> = HashMap::new();
    let mut per_day = Vec::new();
    let mut total_minutes = 0;

    for (date, body) in rows {
        let parsed = parse_time_tracking_data(body);
        if parsed.total_minutes == 0 && parsed.projects.is_empty() {
            // A day that was saved and then emptied. Skipping it keeps
            // zero-minute rows out of the table.
            continue;
        }
        total_minutes += parsed.total_minutes;
        per_day.push((*date, parsed.total_minutes));
        for project in parsed.projects {
            *per_project.entry(project.name).or_default() += project.total_minutes;
        }
    }

    let mut per_project: Vec<(String, u32)> = per_project.into_iter().collect();
    // Largest first, then by name so equal totals are stably ordered rather
    // than reshuffling between renders.
    per_project.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    per_day.sort_by_key(|(d, _)| *d);

    WeekTotals {
        total_minutes,
        per_day,
        per_project,
    }
}

/// Collapses a range read into rows, logging (rather than propagating) a
/// failure — the same "loaded and empty beats stuck blank" tradeoff
/// `hook::loaded_value` makes for a single day.
///
/// A failed range read is neither sealed nor unopenable: nothing was read,
/// so nothing was found to be either, and claiming otherwise would have a
/// dropped request move the account's encryption state.
fn loaded_rows(read: Result<RangeRead, StorageError>) -> RangeRead {
    match read {
        Ok(read) => read,
        Err(err) => {
            error!("failed to load week range, treating as empty: {err}");
            RangeRead::default()
        }
    }
}

#[component]
pub fn WeekView() -> impl IntoView {
    let auth = use_context::<AuthCtx>().expect("AuthCtx provided by App");
    let params = use_params_map();
    let anchor =
        Signal::derive(move || params.with(|p| p.get("date").and_then(|raw| parse_iso(&raw))));

    view! {
        <Title text="Week — Time Tracker"/>
        {move || match anchor.get() {
            None => Either::Left(view! {
                <div class="min-h-screen bg-gray-50">
                    <AppHeader date=None/>
                    <main class="max-w-2xl mx-auto px-4 py-8">
                        <p class="text-gray-600">"That isn't a date."</p>
                    </main>
                </div>
            }),
            Some(day) => Either::Right(view! { <WeekBody anchor=day backend=auth.backend()/> }),
        }}
    }
}

#[component]
fn WeekBody(anchor: NaiveDate, backend: Signal<Backend>) -> impl IntoView {
    let encryption = use_context::<EncryptionCtx>().expect("EncryptionCtx provided by App");
    let (start, end) = week_bounds(anchor);
    // `None` until loaded, exactly like the day view's entry: the totals are
    // a conclusion about stored data, and the shell must not assert one
    // before it has any.
    let totals = RwSignal::new(Option::<WeekTotals>::None);
    let generation = StoredValue::new(Generation::default());
    let identity = session_identity(encryption);

    Effect::new(move |_| {
        let backend = backend.get();
        // Narrowed to *which key*, not the whole session. Unlocking
        // mid-session turns a week of sealed rows into readable ones and has
        // to recompute; the probe resolving from `Unknown` to `Disabled`,
        // which happens on every load, changes nothing this read would
        // return. Tracking the state itself re-ran the load for both — the
        // same over-subscription `storage::hook` documents, costing a
        // redundant week fetch here rather than a lost keystroke, and the
        // narrowing belongs in both places rather than in whichever one the
        // bug surfaced.
        identity.track();
        let session = encryption.state_untracked();
        // Captured synchronously, before the `spawn_local` below: sign-out
        // is a live, no-reload toggle (`AccountMenu` flips `AuthCtx::user`
        // in place), so this effect can re-run — and start a second,
        // differently-backed load — while an earlier one is still in
        // flight. Reading the token back out *after* the await would race
        // that second run for the increment; capturing it now does not.
        let token = generation
            .try_update_value(Generation::next)
            .unwrap_or_default();

        // Back to "not loaded" before the new read starts, so a signed-out
        // reload never shows the previous backend's totals under this
        // week's heading.
        totals.set(None);

        spawn_local(async move {
            // A row this session cannot open is skipped like any other
            // unreadable one, costing its own day and no more — so a week
            // read while locked comes out short rather than wrong.
            let read = loaded_rows(bodies_in_range(backend, start, end, session.key()).await);
            let computed = aggregate(&read.rows);
            // `try_with_value`, not the panicking form: this component's
            // owner — and so this `StoredValue` — can already be disposed
            // by the time this resolves, e.g. the user navigated to
            // another week while the fetch was in flight.
            let is_current = generation
                .try_with_value(|g| g.is_current(token))
                .unwrap_or(false);
            if !is_current {
                return;
            }
            totals.set(Some(computed));
            // Short is not the same as empty, and only the seam knows which
            // this was. A session that believes the account is unencrypted
            // would otherwise render a week of sealed days as "Nothing
            // logged this week." and go on offering an editable day view
            // behind it; reporting the sealed row is what moves the state
            // and puts the unlock prompt up instead.
            if read.sealed {
                encryption.sealed_row_seen();
            }
            // The other way a week comes back short, and the one that
            // reads as a light week rather than an empty one: a session
            // holding another account's key opens none of its rows. The
            // totals above are published either way — they are what this
            // session could actually read — and the re-probe, if it
            // happens at all, moves the state that gates them.
            if read.unopenable {
                let _ = encryption.unopenable_row_seen();
            }
        });
    });

    view! {
        <div class="min-h-screen bg-gray-50">
            <AppHeader date=Some(anchor)/>
            <main class="w-full max-w-3xl mx-auto px-4 py-8">
                <div class="flex items-center justify-between mb-5">
                    <h1 class="text-xl font-semibold text-gray-800">
                        {format!("Week of {}", start.format("%b %-d, %Y"))}
                    </h1>
                    <div class="flex gap-3 text-sm">
                        <A
                            href=format!("/week/{}", to_iso(start - Days::new(7)))
                            attr:class="text-blue-600 no-underline"
                        >
                            "‹ Previous"
                        </A>
                        <A
                            href=format!("/week/{}", to_iso(start + Days::new(7)))
                            attr:class="text-blue-600 no-underline"
                        >
                            "Next ›"
                        </A>
                    </div>
                </div>

                // Gated the same way `DayView` gates the entry area, and for
                // the same reason (spec section 7.4): only a state the user
                // has to act on swaps in the prompt. `Unknown` falls through
                // to the ordinary loading/empty states below, exactly as it
                // did before this gate existed — the server is always
                // `Unknown` (invariant E2), so treating it as a reason to
                // hide the totals shell would remove this page's chrome for
                // every visitor, not just a locked one. A genuinely `Locked`
                // session still gets there in the end: its range read comes
                // back with every row unreadable, `loaded_rows` turns that
                // into an empty week, and this arm replaces that empty week
                // with the prompt once the post-hydration probe resolves — a
                // brief flash of "Nothing logged", not a permanent wrong
                // answer. `Unreachable` joins `Locked` for the reason
                // `DayView`'s gate spells out: only the user can end it.
                {move || match (encryption.state(), totals.get()) {
                    (EncryptionState::Locked, _) => {
                        EitherOf3::C(view! { <UnlockPrompt reason=UnlockReason::Locked/> })
                    }
                    (EncryptionState::Unreachable, _) => {
                        EitherOf3::C(view! { <UnlockPrompt reason=UnlockReason::Unreachable/> })
                    }
                    (_, None) => EitherOf3::A(view! {
                        <div class="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
                            <p class="value-slot"></p>
                        </div>
                    }),
                    (_, Some(t)) if t.per_day.is_empty() => EitherOf3::A(view! {
                        <div class="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
                            <p class="text-sm text-gray-500">"Nothing logged this week."</p>
                        </div>
                    }),
                    (_, Some(t)) => EitherOf3::B(view! { <WeekTables totals=t/> }),
                }}
            </main>
        </div>
    }
}

#[component]
fn WeekTables(totals: WeekTotals) -> impl IntoView {
    let grand = format!(
        "{} ({} hrs)",
        Time::format_duration_minutes(totals.total_minutes),
        Time::format_duration_decimal(totals.total_minutes),
    );

    view! {
        <div class="border-l-4 border-green-400 bg-green-50 p-4 mb-6 rounded">
            <h2 class="text-sm font-medium text-green-800 mb-1">"Total for the week"</h2>
            <p class="text-lg font-semibold text-green-700 value-slot">{grand}</p>
        </div>

        <div class="bg-white rounded-lg shadow-sm border border-gray-200 p-6 mb-6">
            <h2 class="text-lg font-semibold text-gray-800 mb-4 border-b border-gray-200 pb-2">
                "By project"
            </h2>
            <div class="space-y-2">
                {totals
                    .per_project
                    .into_iter()
                    .map(|(name, minutes)| {
                        view! {
                            <div class="flex items-center justify-between">
                                <span class="text-sm text-gray-800">{name}</span>
                                <span class="text-sm font-medium text-blue-600 bg-blue-100 px-2 py-0.5 rounded-full">
                                    {format!(
                                        "{} ({} hrs)",
                                        Time::format_duration_minutes(minutes),
                                        Time::format_duration_decimal(minutes),
                                    )}
                                </span>
                            </div>
                        }
                    })
                    .collect_view()}
            </div>
        </div>

        <div class="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
            <h2 class="text-lg font-semibold text-gray-800 mb-4 border-b border-gray-200 pb-2">
                "By day"
            </h2>
            <div class="space-y-2">
                {totals
                    .per_day
                    .into_iter()
                    .map(|(date, minutes)| {
                        view! {
                            <div class="flex items-center justify-between">
                                <A
                                    href=format!("/{}", to_iso(date))
                                    attr:class="text-sm text-blue-600 no-underline"
                                >
                                    {date.format("%A, %b %-d").to_string()}
                                </A>
                                <span class="text-sm text-gray-700">
                                    {format!(
                                        "{} ({} hrs)",
                                        Time::format_duration_minutes(minutes),
                                        Time::format_duration_decimal(minutes),
                                    )}
                                </span>
                            </div>
                        }
                    })
                    .collect_view()}
            </div>
        </div>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(y: i32, m: u32, day: u32) -> chrono::NaiveDate {
        chrono::NaiveDate::from_ymd_opt(y, m, day).expect("valid date")
    }

    #[test]
    fn totals_a_single_day() {
        let rows = vec![(d(2026, 9, 1), "9-10 code1\n- did a thing".to_string())];
        let totals = aggregate(&rows);
        assert_eq!(totals.total_minutes, 60);
        assert_eq!(totals.per_day.len(), 1);
        assert_eq!(totals.per_project.len(), 1);
        assert_eq!(totals.per_project[0].0, "code1");
        assert_eq!(totals.per_project[0].1, 60);
    }

    /// The point of the view: one project worked across several days is one
    /// row with the combined total.
    #[test]
    fn sums_a_project_across_days() {
        let rows = vec![
            (d(2026, 9, 1), "9-10 code1".to_string()),
            (d(2026, 9, 2), "9-11 code1".to_string()),
            (d(2026, 9, 3), "9-10 code2".to_string()),
        ];
        let totals = aggregate(&rows);
        assert_eq!(totals.total_minutes, 240);
        let code1 = totals
            .per_project
            .iter()
            .find(|(n, _)| n == "code1")
            .expect("code1 present");
        assert_eq!(code1.1, 180);
    }

    /// Biggest first, so a weekly timesheet reads top-down.
    ///
    /// The brief wrote this row as `"9-13 large"` (meaning 9am-1pm), but the
    /// parser's `Time::new` only accepts hours `1..=12` — it is a strict
    /// 12-hour clock with no AM/PM, so `13` is rejected and the entry
    /// silently fails to parse, leaving "large" absent rather than merely
    /// smaller. `"9-1"` is the same 9am-1pm span expressed in a format this
    /// parser actually accepts.
    #[test]
    fn projects_are_ordered_by_time_descending() {
        let rows = vec![
            (d(2026, 9, 1), "9-10 small".to_string()),
            (d(2026, 9, 2), "9-1 large".to_string()),
        ];
        let totals = aggregate(&rows);
        assert_eq!(totals.per_project[0].0, "large");
    }

    #[test]
    fn an_empty_week_totals_zero() {
        let totals = aggregate(&[]);
        assert_eq!(totals.total_minutes, 0);
        assert!(totals.per_project.is_empty());
        assert!(totals.per_day.is_empty());
    }

    /// A day saved and then emptied is a real state; it must not become a
    /// zero-minute row cluttering the view.
    #[test]
    fn empty_bodies_contribute_no_rows() {
        let rows = vec![
            (d(2026, 9, 1), String::new()),
            (d(2026, 9, 2), "9-10 code1".into()),
        ];
        let totals = aggregate(&rows);
        assert_eq!(totals.per_day.len(), 1, "only the non-empty day counts");
        assert_eq!(totals.total_minutes, 60);
    }

    #[test]
    fn a_successful_range_read_is_returned_as_is() {
        let read = RangeRead {
            rows: vec![(d(2026, 9, 1), "9-10 code1".to_string())],
            sealed: false,
            unopenable: false,
        };
        assert_eq!(loaded_rows(Ok(read.clone())), read);
    }

    /// Both halves, and the second is the one that matters: a row this
    /// session could not read is evidence about the *session*, and it has to
    /// survive the collapse that throws the failure away, or a week of
    /// unreadable days goes on rendering as an empty one.
    ///
    /// Both flags, because they are the two different ways that happens — no
    /// key at all, and the wrong account's key — and each is carried
    /// independently of the rows beside it.
    #[test]
    fn a_row_this_session_could_not_read_survives_the_collapse() {
        let read = RangeRead {
            rows: vec![(d(2026, 9, 1), "9-10 code1".to_string())],
            sealed: true,
            unopenable: false,
        };
        assert!(loaded_rows(Ok(read)).sealed);

        let read = RangeRead {
            rows: vec![(d(2026, 9, 1), "9-10 code1".to_string())],
            sealed: false,
            unopenable: true,
        };
        assert!(loaded_rows(Ok(read)).unopenable);
    }

    /// A read that never happened found nothing sealed or unopenable
    /// either: reporting one would let a dropped request move the account's
    /// encryption state — and, for the second flag, spend the page load's
    /// one re-probe on nothing.
    #[test]
    fn a_failed_range_read_becomes_empty() {
        let read = loaded_rows(Err(StorageError::Unavailable));
        assert_eq!(read.rows, Vec::new());
        assert!(
            !read.sealed && !read.unopenable,
            "a failed read learned nothing about the account"
        );
    }
}

/// Pins the mount gate directly (spec section 7.4), the same way `app`'s
/// `day_view_shows_the_unlock_prompt_when_locked` pins `DayView`'s. A
/// separate, `ssr`-gated module rather than folding into `mod tests` above:
/// `.to_html()` needs `leptos`'s `ssr` feature, which the pure `aggregate`/
/// `loaded_rows` tests above have no reason to require.
#[cfg(all(test, feature = "ssr"))]
mod gate_tests {
    use leptos_router::components::Router;
    use leptos_router::location::RequestUrl;

    use super::*;

    /// Renders `WeekBody` directly, with `EncryptionCtx` parked at `state`
    /// via [`EncryptionCtx::for_state`] — the real probe never produces
    /// anything but `Unknown` under `ssr` (invariant E2), so there is no
    /// other way to reach `Locked` here.
    ///
    /// Wrapped in a bare `<Router>` (no `<Routes>`) for the same reason
    /// `app`'s `render_day_view` is: `AppHeader`'s `<A>` needs router
    /// context to resolve its `href` or it panics, and nothing here
    /// navigates, so no route table is required. `backend` is passed
    /// directly rather than read from `AuthCtx`, since `WeekBody` — unlike
    /// `WeekView`, its param-parsing wrapper — takes it as a plain argument.
    fn render_week_body(state: EncryptionState) -> String {
        let runtime = Owner::new();
        let anchor = NaiveDate::from_ymd_opt(2026, 9, 1).expect("valid date");
        let html = runtime.with(move || {
            provide_context(RequestUrl::new("/week/2026-09-01"));
            provide_context(AuthCtx {
                user: RwSignal::new(Some("alice@example.com".to_string())),
            });
            provide_context(EncryptionCtx::for_state(state));
            let backend = Signal::derive(|| Backend::Local);
            view! { <Router><WeekBody anchor=anchor backend=backend/></Router> }.to_html()
        });
        runtime.cleanup();
        html
    }

    /// The primary case: `Locked` must swap the totals shell for the unlock
    /// prompt, not merely leave the week looking empty — without this,
    /// `loaded_rows` would go on to turn the locked range read's failure
    /// into an empty week, rendering "Nothing logged this week." over a
    /// week of real data.
    #[test]
    fn week_body_shows_the_unlock_prompt_when_locked() {
        let html = render_week_body(EncryptionState::Locked);
        assert!(
            html.contains("Unlock your entries"),
            "a locked session must render the unlock prompt"
        );
        assert!(
            !html.contains("Nothing logged this week."),
            "the totals shell must not mount alongside the unlock prompt"
        );
    }

    /// The week view's half of the retry gate: a probe that could not answer
    /// must offer another try here too, rather than render a week that will
    /// stay empty for as long as the session lasts.
    #[test]
    fn week_body_offers_a_retry_when_the_probe_could_not_answer() {
        let html = render_week_body(EncryptionState::Unreachable);
        assert!(
            html.contains("Try again"),
            "an unanswered probe must offer another try"
        );
        assert!(
            !html.contains("Nothing logged this week."),
            "an unanswered probe must not read as an empty week"
        );
    }

    /// The other half: every other state still mounts the totals shell,
    /// exactly as it did before this gate existed (spec 7.4's correction —
    /// `Unknown` is not a second reason to hide it). `totals` starts `None`
    /// and the range-read effect never runs under `ssr`, so this always
    /// renders the loading skeleton rather than a resolved total — enough
    /// to prove the *unlock prompt* did not mount, which is this test's job.
    #[test]
    fn week_body_shows_the_totals_shell_when_not_locked() {
        for state in [EncryptionState::Unknown, EncryptionState::Disabled] {
            let html = render_week_body(state);
            assert!(
                html.contains("value-slot"),
                "a non-locked session must still mount the totals shell"
            );
            assert!(
                !html.contains("Unlock your entries"),
                "a non-locked session must not render the unlock prompt"
            );
        }
    }
}
