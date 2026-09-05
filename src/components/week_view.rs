//! `/week/{date}` — a read-only weekly summary.
//!
//! Every total on this page is computed **in the browser**, from bodies the
//! server hands over uninterpreted. That is not an optimization: phase 2
//! encrypts bodies client-side, so a server-side weekly total could not
//! survive it (spec section 9.1).

use chrono::{Days, NaiveDate};
use leptos::either::Either;
use leptos::logging::error;
use leptos::prelude::*;
use leptos::task::spawn_local;
use leptos_meta::Title;
use leptos_router::components::A;
use leptos_router::hooks::use_params_map;
use time_tracking_parser::{Time, parse_time_tracking_data};

use crate::auth_ctx::AuthCtx;
use crate::components::header::AppHeader;
use crate::date::{parse_iso, to_iso, week_bounds};
use crate::storage::{Backend, Generation, StorageError, bodies_in_range};

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
fn loaded_rows(read: Result<Vec<(NaiveDate, String)>, StorageError>) -> Vec<(NaiveDate, String)> {
    match read {
        Ok(rows) => rows,
        Err(err) => {
            error!("failed to load week range, treating as empty: {err}");
            Vec::new()
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
    let (start, end) = week_bounds(anchor);
    // `None` until loaded, exactly like the day view's entry: the totals are
    // a conclusion about stored data, and the shell must not assert one
    // before it has any.
    let totals = RwSignal::new(Option::<WeekTotals>::None);
    let generation = StoredValue::new(Generation::default());

    Effect::new(move |_| {
        let backend = backend.get();
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
            // `None`: Task 12 threads the real key here, out of
            // `EncryptionCtx`. Until then a sealed row is skipped like any
            // other unreadable one, so a signed-in week reads as empty
            // rather than wrong.
            let rows = loaded_rows(bodies_in_range(backend, start, end, None).await);
            let computed = aggregate(&rows);
            // `try_with_value`, not the panicking form: this component's
            // owner — and so this `StoredValue` — can already be disposed
            // by the time this resolves, e.g. the user navigated to
            // another week while the fetch was in flight.
            let is_current = generation
                .try_with_value(|g| g.is_current(token))
                .unwrap_or(false);
            if is_current {
                totals.set(Some(computed));
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

                {move || match totals.get() {
                    None => Either::Left(view! {
                        <div class="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
                            <p class="value-slot"></p>
                        </div>
                    }),
                    Some(t) if t.per_day.is_empty() => Either::Left(view! {
                        <div class="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
                            <p class="text-sm text-gray-500">"Nothing logged this week."</p>
                        </div>
                    }),
                    Some(t) => Either::Right(view! { <WeekTables totals=t/> }),
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
        let rows = vec![(d(2026, 9, 1), "9-10 code1".to_string())];
        assert_eq!(loaded_rows(Ok(rows.clone())), rows);
    }

    #[test]
    fn a_failed_range_read_becomes_empty() {
        assert_eq!(loaded_rows(Err(StorageError::Unavailable)), Vec::new());
    }
}
