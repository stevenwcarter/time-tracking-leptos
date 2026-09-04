//! The header's date control: a label, day steppers, and a month popover
//! marking the days that have entries.

use chrono::{Datelike, Days, NaiveDate};
use leptos::either::Either;
use leptos::prelude::*;
use leptos::task::spawn_local;
use leptos_router::hooks::use_navigate;

use crate::auth_ctx::AuthCtx;
use crate::date::{format_long, month_bounds, to_iso};
use crate::storage::dates_with_entries;

/// The month's days laid out Monday-first, padded with `None` so each row of
/// seven is a calendar week.
pub fn month_grid(any_day: NaiveDate) -> Vec<Option<NaiveDate>> {
    let (first, last) = month_bounds(any_day);
    let lead = first.weekday().num_days_from_monday() as usize;

    let mut cells: Vec<Option<NaiveDate>> = vec![None; lead];
    let mut day = first;
    while day <= last {
        cells.push(Some(day));
        day = day + Days::new(1);
    }
    // Pad the final row so the grid is always whole weeks; a ragged last row
    // makes the CSS grid reflow the columns.
    while !cells.len().is_multiple_of(7) {
        cells.push(None);
    }
    cells
}

/// The header's date slot: prev/next steppers around the current date, and
/// a popover calendar for jumping to another day in the month.
#[component]
pub fn DatePicker(date: NaiveDate) -> impl IntoView {
    let auth = use_context::<AuthCtx>().expect("AuthCtx provided by App");
    let open = RwSignal::new(false);
    let navigate = use_navigate();

    let go = {
        let navigate = navigate.clone();
        move |target: NaiveDate| {
            open.set(false);
            navigate(&format!("/{}", to_iso(target)), Default::default());
        }
    };

    // Which days in the visible month have entries. Refetched whenever the
    // backend changes: signing in must repopulate the dots from the server,
    // signing out must fall back to the localStorage key scan. Subscribing
    // to `auth.backend()` via `.get()` (tracked) is what makes that happen —
    // reading it untracked would freeze the dots at whatever backend was
    // current on mount.
    let marked = RwSignal::new(Vec::<NaiveDate>::new());
    let backend = auth.backend();
    Effect::new(move |_| {
        let backend = backend.get();
        let (from, to) = month_bounds(date);
        spawn_local(async move {
            // A failed lookup means no dots, never a broken calendar: the
            // picker's job is navigation, and the marks are only a
            // convenience.
            marked.set(
                dates_with_entries(backend, from, to)
                    .await
                    .unwrap_or_default(),
            );
        });
    });

    view! {
        <div class="relative flex items-center gap-1">
            <button
                type="button"
                class="px-1.5 py-1 text-gray-400 hover:text-gray-700 text-sm"
                aria-label="Previous day"
                on:click={let go = go.clone(); move |_| go(date - Days::new(1))}
            >
                "‹"
            </button>
            <button
                type="button"
                class="text-sm font-semibold text-gray-900 border border-gray-300 rounded px-3 py-1 hover:bg-gray-50 whitespace-nowrap"
                on:click=move |_| open.update(|o| *o = !*o)
            >
                {format_long(date)}
            </button>
            <button
                type="button"
                class="px-1.5 py-1 text-gray-400 hover:text-gray-700 text-sm"
                aria-label="Next day"
                on:click={let go = go.clone(); move |_| go(date + Days::new(1))}
            >
                "›"
            </button>

            <div
                class="absolute left-1/2 -translate-x-1/2 top-10 bg-white border border-gray-200 rounded-lg shadow-lg p-3 z-20 w-64"
                class:hidden=move || !open.get()
            >
                <p class="text-xs font-semibold text-gray-700 text-center mb-2">
                    {date.format("%B %Y").to_string()}
                </p>
                <div class="grid grid-cols-7 gap-0.5 text-center">
                    {["M", "T", "W", "T", "F", "S", "S"]
                        .into_iter()
                        .enumerate()
                        .map(|(i, label)| {
                            view! {
                                <span class="text-[10px] text-gray-400" id=format!("dow-{i}")>
                                    {label}
                                </span>
                            }
                        })
                        .collect_view()}
                    {move || {
                        // Read once per render rather than once per cell —
                        // `contains` is cheap, but there is no reason to
                        // clone the vec out of the signal on every cell.
                        let marked_days = marked.get();
                        month_grid(date)
                            .into_iter()
                            .map(|cell| match cell {
                                None => Either::Left(view! { <span></span> }),
                                Some(day) => {
                                    let is_selected = day == date;
                                    let has_entry = marked_days.contains(&day);
                                    let go = go.clone();
                                    Either::Right(view! {
                                        <button
                                            type="button"
                                            class="text-xs rounded py-1 hover:bg-blue-50 relative"
                                            class:bg-blue-600=is_selected
                                            class:text-white=is_selected
                                            class:font-semibold=has_entry
                                            on:click=move |_| go(day)
                                        >
                                            {day.day().to_string()}
                                            {has_entry.then(|| {
                                                view! {
                                                    <span class="absolute bottom-0.5 left-1/2 -translate-x-1/2 w-1 h-1 rounded-full bg-blue-500"></span>
                                                }
                                            })}
                                        </button>
                                    })
                                }
                            })
                            .collect_view()
                    }}
                </div>
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

    /// September 2026 starts on a Tuesday, so one leading blank for Monday.
    #[test]
    fn grid_pads_to_the_first_weekday() {
        let grid = month_grid(d(2026, 9, 4));
        assert_eq!(grid[0], None, "Monday cell is empty");
        assert_eq!(grid[1], Some(d(2026, 9, 1)), "the 1st falls on Tuesday");
    }

    #[test]
    fn grid_covers_every_day_of_the_month() {
        let grid = month_grid(d(2026, 9, 4));
        let days: Vec<_> = grid.iter().flatten().collect();
        assert_eq!(days.len(), 30, "September has 30 days");
        assert_eq!(days.first(), Some(&&d(2026, 9, 1)));
        assert_eq!(days.last(), Some(&&d(2026, 9, 30)));
    }

    /// A month starting on Monday needs no padding at all — the case an
    /// unconditional "add N blanks" gets wrong by a whole week.
    #[test]
    fn a_month_starting_on_monday_has_no_padding() {
        // 2026-06-01 is a Monday.
        let grid = month_grid(d(2026, 6, 15));
        assert_eq!(grid[0], Some(d(2026, 6, 1)));
    }

    #[test]
    fn grid_length_is_a_whole_number_of_weeks() {
        for (y, m) in [(2026, 2), (2026, 9), (2028, 2), (2026, 11)] {
            let grid = month_grid(d(y, m, 1));
            assert_eq!(grid.len() % 7, 0, "{y}-{m} grid must fill whole weeks");
        }
    }
}
