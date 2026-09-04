//! Forward-reference stub for the date control.
//!
//! **Owned by Task 22.** `AppHeader` (Task 20) needs something in its centre
//! slot to look right in the meantime; this renders the formatted date and
//! nothing else. Task 22 replaces it with real prev/next navigation and a
//! calendar popover. Recorded as a known forward reference in the plan's
//! pre-flight scan (row `T20 → T22`).

use chrono::NaiveDate;
use leptos::prelude::*;

use crate::date::format_long;

/// The header's date slot for the day being viewed.
#[component]
pub fn DatePicker(date: NaiveDate) -> impl IntoView {
    view! { <span class="text-sm text-gray-700">{format_long(date)}</span> }
}
