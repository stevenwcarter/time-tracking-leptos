//! Placeholder week view.
//!
//! Task 23 replaces this with the week-at-a-glance calendar and totals.

use leptos::prelude::*;

/// `/week/:date` — the week containing the given date.
#[component]
pub fn WeekView() -> impl IntoView {
    view! {
        <main class="min-h-screen p-8 bg-gray-50">
            <p class="text-gray-600">"Week view arrives in Task 23."</p>
        </main>
    }
}
