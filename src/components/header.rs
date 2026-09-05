//! The slim application header: title, date control, account slot.
//!
//! Layout is fixed by a user decision made from visual mockups: one row,
//! title left, date centre, account right (option B). Not open for
//! redesign here.

use chrono::NaiveDate;
use leptos::prelude::*;
use leptos_router::components::A;

use crate::components::account_menu::AccountMenu;
use crate::components::calendar::DatePicker;

/// The page header, shown on every route.
#[component]
pub fn AppHeader(
    /// `None` on `/`, where the server cannot know the date yet.
    date: Option<NaiveDate>,
) -> impl IntoView {
    view! {
        <header class="bg-white border-b border-gray-200">
            <div class="w-full max-w-7xl mx-auto px-4 h-14 flex items-center gap-4">
                <A
                    href="/"
                    attr:class="text-sm font-bold text-gray-900 tracking-wide no-underline shrink-0"
                >
                    "Time Tracker"
                </A>
                <div class="flex-1 flex justify-center min-w-0">
                    // Absent rather than empty on `/`: the slot renders no
                    // date because none is known, and the client fills the
                    // URL in after hydration.
                    {date.map(|date| view! { <DatePicker date=date/> })}
                </div>
                <div class="shrink-0">
                    <AccountMenu date=date/>
                </div>
            </div>
        </header>
    }
}
