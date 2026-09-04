//! The right-hand summary panel's pieces.

use leptos::either::{Either, EitherOf3};
use leptos::prelude::*;

#[component]
pub fn TimeOverview(start_time: String, end_time: String) -> impl IntoView {
    view! {
        <div class="bg-blue-50 rounded-lg p-4 mb-6">
            <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div class="text-center">
                    <p class="text-sm text-gray-600 font-medium">"Start Time"</p>
                    <p class="text-lg font-semibold text-blue-700 value-slot">{start_time}</p>
                </div>
                <div class="text-center">
                    <p class="text-sm text-gray-600 font-medium">"End Time"</p>
                    <p class="text-lg font-semibold text-blue-700 value-slot">{end_time}</p>
                </div>
            </div>
        </div>
    }
}

#[component]
pub fn WorkingTimeDisplay(total: String, total_decimal: String) -> impl IntoView {
    view! {
        <div class="border-l-4 border-green-400 bg-green-50 p-4 mb-4">
            <h3 class="text-sm font-medium text-green-800 mb-1">"Total Working Time"</h3>
            <p class="text-lg font-semibold text-green-700 value-slot">
                {format!("{total} ({total_decimal} hours)")}
            </p>
        </div>
    }
}

#[component]
pub fn DeadTimeDisplay(dead_minutes: u32, dead: String, dead_decimal: String) -> impl IntoView {
    // Thresholds match the Dioxus original: none / under 90 min / 90+ min.
    if dead_minutes == 0 {
        EitherOf3::A(view! {
            <div class="border-l-4 border-green-400 bg-green-50 p-4 mb-6">
                <h3 class="text-sm font-medium text-green-800 mb-1">"Dead Time"</h3>
                <p class="text-lg font-semibold text-green-700 value-slot">
                    "No dead time (gaps) found"
                </p>
            </div>
        })
    } else if dead_minutes < 90 {
        EitherOf3::B(view! {
            <div class="border-l-4 border-yellow-400 bg-yellow-50 p-4 mb-6">
                <h3 class="text-sm font-medium text-yellow-800 mb-1">"Total Dead Time"</h3>
                <p class="text-lg font-semibold text-yellow-700 value-slot">
                    {format!("{dead} ({dead_decimal} hours)")}
                </p>
            </div>
        })
    } else {
        EitherOf3::C(view! {
            <div class="border-l-4 border-red-400 bg-red-50 p-4 mb-6">
                <h3 class="text-sm font-medium text-red-800 mb-1">"Total Dead Time"</h3>
                <p class="text-lg font-semibold text-red-700 value-slot">
                    {format!("{dead} ({dead_decimal} hours)")}
                </p>
            </div>
        })
    }
}

#[component]
pub fn WarningsDisplay(warnings: Vec<String>) -> impl IntoView {
    if warnings.is_empty() {
        return Either::Left(view! { <div></div> });
    }

    let rows = warnings
        .into_iter()
        .map(|warning| {
            view! {
                <p class="text-sm text-yellow-700 flex items-start">
                    <span class="text-yellow-500 mr-2 mt-0.5 text-xs">"⚠"</span>
                    <span>{warning}</span>
                </p>
            }
        })
        .collect_view();

    Either::Right(view! {
        <div class="border-l-4 border-yellow-400 bg-yellow-50 p-4 mb-6">
            <h3 class="text-sm font-medium text-yellow-800 mb-2">"Warnings"</h3>
            <div class="space-y-1">{rows}</div>
        </div>
    })
}

/// Rendered while the stored value is still `None` (spec §5).
///
/// Shows the panel's chrome with empty value slots and, critically, **no**
/// empty-state message — the server does not yet know whether the user has
/// data, and claiming otherwise causes a flash of wrong content on reload.
#[component]
pub fn SummarySkeleton() -> impl IntoView {
    view! {
        <div class="bg-blue-50 rounded-lg p-4 mb-6">
            <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div class="text-center">
                    <p class="text-sm text-gray-600 font-medium">"Start Time"</p>
                    <p class="text-lg font-semibold text-blue-700 value-slot"></p>
                </div>
                <div class="text-center">
                    <p class="text-sm text-gray-600 font-medium">"End Time"</p>
                    <p class="text-lg font-semibold text-blue-700 value-slot"></p>
                </div>
            </div>
        </div>
        <div class="border-l-4 border-gray-200 bg-gray-50 p-4 mb-4">
            <h3 class="text-sm font-medium text-gray-500 mb-1">"Total Working Time"</h3>
            <p class="value-slot"></p>
        </div>
        <div class="border-l-4 border-gray-200 bg-gray-50 p-4 mb-6">
            <h3 class="text-sm font-medium text-gray-500 mb-1">"Dead Time"</h3>
            <p class="value-slot"></p>
        </div>
    }
}
