//! Placeholder header.
//!
//! Task 20 replaces this with the real navigation shell (date picker,
//! week/account links). This stub exists only so `App` compiles and this
//! task's own SSR tests — which assert on "Sign in" versus the signed-in
//! identity — have real chrome to assert against. The auth check here is
//! real; only the layout around it is a placeholder.

use chrono::NaiveDate;
use leptos::prelude::*;

use crate::auth_ctx::AuthCtx;
use crate::date::format_long;

/// The page header: the date being viewed (when there is one) and the
/// signed-in identity, or a sign-in prompt.
#[component]
pub fn AppHeader(date: Option<NaiveDate>) -> impl IntoView {
    let auth = use_context::<AuthCtx>().expect("AuthCtx provided by App");
    let identity = move || {
        if auth.is_signed_in() {
            auth.user.get().unwrap_or_default()
        } else {
            "Sign in".to_string()
        }
    };

    view! {
        <header class="flex items-center justify-between p-4 bg-white border-b border-gray-200">
            <span class="text-sm text-gray-500">{date.map(format_long).unwrap_or_default()}</span>
            <span class="text-sm font-medium text-gray-700">{identity}</span>
        </header>
    }
}
