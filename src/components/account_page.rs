//! Placeholder account page.
//!
//! Task 21 replaces this with real passkey enrollment/management and the
//! "sign out everywhere" control.

use leptos::prelude::*;

/// `/account` — passkey and session management.
#[component]
pub fn AccountPage() -> impl IntoView {
    view! {
        <main class="min-h-screen p-8 bg-gray-50">
            <h1 class="text-xl font-semibold text-gray-800">"Account"</h1>
            <p class="text-gray-600">"Passkeys and sign-out controls arrive in Task 21."</p>
        </main>
    }
}
