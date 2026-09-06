//! The slim application header: title, date control, account slot.
//!
//! Layout is fixed by a user decision made from visual mockups: one row,
//! title left, date centre, account right (option B). Not open for
//! redesign here.

use chrono::NaiveDate;
use leptos::either::Either;
use leptos::prelude::*;
use leptos_router::components::A;

use crate::auth_ctx::AuthCtx;
use crate::components::account_menu::AccountMenu;
use crate::components::calendar::DatePicker;
use crate::encryption_ctx::{EncryptionCtx, Writes};

/// Worn by both the linked and the unlinked title, so the header does not
/// shift when the gate swaps one for the other.
const TITLE_CLASS: &str = "text-sm font-bold text-gray-900 tracking-wide no-underline shrink-0";

/// The page header, shown on every route.
#[component]
pub fn AppHeader(
    /// `None` on `/`, where the server cannot know the date yet.
    date: Option<NaiveDate>,
) -> impl IntoView {
    let auth = use_context::<AuthCtx>().expect("AuthCtx provided by App");
    let encryption = use_context::<EncryptionCtx>().expect("EncryptionCtx provided by App");
    let backend = auth.backend();
    // Asked of `EncryptionCtx` with the call every other gate uses, rather
    // than re-derived here — the same reason `AccountPage` binds it once for
    // its banner and step framing.
    let gated = move || encryption.writes(backend.get()) == Writes::SetupRequired;

    view! {
        <header class="bg-white border-b border-gray-200">
            <div class="w-full max-w-7xl mx-auto px-4 h-14 flex items-center gap-4">
                // Unlinked, not hidden, while the gate is up: `/` resolves
                // to the day view, which mounts `SetupGate` and bounces
                // straight back to `/account` (spec section 4.1), so the
                // link is the dead end `PasskeySection`'s "‹ Back to today"
                // was — this is the same destination reached by the one
                // control that is on every route. The name still belongs in
                // the header, so only the navigation goes.
                //
                // The server always renders the linked branch: it seeds a
                // signed-in visitor at `EncryptionState::Unknown` (invariant
                // E2), which is `Writes::Refused` rather than
                // `SetupRequired`, and a signed-out one at `Backend::Local`,
                // which is never gated. So does the first client render, and
                // the swap comes with the probe's answer.
                {move || if gated() {
                    Either::Left(view! { <span class=TITLE_CLASS>"Time Tracker"</span> })
                } else {
                    Either::Right(view! {
                        <A href="/" attr:class=TITLE_CLASS>"Time Tracker"</A>
                    })
                }}
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
