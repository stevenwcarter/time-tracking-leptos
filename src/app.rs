use chrono::NaiveDate;
use leptos::either::{Either, EitherOf3};
use leptos::prelude::*;
use leptos_meta::{MetaTags, Stylesheet, Title, provide_meta_context};
use leptos_router::components::{Route, Router, Routes};
use leptos_router::hooks::use_params_map;
use leptos_router::path;

use crate::auth_ctx::{AuthCtx, USER_META, initial_user};
use crate::components::account_page::AccountPage;
use crate::components::header::AppHeader;
use crate::components::import_banner::ImportBanner;
use crate::components::setup_gate::SetupGate;
use crate::components::time_display::TimeDisplay;
use crate::components::time_entry_area::TimeEntryArea;
use crate::components::unlock::{UnlockPrompt, UnlockReason};
use crate::components::week_view::WeekView;
use crate::date::parse_iso;
use crate::encryption_ctx::{EncryptionCtx, EncryptionState, Writes};
use crate::storage::StorageKey;
use crate::storage::hook::use_persistent;

/// The SSR document shell. `HydrationScripts` injects the wasm loader.
pub fn shell(options: LeptosOptions) -> impl IntoView {
    // Carried into the browser so the client's first render can reach the
    // same conclusion the server did, without a cookie or a round trip.
    // See `auth_ctx::initial_user`.
    let user = initial_user();

    view! {
        <!DOCTYPE html>
        <html lang="en">
            <head>
                <meta charset="utf-8"/>
                <meta name="viewport" content="width=device-width, initial-scale=1"/>
                {user.map(|email| view! { <meta name=USER_META content=email/> })}
                <link rel="icon" href="/favicon.ico"/>
                <AutoReload options=options.clone()/>
                <HydrationScripts options/>
                <MetaTags/>
            </head>
            <body>
                <App/>
            </body>
        </html>
    }
}

#[component]
pub fn App() -> impl IntoView {
    provide_meta_context();
    let auth = AuthCtx {
        user: RwSignal::new(initial_user()),
    };
    provide_context(auth);
    // Takes `auth` rather than reading it back out of context, so the
    // dependency between the two is in the signature instead of in the order
    // these two lines happen to be written in. The probe behind it never
    // runs on the server, which is what keeps encryption state out of the
    // SSR body (invariant E2).
    provide_context(EncryptionCtx::probing(auth));

    view! {
        <Stylesheet id="leptos" href="/pkg/time-tracking-leptos.css"/>
        <Title text="Time Tracker"/>
        <Router>
            <Routes fallback=NotFound>
                <Route path=path!("/") view=TodayRedirect/>
                <Route path=path!("/account") view=AccountPage/>
                <Route path=path!("/week/:date") view=WeekView/>
                <Route path=path!("/:date") view=DayPage/>
            </Routes>
        </Router>
    }
}

/// `/` — the canonical entry point, which does not name a date.
///
/// The server cannot resolve "today": it does not know the visitor's
/// timezone, and guessing is wrong for somebody near midnight every single
/// day. So it renders the chrome with an empty date slot, and the browser
/// replaces the URL with its own local date once hydrated. A deep link to
/// `/2026-09-04` skips all of this, because there the date is knowable
/// server-side (spec section 8.1).
#[component]
fn TodayRedirect() -> impl IntoView {
    #[cfg(feature = "hydrate")]
    {
        use leptos_router::NavigateOptions;
        use leptos_router::hooks::use_navigate;

        use crate::date::{to_iso, today_local};

        let navigate = use_navigate();
        Effect::new(move |_| {
            navigate(
                &format!("/{}", to_iso(today_local())),
                NavigateOptions {
                    replace: true,
                    ..Default::default()
                },
            );
        });
    }

    view! {
        <div class="min-h-screen bg-gray-50">
            <AppHeader date=None/>
        </div>
    }
}

/// `/:date` — the day view.
#[component]
fn DayPage() -> impl IntoView {
    let params = use_params_map();
    let parsed =
        Signal::derive(move || params.with(|p| p.get("date").and_then(|raw| parse_iso(&raw))));

    view! {
        {move || match parsed.get() {
            // A single path segment that is not a date. The route pattern
            // cannot express "date-shaped", so the check lives here.
            None => Either::Left(view! { <NotFound/> }),
            Some(date) => Either::Right(view! { <DayView date=date/> }),
        }}
    }
}

/// The day being viewed, and the entry that belongs to it.
///
/// `date` is taken by value and folded into a constant signal rather than
/// derived from the route params. This is safe not because `leptos_router`
/// remounts `DayPage` on a date change — it doesn't; navigating between two
/// `/:date` URLs matches the same route id, and the router updates the
/// params signal on the *same* instance rather than tearing it down. The
/// remount happens one layer down instead: `DayPage`'s `{move || match
/// parsed.get() { .. } }` is itself a reactive closure, and calling
/// `view! { <DayView date=date/> }` inside it re-invokes this function on
/// every date change, in a scope that is disposed and recreated each time
/// (`RenderEffect` wraps each run in `Owner::with_cleanup`). So every date
/// gets a fresh `DayView` instance — and a fresh, independent
/// `use_persistent` — even though the outer route never remounts. If a
/// future change hoists the `match` out of a reactive closure (so `DayView`
/// itself stops being re-invoked per date), `key` must derive from the
/// params signal instead — `use_persistent` is already reactive and would
/// pick that up with no other changes.
#[component]
fn DayView(date: NaiveDate) -> impl IntoView {
    let auth = use_context::<AuthCtx>().expect("AuthCtx provided by App");
    let encryption = use_context::<EncryptionCtx>().expect("EncryptionCtx provided by App");
    let key = Signal::derive(move || StorageKey::TimeEntry(date));
    // Bound once and shared with the gate below, so the backend the entry
    // is stored through and the backend the gate asks about cannot be two
    // different derivations of the same fact.
    let backend = auth.backend();
    let entry = use_persistent(key, backend);

    view! {
        <div class="min-h-screen bg-gray-50">
            <AppHeader date=Some(date)/>
            <div class="w-full max-w-7xl mx-auto px-4 py-8">
                // Mounted unconditionally, above the gate below, and still
                // correct after the two-step setup flow: its candidate list
                // comes from a browser-only effect keyed on sign-in, and a
                // gated session's `SetupGate` navigates to `/account` on
                // mount before that fetch could complete or its banner
                // render anything a gated visitor would see. Import is
                // orthogonal to setup besides — it has just as much to offer
                // a `Locked` or `Unreachable` session — so gating it here
                // alongside the entry area would wrongly withhold it from
                // those too.
                <ImportBanner/>
                // Spec section 4.1's gate comes first, and is asked of
                // `EncryptionCtx` rather than re-derived here: "can this
                // session store anything" is the question that object
                // answers everywhere else, and pairing a state with a
                // backend by hand would put a copy of the same reasoning in
                // the week view and on `/account` too. `SetupRequired`
                // needs the probe's answer *and* `Backend::Remote`, so the
                // server can no more render this arm than it can `Locked`:
                // it seeds a signed-in visitor at `Unknown` (invariant E2)
                // and a signed-out one at `Backend::Local`, where the same
                // `Disabled` writes plaintext and is not gated at all.
                //
                // The remaining arms are spec section 7.4's gate, and only
                // a state the user has to act on swaps in the prompt.
                // `Unknown`, `Unlocked` and a signed-out `Disabled` all
                // render the entry area in its ordinary state rather than
                // blanking it, and the server renders one of the first and
                // last for every visitor, so blanking either would remove
                // the entry area from every server-rendered page rather
                // than only from a locked one. The cost of *not* blanking
                // is narrower: a locked session sees the same shell for the
                // width of the post-hydration probe before this swaps it
                // for the prompt, since a `Locked` read fails the same way
                // `hook::loaded_value` maps any other one — a brief flash
                // on a rare path, not a permanent wrong answer.
                //
                // Mounted is not the same as editable. `Unknown` is
                // `WriteKey::Locked`, so `TimeEntryArea` renders a signed-in
                // visitor's box read-only and says so until the probe lands
                // — the server renders that same shell, which is what keeps
                // it hydrating. `Disabled` is `WriteKey::Plaintext`, so a
                // signed-out visitor's box is editable immediately, on both
                // targets.
                //
                // `Unreachable` joins `Locked` rather than `Unknown`, and the
                // difference is who can end the state. `Unknown` ends by
                // itself, in milliseconds; `Unreachable` ends only if the
                // user asks for another try, and until they do every save is
                // refused. Leaving the entry area mounted there would invite
                // exactly the typing that cannot be saved. The server never
                // reaches it, so E2 is untouched.
                {move || match (encryption.writes(backend.get()), encryption.state()) {
                    (Writes::SetupRequired, _) => EitherOf3::C(view! { <SetupGate/> }),
                    (_, EncryptionState::Locked) => {
                        EitherOf3::B(view! { <UnlockPrompt reason=UnlockReason::Locked/> })
                    }
                    (_, EncryptionState::Unreachable) => {
                        EitherOf3::B(view! { <UnlockPrompt reason=UnlockReason::Unreachable/> })
                    }
                    (
                        _,
                        EncryptionState::Unknown
                        | EncryptionState::Disabled
                        | EncryptionState::Unlocked(_),
                    ) => EitherOf3::A(view! {
                        <div class="flex flex-col md:flex-row gap-6 w-full">
                            <TimeEntryArea entry=entry/>
                            <TimeDisplay entry=entry/>
                        </div>
                    }),
                }}
            </div>
        </div>
    }
}

#[component]
fn NotFound() -> impl IntoView {
    view! {
        <main class="min-h-screen flex items-center justify-center bg-gray-50">
            <p class="text-gray-600">"Page not found."</p>
        </main>
    }
}

#[cfg(all(test, feature = "ssr"))]
mod tests {
    use leptos_router::location::RequestUrl;

    use super::*;
    use crate::session::SessionClaims;
    use crate::test_support::app_ctx_with_claims;

    /// Renders `App` exactly as the server would.
    ///
    /// `leptos_axum`'s handler provides the requested path as a `RequestUrl`
    /// before rendering and `<Router>` panics without it, so we do the same.
    /// When `signed_in_as` is `Some`, an `AppCtx` carrying verified claims is
    /// provided too — which is what production does for a request arriving
    /// with a valid session cookie.
    ///
    /// Still synchronous (`.to_html()`), still providing neither
    /// `ServerMetaContext` nor `ResponseOptions`. Both remain harmless while
    /// the app has no `Resource`s or `<Suspense>` boundaries; see CLAUDE.md.
    fn render_at(path: &str, signed_in_as: Option<&str>) -> String {
        let runtime = Owner::new();
        let path = path.to_string();
        let claims = signed_in_as.map(|email| SessionClaims {
            email: email.to_string(),
            epoch: 0,
        });
        let html = runtime.with(move || {
            provide_context(RequestUrl::new(&path));
            if let Some(claims) = claims {
                provide_context(app_ctx_with_claims(Some(claims)));
            }
            view! { <App/> }.to_html()
        });
        runtime.cleanup();
        html
    }

    fn render_app() -> String {
        render_at("/2026-09-04", None)
    }

    /// Renders `DayView` directly, with `EncryptionCtx` parked at `state`
    /// via [`EncryptionCtx::for_state`] rather than the real probe — which
    /// never produces anything but `Unknown` under `ssr` (invariant E2), so
    /// there is no other way to reach `Locked` here at all.
    ///
    /// `signed_in_as` is a parameter rather than a constant because it is
    /// half of spec section 4.1's gate: the identity decides
    /// `auth.backend()`, and the same `EncryptionState::Disabled` is
    /// ordinary local mode on `Local` and a hard stop on `Remote`. Deeper
    /// in, `AppHeader`'s `AccountMenu`/`DatePicker` read the same context
    /// for their own rendering, which is independent of either gate.
    ///
    /// Wrapped in a bare `<Router>` (no `<Routes>`): `AppHeader`'s `<A>`
    /// needs router context to resolve its `href` or it panics, but nothing
    /// here navigates, so no route table is required.
    fn render_day_view_for(signed_in_as: Option<&str>, state: EncryptionState) -> String {
        let runtime = Owner::new();
        let date = crate::date::parse_iso("2026-09-04").expect("valid date");
        let user = signed_in_as.map(str::to_string);
        let html = runtime.with(move || {
            provide_context(RequestUrl::new("/2026-09-04"));
            provide_context(AuthCtx {
                user: RwSignal::new(user),
            });
            provide_context(EncryptionCtx::for_state(state));
            view! { <Router><DayView date=date/></Router> }.to_html()
        });
        runtime.cleanup();
        html
    }

    /// The signed-in case, which is what every gate below is about except
    /// the one that exists to prove signed-out visitors were left alone.
    fn render_day_view(state: EncryptionState) -> String {
        render_day_view_for(Some("alice@example.com"), state)
    }

    /// Renders `/account` the same way, since that is where the gate sends
    /// an account it stops — and so the only place its escape hatch can be
    /// checked for.
    ///
    /// `AccountPage`'s passkey list is a `Resource` inside a `<Suspense>`;
    /// under `.to_html()` that renders its fallback, which is all this needs
    /// — the banner is above it and does not wait on anything.
    fn render_account_page(state: EncryptionState) -> String {
        // Constructing that `Resource` spawns, and spawning without a global
        // executor panics in a debug build — the same install
        // `storage::hook`'s write-path tests do, but *not* for the same
        // reason: `spawn_local` (what `storage::hook` exercises) lands on a
        // thread-local `LocalPool` that is genuinely inert until something
        // calls `poll_local()`, which nothing here does. `Resource::new`'s
        // fetcher future is `Send`, so it goes through `Executor::spawn`
        // instead, and this backend's `spawn` dispatches straight to a real
        // background `futures::executor::ThreadPool` — it runs regardless of
        // whether anything ever polls it. (Traced through `reactive_graph`'s
        // `spawn` and `any_spawner`'s `init_futures_executor`.)
        //
        // It is harmless here only because `passkey_list()` reaches
        // `require_ctx()`, which returns a graceful `Err` on the missing
        // `AppCtx` rather than panicking — so the fetch this spawns quietly
        // fails and the fallback below is what actually renders either way.
        // A future server function that panics instead of erroring would
        // fail silently on that background thread, outside the per-test
        // `catch_unwind` `cargo test` wraps around the calling thread: this
        // test would keep passing while the thing it exercises died.
        //
        // Not asserted here that nothing panics: `any_spawner` hands back no
        // join handle for the spawned future, so observing its outcome would
        // mean racing a `sleep` against a `ThreadPool` worker thread, or
        // installing a process-global panic hook that every other test in
        // this binary shares — either risks flakiness or misattributing a
        // panic from an unrelated, concurrently-running test. If this ever
        // needs to be load-bearing rather than lucky, the fix is to give
        // `render_account_page` a real `AppCtx` (as `render_at` does) so the
        // fetch runs its real path instead of relying on `require_ctx()`'s
        // graceful failure.
        let _ = any_spawner::Executor::init_futures_executor();
        let runtime = Owner::new();
        let html = runtime.with(move || {
            provide_context(RequestUrl::new("/account"));
            provide_context(AuthCtx {
                user: RwSignal::new(Some("alice@example.com".to_string())),
            });
            provide_context(EncryptionCtx::for_state(state));
            view! { <Router><AccountPage/></Router> }.to_html()
        });
        runtime.cleanup();
        html
    }

    /// The mount gate's primary case (spec section 7.4): `Locked` must swap
    /// the entry area for the unlock prompt, not merely leave it showing
    /// unloaded — without this, `hook::loaded_value` would go on to map the
    /// locked read's failure to an empty string, rendering "No projects
    /// found" over a day of real data.
    #[test]
    fn day_view_shows_the_unlock_prompt_when_locked() {
        let html = render_day_view(EncryptionState::Locked);
        assert!(
            html.contains("Unlock your entries"),
            "a locked session must render the unlock prompt"
        );
        assert!(
            !html.contains("<textarea"),
            "the entry area must not mount alongside the unlock prompt"
        );
    }

    /// The failure mode a retry exists for: a probe that could not answer
    /// must say so and offer another try, not leave the entry area mounted
    /// over a session that refuses every save. The copy matters as much as
    /// the mount — this user is not locked out of anything, the app simply
    /// does not know yet.
    #[test]
    fn day_view_offers_a_retry_when_the_probe_could_not_answer() {
        let html = render_day_view(EncryptionState::Unreachable);
        assert!(
            html.contains("Try again"),
            "an unanswered probe must offer another try"
        );
        assert!(
            !html.contains("Unlock your entries"),
            "an unanswered probe is not a lockout and must not read as one"
        );
        assert!(
            !html.contains("<textarea"),
            "the entry area must not mount over a session that cannot save"
        );
    }

    /// The gate's other half: every other state still mounts the entry
    /// area, exactly as it did before this gate existed (spec 7.4's
    /// correction — `Unknown` is not a second reason to hide it).
    ///
    /// `Disabled` is here as a *signed-out* visitor, and that is spec
    /// section 4.1 rather than a convenience: the same state signed in is
    /// an account the server refuses every write from, which
    /// `a_signed_in_account_without_encryption_gets_no_entry_area` pins on
    /// the other side.
    #[test]
    fn day_view_shows_the_entry_area_when_not_locked() {
        for (user, state) in [
            (Some("alice@example.com"), EncryptionState::Unknown),
            (None, EncryptionState::Disabled),
            // `Unlocked` needs a `SessionKey`, uninhabited on the host — its
            // arm is covered by `encryption_ctx`'s own tests instead.
        ] {
            let html = render_day_view_for(user, state);
            assert!(
                html.contains("<textarea") && html.contains("></textarea>"),
                "a non-locked session must still mount the entry area"
            );
            assert!(
                !html.contains("Unlock your entries"),
                "a non-locked session must not render the unlock prompt"
            );
        }
    }

    /// A signed-in account with no encryption must not be shown a writing
    /// surface (spec section 4.1). The previous branch spent a whole fix
    /// round establishing why: an editable box that silently refuses to
    /// save is worse than no box, because the user types, nothing persists,
    /// and nothing says so.
    ///
    /// Both halves are asserted. Removing the box without saying where to
    /// go would swap a silent failure for a blank page, which is the other
    /// way to get this wrong.
    #[test]
    fn a_signed_in_account_without_encryption_gets_no_entry_area() {
        let html = render_day_view(EncryptionState::Disabled);
        assert!(
            !html.contains("<textarea"),
            "an account the server refuses every write from must not be \
             offered somewhere to type"
        );
        assert!(
            html.contains("Set up encryption"),
            "a gate that does not say what to do next reads as a broken page"
        );
    }

    /// The escape has to be *visible* on the setup view, not merely
    /// reachable: without it the gate reads as a lock-out to anyone who
    /// signed in on a borrowed machine, and the honest fact is that local
    /// mode works completely — it just stores nothing on the server (spec
    /// section 4.1).
    ///
    /// Asserted in both directions. An escape offered to an account that is
    /// already set up is not the same feature: it would sit permanently
    /// beside the passkey controls, inviting a sign-out nobody was gated
    /// into.
    #[test]
    fn the_gate_offers_a_way_back_to_local_mode() {
        let gated = render_account_page(EncryptionState::Disabled);
        assert!(
            gated.contains("Sign out and use this device only"),
            "the setup view must offer the way back to local mode"
        );

        let set_up = render_account_page(EncryptionState::Locked);
        assert!(
            !set_up.contains("Sign out and use this device only"),
            "an account that is past the gate must not be offered its escape"
        );
    }

    /// The other control on this page that claims to lead somewhere: unlike
    /// the escape above, "Back to today" is not a route out of the gate at
    /// all — `/` resolves to the day view, and `SetupGate` bounces a gated
    /// account straight back to `/account` on mount. Offering it during
    /// setup would read as a second way out that flashes and returns the
    /// user where they started, so it must be gone until setup is done.
    #[test]
    fn the_setup_view_hides_the_link_that_would_only_bounce_back() {
        let gated = render_account_page(EncryptionState::Disabled);
        assert!(
            !gated.contains("Back to today"),
            "a link that only bounces back to this same page reads as a broken exit"
        );
        // On the destination and not only on that one link's words. There
        // were two links to `/` on this page — `PasskeySection`'s and the
        // header's "Time Tracker" — and a text match saw only the first.
        // `href="/account"` does not match this: the quote is part of it.
        assert!(
            !gated.contains(r#"href="/""#),
            "every link to `/` bounces a gated account back here, whatever it says: {gated}"
        );
        assert!(
            gated.contains("Time Tracker"),
            "the header still names the app; it is the navigation that goes, not the name"
        );

        let set_up = render_account_page(EncryptionState::Locked);
        assert!(
            set_up.contains("Back to today"),
            "an account past the gate has a real destination at `/`, and the link back to it"
        );
        assert!(
            set_up.contains(r#"href="/""#),
            "and the header's title links there again: {set_up}"
        );
    }

    /// Signed out is untouched, and this is the assertion that stops the
    /// gate over-reaching. `Backend::Local` is never encrypted (spec section
    /// 1.2), so `Disabled` there is not a conclusion about an account at all
    /// — it is ordinary, fully working local mode, and the very mode the
    /// escape hatch above falls back to. Gating it would lock the app's
    /// main page for its main-page majority.
    #[test]
    fn a_signed_out_visitor_is_not_gated() {
        let html = render_day_view_for(None, EncryptionState::Disabled);
        assert!(
            html.contains("<textarea") && !html.contains("readonly"),
            "a signed-out visitor's box must be editable, not gated"
        );
        assert!(
            !html.contains("Set up encryption"),
            "a visitor with no account has nothing to set up"
        );
    }

    /// The window this exists to close: `Unknown` mounts the entry area —
    /// it has to, since the server renders `Unknown` for everybody — but
    /// `Unknown` is `WriteKey::Locked`, so every save made in it is refused.
    /// For a signed-in visitor that window is a full network round trip, and
    /// before this the box took keystrokes and dropped them with nothing on
    /// screen to say so.
    ///
    /// Read-only rather than absent, because the server renders this state
    /// and blanking it would remove the entry area from every server-rendered
    /// page. Both halves are asserted in both directions, so neither the
    /// attribute nor the line can be left permanently on or permanently off.
    #[test]
    fn the_entry_area_is_read_only_until_a_save_would_be_stored() {
        let waiting = render_day_view(EncryptionState::Unknown);
        assert!(
            waiting.contains("readonly"),
            "an unknown session must not offer an editable box it would refuse to save"
        );
        assert!(
            waiting.contains("nothing typed here would be saved yet"),
            "a greyed-out box with no explanation reads as broken: {waiting}"
        );

        // Signed out, because a signed-in `Disabled` no longer reaches the
        // entry area at all (spec section 4.1) — and because local mode is
        // the state where a save genuinely does land with no key involved.
        let saving = render_day_view_for(None, EncryptionState::Disabled);
        assert!(
            !saving.contains("readonly"),
            "a session that can save must hand over an editable box"
        );
        assert!(
            !saving.contains("nothing typed here would be saved yet"),
            "a page that saves must say nothing about not saving"
        );
    }

    #[test]
    fn ssr_renders_chrome() {
        let html = render_app();
        assert!(html.contains("Time Entry"), "entry pane heading missing");
        assert!(
            html.contains("Time Summary"),
            "summary pane heading missing"
        );
        assert!(html.contains("How to use this tool"), "help toggle missing");
        assert!(
            html.contains("whitespace-pre-wrap"),
            "help sample block missing — it must be in the SSR'd HTML, not \
             mounted client-side, or hydration sees a different node count"
        );
    }

    /// Pins spec invariant I2 of the migration design. The server cannot know
    /// whether the user has saved data, so it must not render any conclusion
    /// that depends on it.
    #[test]
    fn ssr_omits_loaded_state() {
        let html = render_app();
        assert!(
            !html.contains("No projects found"),
            "server rendered the empty state it cannot know; returning users \
             would see it flash before their data loads"
        );
        assert!(!html.contains("hours)"), "server rendered a computed total");
        assert!(
            !html.contains("No dead time"),
            "server rendered a dead-time conclusion"
        );
    }

    /// Pins invariant I1, and this is the case that would otherwise regress
    /// silently. For a signed-in visitor the server *could* read the entry
    /// row — it has the user and the date. It must not. Phase 2 encrypts
    /// bodies client-side, so a server render of entry content is not a
    /// performance win to be added later; it is a design the encryption
    /// cannot coexist with.
    #[test]
    fn ssr_omits_entry_content_even_when_signed_in() {
        let html = render_at("/2026-09-04", Some("alice@example.com"));
        // Proves the signed-in branch actually ran, so the assertions below
        // cannot pass vacuously against a render that quietly stayed on the
        // signed-out path (which renders "Sign in" and never "alice").
        // Self-contained rather than leaning on `ssr_renders_the_signed_in_identity`
        // to establish this: that test could be deleted or renamed without
        // this one failing, silently un-guarding invariant I1.
        assert!(
            html.contains("alice"),
            "this render must actually be the signed-in one, or the \
             assertions below prove nothing about a signed-in user"
        );
        assert!(
            !html.contains("No projects found"),
            "server rendered loaded state for a signed-in user"
        );
        assert!(
            !html.contains("hours)"),
            "server rendered a computed total for a signed-in user"
        );
        assert!(
            html.contains("<textarea") && html.contains("></textarea>"),
            "the SSR'd textarea must still be empty for a signed-in user"
        );
    }

    /// Pins invariant E2. The server could read `encrypted_at` cheaply — it
    /// has the session — but rendering `Locked` would put user-derived state
    /// in the SSR body, and the client cannot tell locked from unlocked
    /// without an async IndexedDB read anyway, so the first client render
    /// would differ regardless. `Unknown` on both sides is the only value
    /// that hydrates.
    ///
    /// Asserts negatively, like its two neighbours. Do not weaken it to make
    /// a change pass.
    ///
    /// This cannot distinguish `Unknown` from `Disabled` — neither renders
    /// unlock UI — so `encryption_ctx`'s
    /// `a_context_starts_unknown_and_refuses_writes` pins that half.
    #[test]
    fn ssr_renders_unknown_encryption_state() {
        let html = render_at("/2026-09-05", Some("alice@example.com"));
        // The same positive control as the test above, and for the same
        // reason: without it these assertions would pass just as well
        // against a render that quietly stayed on the signed-out path.
        assert!(
            html.contains("alice"),
            "this render must actually be the signed-in one, or the \
             assertions below prove nothing about a signed-in user"
        );
        assert!(
            !html.contains("Unlock"),
            "server rendered the locked prompt"
        );
        assert!(
            !html.contains("encryption key"),
            "server rendered unlock UI it cannot know is needed"
        );
    }

    /// The bug this round fixes, at a level `ssr_renders_unknown_encryption_state`
    /// cannot reach: a signed-out visitor is the app's main-page majority,
    /// and their data lives in `localStorage` — `Backend::Local`, never
    /// encrypted (spec 1.2). Before `EncryptionCtx` seeded from the
    /// signed-in identity, every server render started at `Unknown`, so
    /// this visitor's box was read-only and greyed out until wasm loaded and
    /// a probe confirmed what the seed already knows for free.
    #[test]
    fn ssr_offers_an_editable_entry_area_when_signed_out() {
        let html = render_app();
        // Positive control: every assertion below also holds if the entry
        // area were missing entirely, which is exactly the over-gating
        // regression this test's name promises to catch. This is the one
        // difference from `a_signed_out_visitor_is_not_gated`, which asserts
        // the same thing but renders `DayView` directly — this render goes
        // through the full route table (`App` -> `Routes` -> `DayPage`),
        // so it is worth keeping rather than deleting as a duplicate.
        assert!(
            html.contains("<textarea") && html.contains("></textarea>"),
            "a signed-out visitor must be offered an entry area to edit"
        );
        assert!(
            !html.contains("readonly"),
            "a signed-out visitor's session has nothing to probe for and \
             must be editable immediately"
        );
        assert!(
            !html.contains("nothing typed here would be saved yet"),
            "a page that can already save must say nothing about not saving"
        );
    }

    /// The half that must not regress alongside the fix above: a signed-in
    /// visitor's account may be encrypted, so the seed still starts at
    /// `Unknown` and the box stays read-only until the probe resolves.
    #[test]
    fn ssr_still_withholds_an_editable_entry_area_when_signed_in() {
        let html = render_at("/2026-09-04", Some("alice@example.com"));
        assert!(
            html.contains("alice"),
            "this render must actually be the signed-in one, or the \
             assertions below prove nothing about a signed-in user"
        );
        assert!(
            html.contains("readonly"),
            "a signed-in visitor's account may be encrypted, so the box \
             must stay read-only until the probe resolves"
        );
        assert!(
            html.contains("nothing typed here would be saved yet"),
            "the read-only box must say why, until the probe resolves"
        );
    }

    /// The other half of the same decision: auth state *is* server-rendered,
    /// because the cookie is right there and a flash of "Sign in" on every
    /// reload is worse than the alternative.
    #[test]
    fn ssr_renders_the_signed_in_identity() {
        let html = render_at("/2026-09-04", Some("alice@example.com"));
        assert!(
            html.contains("alice"),
            "the signed-in identity must be server-rendered, or a returning \
             user sees 'Sign in' flash before their account appears"
        );
    }

    #[test]
    fn ssr_renders_sign_in_when_signed_out() {
        let html = render_at("/2026-09-04", None);
        assert!(
            html.contains("Sign in"),
            "signed-out header must offer sign-in"
        );
    }

    /// `/` cannot name a date, so it must render none rather than guess.
    #[test]
    fn root_route_renders_no_date() {
        let html = render_at("/", None);
        assert!(
            !html.contains("2026"),
            "`/` must not render a specific date — the server does not know \
             the visitor's timezone (spec section 8.1)"
        );
    }

    #[test]
    fn a_non_date_segment_renders_not_found() {
        let html = render_at("/not-a-date", None);
        assert!(html.contains("Page not found"));
    }

    /// Pins invariant I4 for the one element whose SSR shape is subtle.
    #[test]
    fn ssr_textarea_is_empty() {
        let html = render_app();
        assert!(
            html.contains("<textarea") && html.contains("></textarea>"),
            "the SSR'd textarea must have no text content, so the hydrate-side \
             prop:value binding attaches to a matching node"
        );
    }
}
