//! `/account`'s encryption panel: turning encryption on, and living with it.
//!
//! The highest-stakes screen in the application. Everything else here can be
//! undone; this cannot. An account whose passkeys are all gone *and* whose
//! recovery code is lost has no readable entries again, ever — not for the
//! user and not for whoever runs the server, because the server never held
//! the key. The copy below says that in those words on purpose. Softening it
//! to "may not be recoverable" would be a lie that costs somebody their
//! data.
//!
//! Three things the ceremonies make unavoidable, which the panel therefore
//! states before it starts rather than springing mid-flow:
//!
//! 1. **Enabling asks for a passkey again.** Creating a credential reports
//!    only *whether* PRF is available, never the output, so the key material
//!    has to come from a fresh assertion (spec section 6.1 step 1).
//! 2. **Adding a passkey costs three authenticator interactions, always** —
//!    create it, assert against a credential that can already unlock to
//!    re-derive the raw key, assert against the new one for its PRF output.
//!    An unlocked session does not save one of them: what it holds is a
//!    *sealed* key, which by construction cannot yield its bytes (spec
//!    section 6.5, invariant E5).
//! 3. **The recovery code is shown once.** `reissue_recovery` mints a *new*
//!    one; nothing anywhere can reproduce the old.
//!
//! The panel reads [`EncryptionCtx`] for the account's state and never
//! probes on its own, so on the server it renders the "checking" branch for
//! everybody (invariant E2) and hydrates against itself.

use leptos::either::{Either, EitherOf3, EitherOf4};
use leptos::prelude::*;

use crate::auth_ctx::AuthCtx;
use crate::clipboard::copy_to_clipboard;
use crate::encryption_ctx::{EncryptionCtx, EncryptionState};

#[cfg(any(feature = "hydrate", test))]
use crate::crypto::choose_route;
#[cfg(any(feature = "hydrate", test))]
use crate::dto::{PasskeyListItem, WrapDto};
#[cfg(any(feature = "hydrate", test))]
use crate::storage::envelope::{ReadPlan, plan_read};

#[cfg(feature = "hydrate")]
use leptos::task::spawn_local;

#[cfg(feature = "hydrate")]
use crate::crypto::SessionKey;
#[cfg(feature = "hydrate")]
use crate::storage::Generation;

/// What the account's encryption state means for this panel, with the key
/// itself dropped.
///
/// A `Copy + PartialEq` reduction of [`EncryptionState`] so the load effect
/// below can hang off a `Memo` and re-run when the *situation* changes
/// rather than on every republish of the same one. It also keeps
/// [`SessionKey`] — which is neither `Send` nor `Sync`, and uninhabited off
/// the browser — out of the panel's branching entirely; the one place that
/// needs the key reads it back out of the context at the moment it acts.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// The probe has not answered yet. Everything the server renders.
    Checking,
    /// The probe failed; nothing is known and nothing will change on its own.
    Unreachable,
    /// The account is not encrypted.
    Off,
    /// Encrypted, and this device holds no key.
    Locked,
    /// Encrypted, and this device holds the key.
    Unlocked,
}

impl Phase {
    fn of(state: &EncryptionState) -> Self {
        match state {
            EncryptionState::Unknown => Phase::Checking,
            EncryptionState::Unreachable => Phase::Unreachable,
            EncryptionState::Disabled => Phase::Off,
            EncryptionState::Locked => Phase::Locked,
            EncryptionState::Unlocked(_) => Phase::Unlocked,
        }
    }

    /// Whether the account is encrypted, whatever this device can do about
    /// it. Browser-only, like the fetch it steers: the server never leaves
    /// `Checking`.
    #[cfg(feature = "hydrate")]
    fn encrypted(self) -> bool {
        matches!(self, Phase::Locked | Phase::Unlocked)
    }

    /// Whether there is anything worth fetching. `Checking` and
    /// `Unreachable` know nothing, and asking the server about an account
    /// whose state is still unknown would only produce an answer this panel
    /// could not place.
    #[cfg(feature = "hydrate")]
    fn wants_overview(self) -> bool {
        matches!(self, Phase::Off | Phase::Locked | Phase::Unlocked)
    }
}

/// Whether one enrolled passkey can open the account's data key.
///
/// Three states rather than a boolean because the two "no" answers are not
/// the same thing to a user. One is a dead end — the authenticator cannot
/// produce the PRF output a key is derived from, and never will — and the
/// other is a gap they can close in two prompts. Reporting them alike would
/// either offer a repair that cannot work or hide one that can (spec
/// section 6.5).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(not(feature = "hydrate"), allow(dead_code))]
enum RouteStatus {
    /// A wrap exists for this credential: it opens the data key.
    CanUnlock,
    /// PRF-capable, but no wrap yet — enrolled before encryption was turned
    /// on, or its wrap step did not finish.
    NoKeyYet,
    /// The authenticator reported no PRF support when this credential was
    /// enrolled, so no key can ever be derived from it.
    NeverCapable,
}

impl RouteStatus {
    /// The short badge beside the passkey's name.
    fn label(self) -> &'static str {
        match self {
            RouteStatus::CanUnlock => "Can unlock",
            RouteStatus::NoKeyYet => "No unlock key",
            RouteStatus::NeverCapable => "Can't unlock",
        }
    }

    /// The sentence under it. `NeverCapable` says what still works as well
    /// as what does not: the passkey is not broken, it just cannot carry a
    /// key, and a user who reads only the badge might delete a perfectly
    /// good sign-in credential.
    fn explanation(self) -> &'static str {
        match self {
            RouteStatus::CanUnlock => "Opens your entries on any device you use it from.",
            RouteStatus::NoKeyYet => {
                "Signs you in, but has no key for your entries yet. Two passkey prompts will fix that."
            }
            RouteStatus::NeverCapable => {
                "Signs you in, but this authenticator can't derive an encryption key, so this \
                 passkey will never open your entries."
            }
        }
    }
}

/// One enrolled passkey, as this panel talks about it.
#[derive(Clone)]
#[cfg_attr(not(feature = "hydrate"), allow(dead_code))]
struct PasskeyRoute {
    name: String,
    /// Kept so the repair control can name the credential it is fixing.
    credential_id: Vec<u8>,
    status: RouteStatus,
}

/// Joins one passkey against the account's stored wraps.
///
/// Goes through [`choose_route`] rather than scanning `wraps` here, so a row
/// whose `kdf` or `wrap_alg` this build does not recognise reads as "no
/// unlock key" — which is the truth for this build — instead of as a working
/// route it would then fail to open.
#[cfg(any(feature = "hydrate", test))]
fn classify(row: PasskeyListItem, wraps: &[WrapDto]) -> PasskeyRoute {
    let status = if choose_route(wraps, Some(&row.credential_id)).is_some() {
        RouteStatus::CanUnlock
    } else if row.prf_capable {
        RouteStatus::NoKeyYet
    } else {
        RouteStatus::NeverCapable
    };
    PasskeyRoute {
        name: row.name,
        credential_id: row.credential_id,
        status,
    }
}

/// What one pass over `entries_all()` found.
///
/// The server cannot produce this: answering "how many rows are still
/// plaintext" means reading each row's envelope version, which is parsing a
/// body, which invariant E1 forbids outright. So the count comes from the
/// browser doing the classification itself (spec section 8).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
#[cfg_attr(not(feature = "hydrate"), allow(dead_code))]
struct MigrationScan {
    /// `(date, plaintext body)` for every row still stored as v1.
    pending: Vec<(String, String)>,
    /// Dates of rows this build could not interpret at all. Counted rather
    /// than skipped silently: a row nobody is told about stays plaintext
    /// forever.
    unreadable: Vec<String>,
}

/// Sorts `entries_all()`'s rows into the ones the migration must re-write
/// and the ones it cannot touch.
///
/// Pure, and the only part of the migration a host test can reach — sealing
/// a body goes through WebCrypto, which has no host equivalent. Dispatch is
/// on each row's own envelope version, never on account state, which is what
/// makes the pass resumable: run it again and it simply finds fewer v1 rows
/// (spec E3, section 8).
#[cfg(any(feature = "hydrate", test))]
fn migration_scan(rows: Vec<(String, String)>) -> MigrationScan {
    let mut scan = MigrationScan::default();
    for (date, raw) in rows {
        match plan_read(&raw) {
            Ok(ReadPlan::Plaintext(body)) => scan.pending.push((date, body)),
            Ok(ReadPlan::Sealed(_)) => {}
            Err(_) => scan.unreadable.push(date),
        }
    }
    scan
}

/// Everything the panel fetches about the account in one go.
#[derive(Clone, Default)]
#[cfg_attr(not(feature = "hydrate"), allow(dead_code))]
struct Overview {
    routes: Vec<PasskeyRoute>,
    /// Whether a recovery wrap this build can open is on file.
    has_recovery_wrap: bool,
    unencrypted_days: usize,
    unreadable_days: usize,
}

impl Overview {
    /// Whether any enrolled passkey could hold a key — the precondition for
    /// turning encryption on at all.
    fn has_capable_passkey(&self) -> bool {
        self.routes
            .iter()
            .any(|route| route.status != RouteStatus::NeverCapable)
    }
}

/// Where the panel is in a flow it started itself.
///
/// Outranks [`Phase`] in the view, because the recovery-code screen has to
/// survive the state change that produced it: publishing the new key flips
/// the account to `Unlocked`, and if that decided what was on screen the
/// code would vanish before it could be read. The same trap `UnlockPrompt`
/// documents, one ceremony further along.
///
/// `#[cfg_attr]`'d for the same reason as `UnlockPrompt`'s `Mode`: the two
/// code-bearing variants are built only by browser-side ceremonies, so a
/// build with `hydrate` off constructs neither.
#[derive(Clone, Default)]
#[cfg_attr(not(feature = "hydrate"), allow(dead_code))]
enum Mode {
    /// Showing whatever the account's state calls for.
    #[default]
    Idle,
    /// The code minted by the enable ceremony. Confirming it publishes the
    /// key and starts the migration.
    NewCode(String),
    /// A re-issued code. Confirming it just closes.
    ReissuedCode(String),
}

/// The one line the panel talks back through.
///
/// Two variants rather than a bare `String` because the severity has to
/// reach the styling, and every one of these ceremonies can half-finish: a
/// passkey enrolled with no unlock key, a lock whose keystore clear failed,
/// a migration that stopped partway. A failure rendered in the same muted
/// grey as "Encrypted 3 days." is a failure the user scrolls past.
#[derive(Clone)]
#[cfg_attr(not(feature = "hydrate"), allow(dead_code))]
enum Status {
    /// Something worked, or is under way.
    Note(String),
    /// Something did not.
    Problem(String),
}

impl Status {
    fn message(&self) -> &str {
        match self {
            Status::Note(message) | Status::Problem(message) => message,
        }
    }

    fn class(&self) -> &'static str {
        match self {
            Status::Note(_) => "text-sm text-gray-600 mb-3",
            Status::Problem(_) => "text-sm text-red-700 mb-3",
        }
    }
}

/// "1 day" / "2 days", so counts read as English.
fn days(n: usize) -> String {
    format!("{n} {}", if n == 1 { "day" } else { "days" })
}

#[component]
pub fn EncryptionPanel(
    /// Bumped by whoever changes the account's passkeys, and by this panel
    /// when it changes them itself. Shared with `PasskeySection` so the two
    /// halves of `/account` cannot disagree about which passkeys exist.
    reload: RwSignal<u32>,
) -> impl IntoView {
    let auth = use_context::<AuthCtx>().expect("AuthCtx provided by App");
    let encryption = use_context::<EncryptionCtx>().expect("EncryptionCtx provided by App");

    let mode = RwSignal::new(Mode::default());
    let status = RwSignal::new(Option::<Status>::None);
    // Every control that starts a ceremony is disabled on this, so a
    // double-click cannot open two assertions against the same account —
    // the same guard `UnlockPrompt` uses, and it matters more here: two
    // overlapping enable ceremonies would each mint a recovery code, and
    // only one of them would open anything.
    let busy = RwSignal::new(false);
    let understood = RwSignal::new(false);
    let overview = RwSignal::new(Option::<Overview>::None);

    let phase = Memo::new(move |_| Phase::of(&encryption.state()));

    // Bridges the enable ceremony's two clicks. Publishing the key the
    // moment `encryption_enable` returns would flip the account to
    // `Unlocked` and re-render this panel into its manage view, taking the
    // recovery code off the screen before the user had confirmed — or even
    // read — it.
    #[cfg(feature = "hydrate")]
    let pending_key = StoredValue::<Option<SessionKey>, LocalStorage>::new_local(None);

    // Browser-only in full: every call inside reaches the network, and the
    // server has nothing to render from the answer anyway (it is always
    // `Phase::Checking`, invariant E2).
    #[cfg(feature = "hydrate")]
    {
        let generation = StoredValue::new(Generation::default());
        Effect::new(move |_| {
            let phase = phase.get();
            // Tracked so a passkey added or removed on the other half of
            // this page re-classifies the routes below.
            let _ = reload.get();
            // Captured before the `spawn_local`, for the reason
            // `EncryptionCtx::start_probe` spells out: this effect can
            // re-run while an earlier fetch is still awaiting, and reading
            // the token back after the await would race that later run.
            let token = generation
                .try_update_value(Generation::next)
                .unwrap_or_default();

            if !phase.wants_overview() {
                overview.set(None);
                return;
            }
            let encrypted = phase.encrypted();

            spawn_local(async move {
                let loaded = ceremony::load_overview(encrypted).await;
                let is_current = generation
                    .try_with_value(|g| g.is_current(token))
                    .unwrap_or(false);
                if !is_current {
                    return;
                }
                match loaded {
                    Ok(loaded) => overview.set(Some(loaded)),
                    Err(message) => {
                        overview.set(None);
                        status.set(Some(Status::Problem(message)));
                    }
                }
            });
        });
    }

    // Re-encrypts whatever is left in the clear. Shared by the tail of the
    // enable ceremony and the resume control, which are the same operation
    // reached from two places — the second exists precisely because the
    // first can be interrupted (spec section 8).
    let run_migration = move || {
        #[cfg(feature = "hydrate")]
        {
            busy.set(true);
            status.set(Some(Status::Note(
                "Encrypting the entries already saved…".to_string(),
            )));
            spawn_local(async move {
                // The key is read here rather than carried in, so a lock or
                // a sign-out that landed while this was queued is seen.
                let state = encryption.state_untracked();
                let outcome = match state.key() {
                    Some(key) => ceremony::migrate(key).await,
                    None => Err("This device is locked, so nothing could be re-encrypted \
                                 yet."
                        .to_string()),
                };
                busy.set(false);
                match outcome {
                    Ok(0) => status.set(Some(Status::Note(
                        "Everything is already encrypted.".to_string(),
                    ))),
                    Ok(count) => {
                        status.set(Some(Status::Note(format!("Encrypted {}.", days(count)))))
                    }
                    Err(message) => status.set(Some(Status::Problem(message))),
                }
                reload.update(|n| *n += 1);
            });
        }
    };

    let turn_on = move || {
        status.set(None);
        #[cfg(feature = "hydrate")]
        {
            let Some(user) = auth.user.get_untracked() else {
                // Unreachable in practice: the panel only renders for a
                // signed-in visitor. Doing nothing costs nothing if that
                // ever stops holding.
                return;
            };
            busy.set(true);
            spawn_local(async move {
                let outcome = ceremony::enable_encryption(&user).await;
                busy.set(false);
                match outcome {
                    Ok((key, code)) => {
                        pending_key.set_value(Some(key));
                        mode.set(Mode::NewCode(code));
                    }
                    Err(message) => status.set(Some(Status::Problem(message))),
                }
            });
        }
    };

    let confirm_new_code = move || {
        mode.set(Mode::Idle);
        #[cfg(feature = "hydrate")]
        {
            let Some(Some(key)) = pending_key.try_update_value(Option::take) else {
                return;
            };
            // `EncryptionCtx::unlock` refuses a key for an account that is
            // no longer the signed-in one, so a sign-out during the code
            // screen leaves the key unpublished rather than sealing the
            // signed-out page's `localStorage` under it.
            encryption.unlock(key);
            run_migration();
        }
    };

    let dismiss_code = move || {
        mode.set(Mode::Idle);
        status.set(None);
    };

    let lock_now = move || {
        status.set(None);
        #[cfg(feature = "hydrate")]
        {
            busy.set(true);
            spawn_local(async move {
                let outcome = encryption.lock().await;
                busy.set(false);
                match outcome {
                    Ok(()) => status.set(Some(Status::Note(
                        "Locked. You'll need a passkey or your recovery code to read your \
                         entries in this browser again."
                            .to_string(),
                    ))),
                    // The state is `Locked` either way — that half happens
                    // before the await — but a keystore this browser could
                    // not clear will hand the key straight back on the next
                    // load, and a user who locked deliberately should not
                    // find out by accident.
                    Err(_) => status.set(Some(Status::Problem(
                        "Locked for now, but this browser couldn't forget the stored key. \
                         It may unlock itself again after a reload — clear this site's \
                         data if that matters."
                            .to_string(),
                    ))),
                }
            });
        }
    };

    let new_recovery_code = move || {
        status.set(None);
        #[cfg(feature = "hydrate")]
        {
            let Some(user) = auth.user.get_untracked() else {
                return;
            };
            busy.set(true);
            spawn_local(async move {
                let outcome = ceremony::reissue_with_passkey(&user).await;
                busy.set(false);
                match outcome {
                    Ok(code) => mode.set(Mode::ReissuedCode(code)),
                    Err(message) => status.set(Some(Status::Problem(message))),
                }
            });
        }
    };

    let give_key = move |credential_id: Vec<u8>| {
        status.set(None);
        #[cfg(feature = "hydrate")]
        {
            let Some(user) = auth.user.get_untracked() else {
                return;
            };
            busy.set(true);
            spawn_local(async move {
                let outcome = crate::crypto::flow::add_passkey_key(&user, &credential_id).await;
                busy.set(false);
                match outcome {
                    Ok(()) => {
                        status.set(Some(Status::Note(
                            "That passkey can now open your entries.".to_string(),
                        )));
                        reload.update(|n| *n += 1);
                    }
                    Err(message) => status.set(Some(Status::Problem(message))),
                }
            });
        }
        #[cfg(not(feature = "hydrate"))]
        let _ = credential_id;
    };

    let retry_probe = move || {
        status.set(None);
        #[cfg(feature = "hydrate")]
        encryption.retry();
    };

    // Read unconditionally so the context lookup itself is not `cfg`-forked,
    // but consumed only by the browser-side handlers above: there is no
    // ceremony to run, and no list to fetch, during a server render.
    #[cfg(not(feature = "hydrate"))]
    let _ = (auth, reload);

    view! {
        <div class="bg-white rounded-lg shadow-sm border border-gray-200 p-6 mt-6">
            {move || status.get().map(|line| view! {
                <p class=line.class()>{line.message().to_string()}</p>
            })}
            {move || match mode.get() {
                Mode::NewCode(code) => EitherOf3::A(view! {
                    <RecoveryCodeCard
                        code=code
                        heading="Save your recovery code"
                        intro="This is the only thing that opens your entries if you lose every \
                               passkey. It is shown once — leaving this page without it means \
                               generating a replacement from this panel while you still have a \
                               passkey that works."
                        confirm="I've saved it — finish turning on encryption"
                        on_confirm=confirm_new_code
                    />
                }),
                Mode::ReissuedCode(code) => EitherOf3::B(view! {
                    <RecoveryCodeCard
                        code=code
                        heading="Your new recovery code"
                        intro="Your previous code no longer works. This one is shown once and \
                               never again."
                        confirm="I've saved it"
                        on_confirm=dismiss_code
                    />
                }),
                Mode::Idle => EitherOf3::C(match phase.get() {
                    // What the server renders for everybody, and what the
                    // browser renders until the probe lands (invariant E2).
                    Phase::Checking => EitherOf4::A(view! {
                        <div>
                            <h2 class="text-lg font-semibold text-gray-800 mb-1">"Encryption"</h2>
                            <p class="text-sm text-gray-500">"Checking this account…"</p>
                        </div>
                    }),
                    Phase::Unreachable => EitherOf4::B(view! {
                        <div>
                            <h2 class="text-lg font-semibold text-gray-800 mb-1">"Encryption"</h2>
                            <p class="text-sm text-gray-600 mb-4">
                                "We couldn't tell whether this account's entries are encrypted. \
                                 Nothing is being saved until we can — guessing wrong would \
                                 store your entries in the clear."
                            </p>
                            <button
                                type="button"
                                class="bg-blue-600 text-white text-sm font-semibold rounded px-4 py-2 hover:bg-blue-700"
                                on:click=move |_| retry_probe()
                            >
                                "Try again"
                            </button>
                        </div>
                    }),
                    Phase::Off => EitherOf4::C(view! {
                        <EnableSection
                            overview=overview
                            understood=understood
                            busy=busy
                            on_enable=turn_on
                        />
                    }),
                    encrypted @ (Phase::Locked | Phase::Unlocked) => EitherOf4::D(view! {
                        <ManageSection
                            unlocked=encrypted == Phase::Unlocked
                            overview=overview
                            busy=busy
                            on_lock=lock_now
                            on_reissue=new_recovery_code
                            on_migrate=run_migration
                            on_give_key=give_key
                        />
                    }),
                }),
            }}
        </div>
    }
}

/// The one-time display of a recovery code (spec section 6.1 step 5).
///
/// The confirmation is a button rather than a timer or a plain dismiss: the
/// user has to say they have the code before this closes, and nothing here
/// can show it to them again afterwards.
#[component]
fn RecoveryCodeCard(
    code: String,
    heading: &'static str,
    intro: &'static str,
    confirm: &'static str,
    on_confirm: impl Fn() + Copy + Send + 'static,
) -> impl IntoView {
    let copied = RwSignal::new(false);
    let to_copy = code.clone();
    // Fire-and-forget: `copy_to_clipboard` cannot report a clipboard the
    // browser refused, so the code stays on screen and the line below says
    // to write it down rather than trusting the copy.
    let copy = move |_| {
        copy_to_clipboard(to_copy.clone());
        copied.set(true);
    };

    view! {
        <div>
            <h2 class="text-lg font-semibold text-gray-800 mb-1">{heading}</h2>
            <p class="text-sm text-gray-600 mb-3">{intro}</p>
            <p class="font-mono text-sm bg-gray-50 border border-gray-200 rounded px-3 py-2 mb-2 break-all">
                {code}
            </p>
            <div class="flex items-center gap-3 mb-4">
                <button
                    type="button"
                    class="border border-gray-300 text-sm rounded px-3 py-1.5 hover:bg-gray-50"
                    on:click=copy
                >
                    "Copy"
                </button>
                <p class="text-xs text-gray-500">
                    {move || copied.get().then(|| view! {
                        <span class="text-green-700">"Copied. "</span>
                    })}
                    "Store it in a password manager, or write it down."
                </p>
            </div>
            <button
                type="button"
                class="w-full bg-blue-600 text-white text-sm font-semibold rounded py-2 hover:bg-blue-700"
                on:click=move |_| on_confirm()
            >
                {confirm}
            </button>
        </div>
    }
}

/// The pitch, the warning, and the gate (spec section 6.1).
#[component]
fn EnableSection(
    overview: RwSignal<Option<Overview>>,
    understood: RwSignal<bool>,
    busy: RwSignal<bool>,
    on_enable: impl Fn() + Copy + Send + 'static,
) -> impl IntoView {
    // Three answers, not two. Until the fetch lands nothing is known, which
    // disables the button — offering a ceremony that would fail at its first
    // assertion is worse than a moment of greyed-out control — but it must
    // not yet *say* the account has no usable passkey. That claim is only
    // true once the list is in, and rendering it before then would flash a
    // false alarm on every visit, including the server's own render.
    let known = move || overview.get().is_some();
    let capable = move || {
        overview
            .get()
            .is_some_and(|overview| overview.has_capable_passkey())
    };

    view! {
        <div>
            <h2 class="text-lg font-semibold text-gray-800 mb-1">"Encrypt your entries"</h2>
            <p class="text-sm text-gray-600 mb-4">
                "Right now this account's entries are stored on the server as plain text: \
                 anyone who can read the database — including whoever runs this server — can \
                 read them. Turning encryption on locks them to a key that only your browser \
                 ever holds."
            </p>

            <div class="rounded border border-red-200 bg-red-50 p-3 mb-4">
                <p class="text-sm font-semibold text-red-900 mb-1">"There is no reset."</p>
                <p class="text-sm text-red-900">
                    "If you lose every passkey and your recovery code, your entries are gone \
                     forever — for you and for whoever runs this server. Nobody can unlock \
                     them, because nobody else ever has the key. This is not a password that \
                     can be reissued."
                </p>
            </div>

            <p class="text-sm font-medium text-gray-800 mb-1">"What happens when you turn it on"</p>
            <ul class="list-disc pl-5 text-sm text-gray-600 mb-4 space-y-1">
                <li>
                    "Your browser asks for a passkey. Creating a passkey doesn't hand back the \
                     key material this needs, so even one you added a moment ago has to answer \
                     a fresh prompt."
                </li>
                <li>
                    "You're shown a recovery code, once. Save it before you close the page — it \
                     is never shown again."
                </li>
                <li>"Entries you've already saved are re-encrypted in place. Nothing is deleted."</li>
                <li>
                    "Adding another passkey afterwards takes three passkey prompts, every time. \
                     That's a consequence of the key never leaving your authenticator in a \
                     copyable form, not a bug to be fixed later."
                </li>
            </ul>

            {move || (known() && !capable()).then(|| view! {
                <p class="text-sm text-amber-800 bg-amber-50 border border-amber-200 rounded p-3 mb-4">
                    "Encryption needs a passkey that can hold a key. Add one above first — if \
                     you already have passkeys, none of their authenticators reported support \
                     for the extension the key is derived from."
                </p>
            })}

            <label class="flex items-start gap-2 text-sm text-gray-700 mb-4">
                <input
                    type="checkbox"
                    class="mt-0.5"
                    prop:checked=move || understood.get()
                    on:change=move |ev| understood.set(event_target_checked(&ev))
                />
                <span>
                    "I understand that losing every passkey and my recovery code means losing \
                     my entries for good."
                </span>
            </label>

            <button
                type="button"
                class="bg-blue-600 text-white text-sm font-semibold rounded px-4 py-2 hover:bg-blue-700 disabled:opacity-60"
                disabled=move || busy.get() || !understood.get() || !capable()
                on:click=move |_| on_enable()
            >
                "Turn on encryption"
            </button>
        </div>
    }
}

/// The panel for an account that is already encrypted (spec sections 6.5,
/// 6.6, 6.7 and 8).
#[component]
fn ManageSection(
    unlocked: bool,
    overview: RwSignal<Option<Overview>>,
    busy: RwSignal<bool>,
    on_lock: impl Fn() + Copy + Send + 'static,
    on_reissue: impl Fn() + Copy + Send + 'static,
    on_migrate: impl Fn() + Copy + Send + 'static,
    on_give_key: impl Fn(Vec<u8>) + Copy + Send + 'static,
) -> impl IntoView {
    view! {
        <div>
            <h2 class="text-lg font-semibold text-gray-800 mb-1">"Encryption is on"</h2>
            <p class="text-sm text-gray-600 mb-4">
                "Entry bodies are encrypted in this browser before they're saved. The server \
                 stores ciphertext it cannot read."
            </p>

            {if unlocked {
                Either::Left(view! {
                    <div class="mb-5">
                        <p class="text-sm text-gray-700 mb-2">"This device is unlocked."</p>
                        <button
                            type="button"
                            class="border border-gray-300 text-sm rounded px-3 py-1.5 hover:bg-gray-50 disabled:opacity-60"
                            disabled=move || busy.get()
                            on:click=move |_| on_lock()
                        >
                            "Lock now"
                        </button>
                        <p class="text-xs text-gray-500 mt-1">
                            "Forgets the key stored in this browser. You'll need a passkey or \
                             your recovery code to read your entries here again."
                        </p>
                    </div>
                })
            } else {
                Either::Right(view! {
                    <p class="text-sm text-gray-700 mb-5">
                        "This device is locked — it holds no key for this account. Open any day \
                         and choose “Unlock your entries” to read them here."
                    </p>
                })
            }}

            <h3 class="text-sm font-medium text-gray-800 mb-1">"What can unlock your entries"</h3>
            {move || match overview.get() {
                None => Either::Left(view! { <p class="text-sm text-gray-500">"Loading…"</p> }),
                Some(overview) => Either::Right(view! {
                    <div>
                        <ul class="divide-y divide-gray-100 mb-2">
                            {overview.routes.into_iter()
                                .map(|route| view! { <RouteRow route=route busy=busy on_give_key=on_give_key/> })
                                .collect_view()}
                        </ul>
                        // Never reached by a healthy account — `encryption_enable`
                        // inserts a recovery wrap in the same transaction that turns
                        // encryption on, and re-issuing replaces it in one. It is
                        // still worth saying: an account in this state is one lost
                        // authenticator away from unreadable, and silence would be
                        // the worst possible way to report that.
                        {(!overview.has_recovery_wrap).then(|| view! {
                            <p class="text-sm text-red-700 bg-red-50 border border-red-200 rounded p-3 mb-2">
                                "No recovery code is on file for this account. If you lose the \
                                 passkeys above, your entries are gone. Generate one now."
                            </p>
                        })}
                        {(overview.unencrypted_days > 0).then(|| view! {
                            <div class="rounded border border-amber-200 bg-amber-50 p-3 mb-2">
                                <p class="text-sm text-amber-900 mb-2">
                                    {format!("{} still stored unencrypted.", days(overview.unencrypted_days))}
                                </p>
                                {if unlocked {
                                    Either::Left(view! {
                                        <button
                                            type="button"
                                            class="bg-amber-700 text-white text-sm font-semibold rounded px-3 py-1.5 hover:bg-amber-800 disabled:opacity-60"
                                            disabled=move || busy.get()
                                            on:click=move |_| on_migrate()
                                        >
                                            "Finish encrypting"
                                        </button>
                                    })
                                } else {
                                    Either::Right(view! {
                                        <p class="text-sm text-amber-900">
                                            "Unlock this device to finish."
                                        </p>
                                    })
                                }}
                            </div>
                        })}
                        {(overview.unreadable_days > 0).then(|| view! {
                            <p class="text-sm text-red-700 mb-2">
                                {format!(
                                    "{} could not be read at all. Nothing was changed there.",
                                    days(overview.unreadable_days),
                                )}
                            </p>
                        })}
                    </div>
                }),
            }}

            <p class="text-xs text-gray-500 mt-3">
                "Adding a passkey to an encrypted account takes three passkey prompts, every \
                 time: one to create it, one against a passkey that can already unlock, and one \
                 against the new one. An unlocked session doesn't save a prompt — the key it \
                 holds is sealed and can't be copied out."
            </p>

            <div class="mt-6 pt-4 border-t border-gray-100">
                <button
                    type="button"
                    class="text-sm text-gray-600 hover:text-gray-900 underline disabled:opacity-60"
                    disabled=move || busy.get()
                    on:click=move |_| on_reissue()
                >
                    "Generate a new recovery code"
                </button>
                <p class="text-xs text-gray-500 mt-1">
                    "Asks for a passkey, then shows a new code once. Your current code stops \
                     working as soon as the new one is stored."
                </p>
            </div>
        </div>
    }
}

/// One passkey's line in the unlock list.
///
/// A credential that cannot unlock is labelled here, never hidden: a user
/// who believes a passkey will open their entries and finds out otherwise
/// after losing the others has been misled by the omission (spec 6.5).
#[component]
fn RouteRow(
    route: PasskeyRoute,
    busy: RwSignal<bool>,
    on_give_key: impl Fn(Vec<u8>) + Copy + Send + 'static,
) -> impl IntoView {
    let status = route.status;
    let credential_id = route.credential_id;

    view! {
        <li class="flex items-start justify-between gap-3 py-2">
            <div class="min-w-0">
                <p class="text-sm font-medium text-gray-900">
                    {route.name}
                    <span class="ml-2 text-xs font-normal text-gray-500">{status.label()}</span>
                </p>
                <p class="text-xs text-gray-500">{status.explanation()}</p>
            </div>
            {(status == RouteStatus::NoKeyYet).then(|| view! {
                <button
                    type="button"
                    class="text-sm text-blue-600 hover:text-blue-800 shrink-0 disabled:opacity-60"
                    disabled=move || busy.get()
                    on:click=move |_| on_give_key(credential_id.clone())
                >
                    "Give it an unlock key"
                </button>
            })}
        </li>
    }
}

/// The panel's ceremonies: the ones only this panel runs. The steps shared
/// with `UnlockPrompt` live in [`crate::crypto::flow`].
///
/// Browser-only, like the rest of spec section 6.
#[cfg(feature = "hydrate")]
mod ceremony {
    use super::{MigrationScan, Overview, classify, migration_scan};
    use crate::crypto::flow::{self, PrfAssertion};
    use crate::crypto::{Opener, SessionKey, choose_route, enable};
    use crate::server_fns::encryption::{encryption_enable, encryption_wraps};
    use crate::server_fns::entries::{entries_all, entry_save_many};
    use crate::server_fns::passkey::passkey_list;
    use crate::storage::envelope;

    /// Fetches everything the panel reports on.
    ///
    /// `entries_all` is only called for an encrypted account, and only
    /// because there is no server-side answer to "how many rows are still
    /// plaintext": producing one would mean the server parsing bodies,
    /// which invariant E1 forbids (see `dto::EncryptionStatus`).
    pub async fn load_overview(encrypted: bool) -> Result<Overview, String> {
        let rows = passkey_list().await.map_err(flow::server_unreachable)?;
        let wraps = if encrypted {
            encryption_wraps().await.map_err(flow::server_unreachable)?
        } else {
            Vec::new()
        };
        let scan = if encrypted {
            migration_scan(entries_all().await.map_err(flow::server_unreachable)?)
        } else {
            MigrationScan::default()
        };

        Ok(Overview {
            routes: rows.into_iter().map(|row| classify(row, &wraps)).collect(),
            has_recovery_wrap: choose_route(&wraps, None).is_some(),
            unencrypted_days: scan.pending.len(),
            unreadable_days: scan.unreadable.len(),
        })
    }

    /// Turns encryption on (spec section 6.1), returning the unlocked key
    /// and the recovery code to show once.
    ///
    /// `crypto::enable` has already written this device's keystore record by
    /// the time `encryption_enable` is called — see its own doc for why that
    /// inversion is the safe direction. If the server call fails, that
    /// record is inert: the next probe asks the server, is told the account
    /// is not encrypted, and lands on `Disabled`.
    ///
    /// The failure worth spelling out is the *lost response*, the same shape
    /// `flow::reissue`'s retry exists for and the one case a retry cannot
    /// fix: if the transaction commits and the reply never arrives, the
    /// account is encrypted under a recovery code the user was never shown.
    /// It is recoverable — this device still holds the key, so the manage
    /// view can mint a replacement — but only by somebody who knows to. So
    /// the error says so, rather than reporting a generic failure for an
    /// operation that may well have succeeded.
    pub async fn enable_encryption(user: &str) -> Result<(SessionKey, String), String> {
        let PrfAssertion {
            credential_id,
            prf_output,
        } = flow::assert_with_prf(user)
            .await
            .map_err(flow::assertion_message)?;

        let enabled = enable(&prf_output, user)
            .await
            .map_err(|_| "This browser couldn't generate an encryption key.".to_string())?;

        encryption_enable(enabled.passkey_wrap, credential_id, enabled.recovery_wrap)
            .await
            .map_err(|err| {
                format!(
                    "{} If encryption now shows as on for this account, generate a new \
                     recovery code below straight away — the code from this attempt was \
                     never shown to you.",
                    crate::webauthn_browser::friendly_error(err.to_string())
                )
            })?;

        Ok((enabled.session_key, enabled.recovery_code))
    }

    /// Spec section 6.4's re-issue, opened with a passkey rather than the
    /// old code.
    ///
    /// Works from a locked device as well as an unlocked one: the ceremony
    /// needs an opener either way, and an unlocked session has no shortcut
    /// to offer (invariant E5).
    pub async fn reissue_with_passkey(user: &str) -> Result<String, String> {
        let wraps = encryption_wraps().await.map_err(flow::server_unreachable)?;
        let assertion = flow::assert_with_prf(user)
            .await
            .map_err(flow::assertion_message)?;
        let route = choose_route(&wraps, Some(&assertion.credential_id)).ok_or_else(|| {
            "That passkey can't open this account's entries, so it can't issue a new recovery \
             code either. Choose one that can."
                .to_string()
        })?;

        flow::reissue(&Opener::Passkey {
            prf_output: &assertion.prf_output,
            wrap: &route.wrapped_key,
        })
        .await
    }

    /// Re-encrypts every row still stored as v1, in one transaction (spec
    /// section 8).
    ///
    /// Resumable by construction: a run that never reaches `entry_save_many`
    /// changes nothing, and a run that does leaves fewer v1 rows for the
    /// next one to find. Rows this build cannot read at all are not sent —
    /// they are counted and reported by the overview instead, because
    /// guessing at one would destroy it.
    pub async fn migrate(key: &SessionKey) -> Result<usize, String> {
        let rows = entries_all().await.map_err(flow::server_unreachable)?;
        let scan = migration_scan(rows);
        if scan.pending.is_empty() {
            return Ok(0);
        }

        let mut sealed = Vec::with_capacity(scan.pending.len());
        for (date, body) in scan.pending {
            let wrapped = envelope::wrap(&body, Some(key)).await.map_err(|_| {
                format!("Couldn't encrypt the entry for {date}; nothing was saved.")
            })?;
            sealed.push((date, wrapped));
        }

        let count = sealed.len();
        entry_save_many(sealed)
            .await
            .map_err(flow::server_unreachable)?;
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::wire::{self, WrapKind};
    use crate::storage::envelope::wrap_v1;

    fn passkey(name: &str, credential_id: &[u8], prf_capable: bool) -> PasskeyListItem {
        PasskeyListItem {
            id: 1,
            name: name.to_string(),
            added: "Sep 5, 2026".to_string(),
            last_used: None,
            credential_id: credential_id.to_vec(),
            prf_capable,
        }
    }

    fn passkey_wrap(credential_id: &[u8]) -> WrapDto {
        WrapDto {
            kind: WrapKind::Passkey.as_str().to_string(),
            credential_id: Some(credential_id.to_vec()),
            wrapped_key: vec![7; wire::WRAPPED_KEY_LEN],
            kdf: wire::KDF_HKDF_SHA256.to_string(),
            wrap_alg: wire::WRAP_ALG_AESKW256.to_string(),
        }
    }

    /// The three answers, and the reason all three exist. A passkey with a
    /// wrap opens the account; one without a wrap has either a gap or a
    /// dead end, and only `prf_capable` tells those apart.
    #[test]
    fn a_passkey_is_classified_by_its_wrap_then_its_capability() {
        let wraps = vec![passkey_wrap(b"cred-a")];
        assert_eq!(
            classify(passkey("A", b"cred-a", true), &wraps).status,
            RouteStatus::CanUnlock
        );
        assert_eq!(
            classify(passkey("B", b"cred-b", true), &wraps).status,
            RouteStatus::NoKeyYet
        );
        assert_eq!(
            classify(passkey("C", b"cred-c", false), &wraps).status,
            RouteStatus::NeverCapable
        );
    }

    /// A credential that reported PRF support but whose wrap this build
    /// cannot use must read as "no unlock key", not as a working route. The
    /// alternative is a row labelled "Can unlock" that fails at the unwrap
    /// with an error indistinguishable from a corrupt one.
    #[test]
    fn a_wrap_this_build_cannot_use_is_not_an_unlock_route() {
        let mut wraps = vec![passkey_wrap(b"cred-a")];
        wraps[0].kdf = "future-kdf".to_string();
        assert_eq!(
            classify(passkey("A", b"cred-a", true), &wraps).status,
            RouteStatus::NoKeyYet
        );
    }

    /// The gate on the enable button. An account whose only passkeys are
    /// PRF-incapable cannot complete the ceremony — the assertion returns no
    /// key material — so offering it would end in a failure the user could
    /// not act on.
    #[test]
    fn an_account_with_no_capable_passkey_cannot_enable() {
        let none = Overview::default();
        assert!(!none.has_capable_passkey(), "no passkeys at all");

        let incapable = Overview {
            routes: vec![classify(passkey("C", b"cred-c", false), &[])],
            ..Overview::default()
        };
        assert!(!incapable.has_capable_passkey());

        let capable = Overview {
            routes: vec![classify(passkey("B", b"cred-b", true), &[])],
            ..Overview::default()
        };
        assert!(capable.has_capable_passkey());
    }

    /// The count the panel reports, and the selection the migration acts on.
    /// A v2 row re-sent through the pass would be decrypted and re-sealed
    /// for nothing, and a bug in that path destroys data — so "already
    /// encrypted" must be excluded, not merely harmless.
    #[test]
    fn only_plaintext_rows_are_pending() {
        let sealed = wire::encode_v2(&wire::Sealed {
            nonce: vec![0; wire::NONCE_LEN],
            ciphertext: vec![1, 2, 3],
        });
        let scan = migration_scan(vec![
            ("2026-09-01".to_string(), wrap_v1("morning")),
            ("2026-09-02".to_string(), sealed),
            ("2026-09-03".to_string(), wrap_v1("")),
        ]);

        assert_eq!(
            scan.pending,
            vec![
                ("2026-09-01".to_string(), "morning".to_string()),
                // An empty body is a real saved state, not an absence, and
                // leaving it as the account's one v1 row would keep the
                // panel reporting unfinished work forever.
                ("2026-09-03".to_string(), String::new()),
            ]
        );
        assert!(scan.unreadable.is_empty());
    }

    /// A row nobody can interpret is named, not dropped. Silently skipping
    /// it would leave it plaintext forever with nothing to say so — the one
    /// outcome a one-shot migration cannot recover from on a later run.
    #[test]
    fn an_unreadable_row_is_reported_rather_than_skipped() {
        let scan = migration_scan(vec![
            ("2026-09-01".to_string(), "not an envelope".to_string()),
            (
                "2026-09-02".to_string(),
                r#"{"v":9,"alg":"future"}"#.to_string(),
            ),
            ("2026-09-03".to_string(), wrap_v1("real")),
        ]);

        assert_eq!(
            scan.unreadable,
            vec!["2026-09-01".to_string(), "2026-09-02".to_string()]
        );
        assert_eq!(scan.pending.len(), 1);
    }

    /// Resumability at the boundary: an account with nothing left to do
    /// reports nothing to do, so the panel stops offering a pass that would
    /// re-write every row for no reason.
    #[test]
    fn an_account_with_no_plaintext_rows_needs_no_work() {
        assert_eq!(migration_scan(Vec::new()), MigrationScan::default());

        let sealed = wire::encode_v2(&wire::Sealed {
            nonce: vec![0; wire::NONCE_LEN],
            ciphertext: vec![4],
        });
        let scan = migration_scan(vec![("2026-09-01".to_string(), sealed)]);
        assert_eq!(scan, MigrationScan::default());
    }

    /// Renders the whole panel the way the server would, with the context
    /// parked at `state` — the only way to reach anything but `Unknown` on
    /// the host, since the probe that moves it is `hydrate`-only.
    ///
    /// The panel's own fetch never runs here (it lives in an `Effect`, which
    /// SSR does not fire), so `overview` stays `None` throughout. That is
    /// the point for the `Unknown` case and a limit for the others, which is
    /// why the sections below are also rendered directly with an overview
    /// supplied.
    #[cfg(feature = "ssr")]
    fn render_panel(state: EncryptionState) -> String {
        let runtime = Owner::new();
        let html = runtime.with(move || {
            provide_context(AuthCtx {
                user: RwSignal::new(Some("alice@example.com".to_string())),
            });
            provide_context(EncryptionCtx::for_state(state));
            view! { <EncryptionPanel reload=RwSignal::new(0)/> }.to_html()
        });
        runtime.cleanup();
        html
    }

    #[cfg(feature = "ssr")]
    fn render_enable(overview: Overview) -> String {
        let runtime = Owner::new();
        let html = runtime.with(move || {
            view! {
                <EnableSection
                    overview=RwSignal::new(Some(overview))
                    understood=RwSignal::new(false)
                    busy=RwSignal::new(false)
                    on_enable=|| {}
                />
            }
            .to_html()
        });
        runtime.cleanup();
        html
    }

    #[cfg(feature = "ssr")]
    fn render_manage(unlocked: bool, overview: Overview) -> String {
        let runtime = Owner::new();
        let html = runtime.with(move || {
            view! {
                <ManageSection
                    unlocked=unlocked
                    overview=RwSignal::new(Some(overview))
                    busy=RwSignal::new(false)
                    on_lock=|| {}
                    on_reissue=|| {}
                    on_migrate=|| {}
                    on_give_key=|_| {}
                />
            }
            .to_html()
        });
        runtime.cleanup();
        html
    }

    /// The screen the whole recovery story depends on. If `code` ever
    /// stopped reaching the page the ceremony would still "succeed" — the
    /// wrap is already stored — and the user would be left with a recovery
    /// route whose secret nobody ever saw. Silent, total, and only
    /// discovered when it was needed.
    #[cfg(feature = "ssr")]
    #[test]
    fn the_recovery_code_is_shown_with_a_copy_control_and_a_confirmation() {
        let runtime = Owner::new();
        let html = runtime.with(|| {
            view! {
                <RecoveryCodeCard
                    code="K7M2-9XQR-4TVB-8HJN-3PWD-6ZFG-2SCY-5NKA".to_string()
                    heading="Save your recovery code"
                    intro="Shown once."
                    confirm="I've saved it"
                    on_confirm=|| {}
                />
            }
            .to_html()
        });
        runtime.cleanup();

        assert!(html.contains("K7M2-9XQR-4TVB-8HJN-3PWD-6ZFG-2SCY-5NKA"));
        assert!(html.contains(">Copy</button>"));
        assert!(
            html.contains("saved it</button>"),
            "closing must take an explicit confirmation, not a plain dismiss"
        );
    }

    /// Invariant E2 on this page. The server holds the session and could
    /// read `encrypted_at` cheaply, but rendering any conclusion from it
    /// puts user-derived state in the SSR body — and the browser cannot tell
    /// locked from unlocked without an async IndexedDB read anyway, so the
    /// first client render would differ regardless.
    #[cfg(feature = "ssr")]
    #[test]
    fn ssr_renders_no_conclusion_about_encryption() {
        let html = render_panel(EncryptionState::Unknown);
        assert!(
            html.contains("Checking this account"),
            "the server must render the not-yet-known branch"
        );
        for leaked in [
            "There is no reset",
            "Encryption is on",
            "Turn on encryption",
        ] {
            assert!(
                !html.contains(leaked),
                "server rendered `{leaked}`, a conclusion it must not reach"
            );
        }
    }

    /// The words the whole feature rests on. A reader who skims this panel
    /// and comes away thinking a lost recovery code is an inconvenience has
    /// been misled, so the loss is stated as loss — and the second
    /// authenticator prompt, which would otherwise arrive as a surprise, is
    /// announced before the button is pressed.
    #[cfg(feature = "ssr")]
    #[test]
    fn the_enable_pitch_states_the_loss_and_the_prompts_plainly() {
        let html = render_panel(EncryptionState::Disabled);
        assert!(html.contains("There is no reset"));
        assert!(
            html.contains("gone forever"),
            "the loss must be stated as loss, not hedged"
        );
        assert!(
            html.contains("has to answer a fresh prompt"),
            "the second authenticator prompt must be announced before it happens"
        );
        assert!(
            html.contains("three passkey prompts"),
            "the cost of adding a passkey later must be set up front"
        );
    }

    /// The gate, in the state the server renders: nothing is known about the
    /// account's passkeys yet, and "not known" must hold the ceremony shut
    /// rather than start one that would fail at its first assertion.
    ///
    /// It must not yet *claim* there is no usable passkey either — that
    /// sentence is only true once the list has arrived, and rendering it
    /// here would flash a false alarm on every visit.
    #[cfg(feature = "ssr")]
    #[test]
    fn enabling_is_shut_until_the_account_is_known() {
        let html = render_panel(EncryptionState::Disabled);
        assert!(
            html.contains(r#"<button type="button" disabled"#),
            "the enable button must render disabled: {html}"
        );
        assert!(
            !html.contains("Encryption needs a passkey"),
            "an unknown passkey list must not read as a missing one"
        );
    }

    /// And once the list *is* in and holds nothing usable, the panel says so
    /// rather than presenting a dead control with no explanation. The
    /// ceremony would fail at its first assertion, and "the button does
    /// nothing" is the least useful way to learn that.
    #[cfg(feature = "ssr")]
    #[test]
    fn an_account_with_no_usable_passkey_is_told_why_it_cannot_enable() {
        let html = render_enable(Overview {
            routes: vec![classify(passkey("Old token", b"cred-c", false), &[])],
            ..Overview::default()
        });
        assert!(html.contains(r#"<button type="button" disabled"#));
        assert!(html.contains("Encryption needs a passkey that can hold a key"));

        let usable = render_enable(Overview {
            routes: vec![classify(passkey("Phone", b"cred-b", true), &[])],
            ..Overview::default()
        });
        assert!(
            !usable.contains("Encryption needs a passkey"),
            "an account that can enable must not be told it cannot"
        );
    }

    /// A locked device is told what it is and offered nothing it cannot do —
    /// "Lock now" on an already-locked device would be a control with no
    /// effect.
    #[cfg(feature = "ssr")]
    #[test]
    fn a_locked_device_says_so_and_offers_no_lock() {
        let html = render_panel(EncryptionState::Locked);
        assert!(html.contains("Encryption is on"));
        assert!(html.contains("This device is locked"));
        assert!(!html.contains("Lock now"));
    }

    /// Spec section 6.5's requirement, at the view: a passkey that cannot
    /// unlock is **labelled**, never dropped from the list. Hiding it would
    /// let somebody count three passkeys, lose two, and discover only then
    /// that the third never opened anything.
    ///
    /// The repair control is asserted by count, not presence: offering it on
    /// the row whose authenticator can never produce a key would send the
    /// user through two authenticator prompts to reach a failure.
    #[cfg(feature = "ssr")]
    #[test]
    fn a_passkey_that_cannot_unlock_is_labelled_not_hidden() {
        let wraps = vec![passkey_wrap(b"cred-a")];
        let html = render_manage(
            true,
            Overview {
                routes: vec![
                    classify(passkey("Work laptop", b"cred-a", true), &wraps),
                    classify(passkey("Phone", b"cred-b", true), &wraps),
                    classify(passkey("Old token", b"cred-c", false), &wraps),
                ],
                has_recovery_wrap: true,
                ..Overview::default()
            },
        );

        for name in ["Work laptop", "Phone", "Old token"] {
            assert!(html.contains(name), "`{name}` was hidden from the list");
        }
        assert!(
            html.contains("will never open your entries"),
            "a PRF-incapable passkey must say so on its own row"
        );
        assert_eq!(
            html.matches("Give it an unlock key").count(),
            1,
            "only the fixable row may offer the repair"
        );
    }

    /// The resume control from spec section 8, and the one thing it depends
    /// on: sealing needs the key, so a locked device is told what to do
    /// rather than handed a button that cannot work. The count itself shows
    /// either way — it is the answer to "is my data actually encrypted
    /// yet", which a locked visitor may well be asking.
    #[cfg(feature = "ssr")]
    #[test]
    fn an_unfinished_migration_offers_a_resume_only_where_it_can_run() {
        let pending = Overview {
            has_recovery_wrap: true,
            unencrypted_days: 3,
            ..Overview::default()
        };

        let unlocked = render_manage(true, pending.clone());
        assert!(unlocked.contains("3 days still stored unencrypted"));
        assert!(unlocked.contains("Finish encrypting"));

        let locked = render_manage(false, pending);
        assert!(locked.contains("3 days still stored unencrypted"));
        assert!(
            !locked.contains("Finish encrypting"),
            "a locked device cannot seal anything and must not be offered the pass"
        );
        assert!(locked.contains("Unlock this device to finish"));
    }

    /// A finished account is not nagged: no count, no resume control, and no
    /// unreadable-row warning where there are none.
    #[cfg(feature = "ssr")]
    #[test]
    fn a_finished_account_is_offered_no_migration() {
        let html = render_manage(
            true,
            Overview {
                has_recovery_wrap: true,
                ..Overview::default()
            },
        );
        assert!(!html.contains("still stored unencrypted"));
        assert!(!html.contains("Finish encrypting"));
        assert!(!html.contains("could not be read"));
    }
}
