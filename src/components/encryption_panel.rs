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
//! 1. **Enabling asks for a passkey again** — on the route that uses one.
//!    Creating a credential reports only *whether* PRF is available, never
//!    the output, so the key material has to come from a fresh assertion
//!    (spec section 6.1 step 1). An account whose authenticators cannot
//!    produce a PRF output at all takes the other route, where the recovery
//!    code is the only wrap and no passkey is asked for — see [`EnableRoute`],
//!    whose two sets of words are the difference between "you have a backup"
//!    and "this code is the account".
//! 2. **Adding a passkey costs three authenticator interactions** — create
//!    it, assert against a credential that can already unlock to re-derive
//!    the raw key, assert against the new one for its PRF output. An
//!    unlocked session does not save one of them: what it holds is a
//!    *sealed* key, which by construction cannot yield its bytes (spec
//!    section 6.5, invariant E5). The recovery code can stand in for the
//!    middle one, which is the only thing that works on an account whose
//!    passkeys are all gone — see [`Openers`].
//! 3. **The recovery code is shown once.** `reissue_recovery` mints a *new*
//!    one; nothing anywhere can reproduce the old.
//!
//! The panel reads [`EncryptionCtx`] for the account's state and never
//! probes on its own, so on the server it renders the "checking" branch for
//! everybody (invariant E2) and hydrates against itself.

use leptos::prelude::*;

use crate::auth_ctx::AuthCtx;
use crate::clipboard::copy_to_clipboard;
use crate::components::status::Status;
use crate::crypto::KeySource;
use crate::encryption_ctx::{EncryptionCtx, EncryptionState};

use leptos::either::{Either, EitherOf3, EitherOf7};

#[cfg(any(feature = "hydrate", test))]
use crate::crypto::choose_route;
#[cfg(any(feature = "hydrate", test))]
use crate::dto::{PasskeyListItem, WrapDto};

#[cfg(feature = "hydrate")]
use leptos::task::spawn_local;

#[cfg(feature = "hydrate")]
use crate::storage::Generation;
#[cfg(feature = "hydrate")]
use ceremony::PendingEnable;

/// What the account's encryption state means for this panel, with the key
/// itself dropped.
///
/// A `Copy + PartialEq` reduction of [`EncryptionState`] so the load effect
/// below can hang off a `Memo` and re-run when the *situation* changes
/// rather than on every republish of the same one. It also keeps
/// [`SessionKey`](crate::crypto::SessionKey) — which is neither `Send` nor
/// `Sync`, and uninhabited off the browser — out of the panel's branching
/// entirely; the one place that needs the key reads it back out of the
/// context at the moment it acts.
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

/// Everything the panel fetches about the account in one go.
#[derive(Clone, Default)]
#[cfg_attr(not(feature = "hydrate"), allow(dead_code))]
struct Overview {
    routes: Vec<PasskeyRoute>,
    /// Whether a recovery wrap this build can open is on file.
    has_recovery_wrap: bool,
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

/// What the panel knows about the account beyond its phase.
///
/// Three states rather than `Option<Overview>`, because the fetch has two
/// ways of not producing one and only one of them is a spinner. The failure
/// used to be written into `status` — the line every ceremony writes — which
/// gave that line two writers, and they raced: a refresh failing mid-ceremony
/// painted over what the ceremony was saying, and the ceremony's next line
/// painted over the failure. Keeping the fetch's own answer here leaves
/// `status` with exactly one writer.
#[derive(Clone, Default)]
#[cfg_attr(not(feature = "hydrate"), allow(dead_code))]
enum Fetched {
    /// Not answered yet — which is everything the server renders, since it
    /// never asks.
    #[default]
    Pending,
    Loaded(Overview),
    /// The fetch failed, with the sentence to show for it.
    Failed(String),
}

impl Fetched {
    /// The account's routes, once they have arrived.
    ///
    /// `Pending` and `Failed` collapse here on purpose: neither knows
    /// anything about the account's passkeys, and every control that reads
    /// this has to stay shut for both. What tells them apart is the line the
    /// panel renders from `Failed`, which is where that difference belongs.
    fn loaded(self) -> Option<Overview> {
        match self {
            Fetched::Loaded(overview) => Some(overview),
            Fetched::Pending | Fetched::Failed(_) => None,
        }
    }
}

/// Which of the account's secrets can open its data key right now, and so
/// which of them can pass a copy on to a newly enrolled passkey.
///
/// Four answers rather than two booleans, because each is a different
/// situation to be in and the panel offers different controls for each.
/// `RecoveryOnly` is the one that earns the type: it is where an account
/// lands when every passkey is lost and the recovery code gets the user back
/// in — which is precisely when they enrol a replacement. A ceremony that
/// only ever asked another passkey would find none, and the account would
/// stay recovery-code-only on every device, permanently. The code exists to
/// get somebody back in, not to cost them the way back (spec section 6.5).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Openers {
    /// No enrolled passkey holds a wrap and no recovery wrap is on file.
    /// Nothing can open this account's entries, so nothing can key a new
    /// passkey either.
    Nothing,
    /// Only the recovery code: every passkey here is keyless or incapable.
    RecoveryOnly,
    /// Only a passkey — an account with no recovery wrap, or one this build
    /// cannot use.
    PasskeyOnly,
    /// Either, which is where a healthy encrypted account sits.
    Either,
}

impl Openers {
    fn of(overview: &Overview) -> Self {
        let passkey = overview
            .routes
            .iter()
            .any(|route| route.status == RouteStatus::CanUnlock);
        match (passkey, overview.has_recovery_wrap) {
            (true, true) => Openers::Either,
            (true, false) => Openers::PasskeyOnly,
            (false, true) => Openers::RecoveryOnly,
            (false, false) => Openers::Nothing,
        }
    }

    /// Whether a passkey assertion is worth offering as the opener.
    fn passkey(self) -> bool {
        matches!(self, Openers::PasskeyOnly | Openers::Either)
    }

    /// Whether the recovery code is worth offering as the opener.
    fn recovery(self) -> bool {
        matches!(self, Openers::RecoveryOnly | Openers::Either)
    }
}

/// Which of spec section 6.1's two routes to encryption an account can take.
///
/// The account's own capability decides it, not a preference: the PRF
/// extension is a property of the browser and the authenticator, and one
/// that does not implement it never will on the credentials already
/// enrolled. So an account with no capable passkey is not being offered a
/// weaker option alongside a stronger one — the stronger one does not exist
/// for it, and the real alternative is entries stored in the clear.
///
/// The routes cost different things and the panel must not blur them. Two
/// wraps means losing every passkey *and* the code is fatal; one wrap means
/// losing the code is fatal on its own. A user who reads the two-wrap
/// sentence and ends up with a one-wrap account has been told they have
/// slack they do not have, which is why the words hang off this value rather
/// than off the section that renders them.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum EnableRoute {
    /// The data key is wrapped under a PRF-capable passkey *and* under the
    /// recovery code. What most accounts get.
    PasskeyAndRecovery,
    /// The data key is wrapped under the recovery code alone, because no
    /// enrolled passkey can hold one.
    RecoveryOnly,
}

impl EnableRoute {
    fn of(overview: &Overview) -> Self {
        if overview.has_capable_passkey() {
            EnableRoute::PasskeyAndRecovery
        } else {
            EnableRoute::RecoveryOnly
        }
    }

    fn words(self) -> EnableWords {
        match self {
            EnableRoute::PasskeyAndRecovery => PASSKEY_AND_RECOVERY_WORDS,
            EnableRoute::RecoveryOnly => RECOVERY_ONLY_WORDS,
        }
    }
}

/// The words one [`EnableRoute`] wears.
///
/// Every sentence that differs between the routes lives here, for the reason
/// [`OpenerWords`] gives one screen further on: a card built from the other
/// route's words would still render, and the sentence it got wrong is the
/// one telling the user how much room for error they have.
#[derive(Clone, Copy)]
struct EnableWords {
    /// Why this route and not the ordinary one. `None` where no explanation
    /// is owed.
    why: Option<&'static str>,
    /// The red block's first line.
    warning_heading: &'static str,
    /// The red block itself: what is lost, and what nobody can do about it.
    warning: &'static str,
    /// What the ceremony asks for first.
    first_step: &'static str,
    /// What the recovery code is, in the list of what happens.
    code_step: &'static str,
    /// What enrolling another passkey costs afterwards.
    later_passkey: &'static str,
    /// The sentence beside the checkbox that gates the button.
    acknowledgement: &'static str,
    /// The button that starts the ceremony.
    button: &'static str,
}

const PASSKEY_AND_RECOVERY_WORDS: EnableWords = EnableWords {
    why: None,
    warning_heading: "There is no reset.",
    warning: "If you lose every passkey and your recovery code, your entries are gone forever \
              — for you and for whoever runs this server. Nobody can unlock them, because \
              nobody else ever has the key. This is not a password that can be reissued.",
    first_step: "Your browser asks for a passkey. Creating a passkey doesn't hand back the key \
                 material this needs, so even one you added a moment ago has to answer a fresh \
                 prompt.",
    code_step: "You're shown a recovery code, once, before encryption is switched on. Save it \
                before you go on — it is never shown again.",
    later_passkey: "Adding another passkey afterwards takes three passkey prompts, unless you \
                    use your recovery code in place of one of them. That's a consequence of the \
                    key never leaving your authenticator in a copyable form, not a bug to be \
                    fixed later.",
    acknowledgement: "I understand that losing every passkey and my recovery code means losing \
                      my entries for good.",
    button: "Turn on encryption",
};

/// Deliberately not a softened copy of the words above. The two-wrap warning
/// describes a loss that takes two mistakes; this one takes one.
const RECOVERY_ONLY_WORDS: EnableWords = EnableWords {
    why: Some(
        "None of your passkeys can hold an encryption key — their authenticators don't support \
         the extension the key is derived from, and that isn't something a setting turns on. \
         You can still encrypt your entries, with a recovery code as the key.",
    ),
    warning_heading: "Your recovery code will be the only key.",
    warning: "Not a backup — the key itself. No passkey on this account can hold a copy, so \
              there is no second way in and nothing to fall back on. Lose the code and your \
              entries are gone forever, for you and for whoever runs this server. Nobody can \
              unlock them, because nobody else ever has the key. This is not a password that \
              can be reissued.",
    first_step: "Your browser generates the key. There is no passkey prompt on this route — \
                 which is exactly why the code has to carry the whole account.",
    code_step: "You're shown the recovery code, once, before encryption is switched on. Store \
                it somewhere you would trust with the entries themselves, because that is what \
                it is worth. It is never shown again.",
    later_passkey: "If you ever enrol a passkey that can hold a key, you can give it one from \
                    this panel using the recovery code. Until then the code stays the only \
                    thing that opens your entries.",
    acknowledgement: "I understand that my recovery code will be the only key to my entries, \
                      and that losing it loses them for good.",
    button: "Turn on encryption with a recovery code only",
};

/// Where the panel is in a flow it started itself.
///
/// Half of what decides the screen; [`Phase`] is the other half, and
/// [`Screen::of`] says which wins.
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
    /// The code minted by the enable ceremony, held while the server still
    /// knows nothing. Confirming it is what turns encryption on: the server
    /// call, and then the key into this device's keystore.
    ///
    /// The route travels with the code because the card's words depend on
    /// it, and by then the overview it was chosen from is no longer what the
    /// screen is reading. A code minted on the recovery-only route and
    /// described as a passkey's backup would be the one lie this panel
    /// cannot afford.
    NewCode { code: String, route: EnableRoute },
    /// A re-issued code. Confirming it just closes.
    ReissuedCode(String),
    /// One keyless passkey, and the choice of which secret will open the
    /// data key to give it one.
    GiveKey {
        credential_id: Vec<u8>,
        /// Carried so the card can name the passkey it is about to key. The
        /// list it came from is a fetch away and may re-order underneath
        /// this screen.
        name: String,
    },
    /// The choice of which secret will open the data key to wrap it under a
    /// freshly minted recovery code.
    ///
    /// A screen rather than a straight-to-the-authenticator ceremony for the
    /// reason [`Openers`] exists: an account whose passkeys are all keyless
    /// has nothing for a passkey route to open, and that is exactly the
    /// account whose owner has just typed their recovery code somewhere and
    /// wants a new one.
    Reissue,
}

/// Which of the two code screens is up.
///
/// The heading, the sentence under it and the confirm label are the entire
/// difference between them, so they hang off the variant rather than off
/// two near-identical call sites. Pairing them removes the chance of a card
/// built with the other one's words: "your previous code no longer works"
/// over a code minted for an account that has never had one would be a lie,
/// and the enable card's label is what tells the user that pressing it is
/// the thing that turns encryption on.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum CodeKind {
    /// Minted by the enable ceremony, with the server not yet told. Carries
    /// the route because what this code *is* differs between them: a backup
    /// behind a passkey, or the account's only key.
    New(EnableRoute),
    /// Minted by a re-issue, replacing one that has stopped working.
    Reissued,
}

impl CodeKind {
    fn heading(self) -> &'static str {
        match self {
            CodeKind::New(_) => "Save your recovery code",
            CodeKind::Reissued => "Your new recovery code",
        }
    }

    fn intro(self) -> &'static str {
        match self {
            CodeKind::New(EnableRoute::PasskeyAndRecovery) => {
                "This is the only thing that opens your entries if you lose every passkey. It \
                 is shown once — leaving this page without it means generating a replacement \
                 from this panel while you still have a passkey that works."
            }
            // The last screen before the account becomes unrecoverable
            // without this string of characters, so it says so rather than
            // repeating the sentence above with "passkey" quietly removed.
            CodeKind::New(EnableRoute::RecoveryOnly) => {
                "This is not a backup — it is the key. No passkey on this account can hold a \
                 copy, so nothing else will ever open your entries. It is shown once. Save it \
                 before you press the button below; after that, losing it loses your entries."
            }
            CodeKind::Reissued => {
                "Your previous code no longer works. This one is shown once and never again."
            }
        }
    }

    fn confirm(self) -> &'static str {
        match self {
            CodeKind::New(_) => "I've saved it — finish turning on encryption",
            CodeKind::Reissued => "I've saved it",
        }
    }
}

/// What the panel is showing, once the flow it is running and the state of
/// the account have been reconciled.
///
/// The reconciliation is a value rather than a nested `match` in the view so
/// that the one thing it decides can be pinned by a test on the host. What
/// it decides is that a code on screen outranks the account's state, and
/// neither code-bearing mode lines up with a phase that would render it:
/// `NewCode` is shown while the account is still `Off`, because the server
/// is not told until the user confirms, and `ReissuedCode` while it is
/// `Unlocked`. If `Phase` won, each would be painted over by the section for
/// that phase — the enable pitch or the manage view — and the code would be
/// minted, stored as the account's only backup, and never seen. Nothing
/// would fail; the ceremony would report success. The same trap
/// `UnlockPrompt` documents, one ceremony further along.
#[derive(Clone, PartialEq, Eq, Debug)]
enum Screen {
    /// A recovery code, shown once.
    Code { code: String, kind: CodeKind },
    /// The probe has not answered. Everything the server renders.
    Checking,
    /// The probe failed and will not retry itself.
    Unreachable,
    /// The pitch, the warning and the gate.
    Enable,
    /// An encrypted account, from a device that may or may not hold the key.
    Manage { unlocked: bool },
    /// One passkey is being given an unlock key, and the account's openers
    /// are the choice on offer.
    GiveKey {
        credential_id: Vec<u8>,
        name: String,
    },
    /// A new recovery code is being minted, and the account's openers are
    /// the choice on offer.
    Reissue,
}

impl Screen {
    /// `phase` is a closure, not a value, so the caller's read of it happens
    /// only on the arm that uses it.
    ///
    /// This runs inside a reactive closure, and a phase read on an arm that
    /// ignores the answer still subscribes to it: any phase change would
    /// then rebuild the card on screen, and a rebuilt
    /// [`RecoveryCodeCard`] is a fresh `copied` flag — the "Copied."
    /// confirmation vanishing from beside a code the user may have copied
    /// but not yet saved. No shipped flow moves the phase while a code is
    /// up; this makes the card not depend on that staying true.
    fn of(mode: Mode, phase: impl FnOnce() -> Phase) -> Self {
        match mode {
            Mode::NewCode { code, route } => Screen::Code {
                code,
                kind: CodeKind::New(route),
            },
            Mode::ReissuedCode(code) => Screen::Code {
                code,
                kind: CodeKind::Reissued,
            },
            Mode::GiveKey {
                credential_id,
                name,
            } => Screen::GiveKey {
                credential_id,
                name,
            },
            Mode::Reissue => Screen::Reissue,
            Mode::Idle => match phase() {
                Phase::Checking => Screen::Checking,
                Phase::Unreachable => Screen::Unreachable,
                Phase::Off => Screen::Enable,
                Phase::Locked => Screen::Manage { unlocked: false },
                Phase::Unlocked => Screen::Manage { unlocked: true },
            },
        }
    }
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
    let overview = RwSignal::new(Fetched::default());

    let phase = Memo::new(move |_| Phase::of(&encryption.state()));

    // Bridges the enable ceremony's two clicks: everything computed before
    // the server hears about it waits here while the recovery code is on
    // screen. Nothing is encrypted until the second click, which is the
    // point — a lost response to `encryption_enable` then finds the user
    // already holding the code that went live with it.
    #[cfg(feature = "hydrate")]
    let pending_enable = StoredValue::<Option<PendingEnable>, LocalStorage>::new_local(None);

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
                overview.set(Fetched::Pending);
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
                overview.set(match loaded {
                    Ok(loaded) => Fetched::Loaded(loaded),
                    Err(message) => Fetched::Failed(message),
                });
            });
        });
    }

    // `route` is decided by the section that rendered the button, not
    // re-derived here: the words the user just read and the ceremony that
    // runs have to be the same choice, and two independent reads of the
    // overview could land either side of a refresh.
    let turn_on = move |route: EnableRoute| {
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
                let outcome = match route {
                    EnableRoute::PasskeyAndRecovery => ceremony::begin_enable(&user).await,
                    EnableRoute::RecoveryOnly => ceremony::begin_enable_recovery_only(&user).await,
                };
                busy.set(false);
                match outcome {
                    Ok(pending) => {
                        let code = pending.recovery_code().to_string();
                        pending_enable.set_value(Some(pending));
                        mode.set(Mode::NewCode { code, route });
                    }
                    Err(message) => status.set(Some(Status::Problem(message))),
                }
            });
        }
        #[cfg(not(feature = "hydrate"))]
        let _ = route;
    };

    // Spec section 6.1's step 4, reached only once the user has said they
    // have the code step 5 showed them. Running the server call here rather
    // than before the code screen is what makes a lost response survivable:
    // whichever way it went, the code in the user's hands is the account's.
    //
    // The key is published on the same answer that turns the account on, so
    // there is no stretch of time in which the server considers the account
    // encrypted while `EncryptionCtx` still says `Disabled` — which is
    // `WriteKey::Plaintext`, and so a v1 row written into an encrypted
    // account, the downgrade invariant E7 exists to prevent. Deferring the
    // publication to a later click would open exactly that window, and the
    // probe does not re-run on its own to close it.
    let confirm_new_code = move || {
        #[cfg(feature = "hydrate")]
        {
            // Taken, not read: a second click while the call is in flight
            // finds nothing and does nothing, rather than enabling twice.
            let Some(Some(pending)) = pending_enable.try_update_value(Option::take) else {
                return;
            };
            busy.set(true);
            status.set(Some(Status::Note("Turning on encryption…".to_string())));
            spawn_local(async move {
                let outcome = ceremony::commit_enable(pending).await;
                busy.set(false);
                // The code comes down only on an answer, either way. A
                // failed call leaves the pitch and the message rather than a
                // card whose button no longer does anything.
                mode.set(Mode::Idle);
                match outcome {
                    Ok(key) => {
                        status.set(None);
                        // `EncryptionCtx::unlock` refuses a key for an
                        // account that is no longer the signed-in one, so a
                        // sign-out during the code screen leaves the key
                        // neither published nor written to this device's
                        // keystore, rather than sealing the signed-out
                        // page's `localStorage` under it. Awaited because
                        // the keystore write lives behind that check.
                        encryption.unlock(key).await;
                    }
                    Err(message) => status.set(Some(Status::Problem(message))),
                }
            });
        }
    };

    // Shared by every card that can be closed without doing anything: the
    // re-issued code screen and the give-a-key screen both return to
    // whatever the account's state calls for.
    let close_card = move || {
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

    // Opens the choice of opener rather than starting a ceremony, for the
    // reason `ReissueCard` spells out: the passkey route is the wrong one —
    // and the only one — on the account most likely to want a new code.
    let start_reissue = move || {
        status.set(None);
        mode.set(Mode::Reissue);
    };

    let new_recovery_code = move |source: KeySource| {
        status.set(None);
        #[cfg(feature = "hydrate")]
        {
            let Some(user) = auth.user.get_untracked() else {
                return;
            };
            busy.set(true);
            spawn_local(async move {
                let outcome = crate::crypto::flow::reissue_with(&user, source).await;
                busy.set(false);
                match outcome {
                    Ok(code) => mode.set(Mode::ReissuedCode(code)),
                    // The card stays up, so a mistyped recovery code can be
                    // corrected without reopening it.
                    Err(message) => status.set(Some(Status::Problem(message))),
                }
            });
        }
        #[cfg(not(feature = "hydrate"))]
        let _ = source;
    };

    // Opens the choice of opener rather than starting a ceremony, because
    // there is more than one and the account may only have the second: see
    // `Openers`.
    let start_give_key = move |name: String, credential_id: Vec<u8>| {
        status.set(None);
        mode.set(Mode::GiveKey {
            credential_id,
            name,
        });
    };

    let give_key = move |credential_id: Vec<u8>, source: KeySource| {
        status.set(None);
        #[cfg(feature = "hydrate")]
        {
            let Some(user) = auth.user.get_untracked() else {
                return;
            };
            busy.set(true);
            spawn_local(async move {
                let outcome =
                    crate::crypto::flow::add_passkey_key(&user, &credential_id, source).await;
                busy.set(false);
                match outcome {
                    Ok(()) => {
                        mode.set(Mode::Idle);
                        status.set(Some(Status::Note(
                            "That passkey can now open your entries.".to_string(),
                        )));
                        reload.update(|n| *n += 1);
                    }
                    // The card stays up on a failure, so a mistyped recovery
                    // code can be corrected without walking back through the
                    // list to find the same row again.
                    Err(message) => status.set(Some(Status::Problem(message))),
                }
            });
        }
        #[cfg(not(feature = "hydrate"))]
        let _ = (credential_id, source);
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
                <p class=format!("{} mb-3", line.tone())>{line.message().to_string()}</p>
            })}
            <FetchProblem overview=overview/>
            {move || match Screen::of(mode.get(), move || phase.get()) {
                Screen::Code { code, kind } => EitherOf7::A(view! {
                    <RecoveryCodeCard
                        code=code
                        heading=kind.heading()
                        intro=kind.intro()
                        confirm=kind.confirm()
                        busy=busy
                        on_confirm=move || match kind {
                            CodeKind::New(_) => confirm_new_code(),
                            CodeKind::Reissued => close_card(),
                        }
                    />
                }),
                // What the server renders for everybody, and what the
                // browser renders until the probe lands (invariant E2).
                Screen::Checking => EitherOf7::B(view! {
                    <div>
                        <h2 class="text-lg font-semibold text-gray-800 mb-1">"Encryption"</h2>
                        <p class="text-sm text-gray-500">"Checking this account…"</p>
                    </div>
                }),
                Screen::Unreachable => EitherOf7::C(view! {
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
                Screen::Enable => EitherOf7::D(view! {
                    <EnableSection
                        overview=overview
                        understood=understood
                        busy=busy
                        on_enable=turn_on
                    />
                }),
                Screen::Manage { unlocked } => EitherOf7::E(view! {
                    <ManageSection
                        unlocked=unlocked
                        overview=overview
                        busy=busy
                        on_lock=lock_now
                        on_reissue=start_reissue
                        on_give_key=start_give_key
                    />
                }),
                Screen::GiveKey { credential_id, name } => EitherOf7::F(view! {
                    <GiveKeyCard
                        name=name
                        credential_id=credential_id
                        overview=overview
                        busy=busy
                        on_open=give_key
                        on_cancel=close_card
                    />
                }),
                Screen::Reissue => EitherOf7::G(view! {
                    <ReissueCard
                        overview=overview
                        busy=busy
                        on_open=new_recovery_code
                        on_cancel=close_card
                    />
                }),
            }}
        </div>
    }
}

/// The last refresh's own failure, if it had one.
///
/// Kept out of `status` so the ceremonies and the fetch cannot paint over
/// each other mid-ceremony — see [`Fetched`] — and a component rather than
/// an inline closure so a test can reach it: the signal behind it is
/// internal to [`EncryptionPanel`], and the fetch that would set it lives in
/// an `Effect`, which never runs on the host.
#[component]
fn FetchProblem(overview: RwSignal<Fetched>) -> impl IntoView {
    move || match overview.get() {
        Fetched::Failed(message) => {
            Some(view! { <p class="text-sm text-red-700 mb-3">{message}</p> })
        }
        Fetched::Pending | Fetched::Loaded(_) => None,
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
    /// Whether a ceremony is already in flight. Double-firing is already
    /// prevented synchronously — `confirm_new_code` *takes* the pending
    /// enable rather than reading it — so this is for consistency with every
    /// other control that starts a ceremony, and so a click during the
    /// server call looks like what it is.
    busy: RwSignal<bool>,
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
                class="w-full bg-blue-600 text-white text-sm font-semibold rounded py-2 hover:bg-blue-700 disabled:opacity-60"
                disabled=move || busy.get()
                on:click=move |_| on_confirm()
            >
                {confirm}
            </button>
        </div>
    }
}

/// The pitch, the warning, and the gate (spec section 6.1).
///
/// There is no third state here any more. An account with no PRF-capable
/// passkey used to get a dead control and a sentence telling it to go and
/// add one — advice with nowhere to go, since an authenticator that does not
/// implement the extension will not start, and the account it left behind
/// was a plaintext one. It now gets [`EnableRoute::RecoveryOnly`] and a
/// warning written for the loss that route actually carries.
#[component]
fn EnableSection(
    overview: RwSignal<Fetched>,
    understood: RwSignal<bool>,
    busy: RwSignal<bool>,
    on_enable: impl Fn(EnableRoute) + Copy + Send + 'static,
) -> impl IntoView {
    // `None` until the passkey list lands, and that is what holds the button
    // shut: starting a ceremony before the account's capability is known
    // would pick a route by guess, and the two are not interchangeable.
    let route_of = |fetched: Fetched| fetched.loaded().map(|it| EnableRoute::of(&it));
    let route = move || route_of(overview.get());
    // The words shown while nothing is known are the ordinary route's,
    // because most accounts take it and a panel that says nothing at all
    // until a fetch lands would render blank on the server too (invariant
    // E2's `Checking` branch is a different screen entirely). Nothing can be
    // started under them: the gate above is what the button reads.
    let words = move || route().unwrap_or(EnableRoute::PasskeyAndRecovery).words();

    view! {
        <div>
            <h2 class="text-lg font-semibold text-gray-800 mb-1">"Encrypt your entries"</h2>
            <p class="text-sm text-gray-600 mb-4">
                "Right now this account's entries are stored on the server as plain text: \
                 anyone who can read the database — including whoever runs this server — can \
                 read them. Turning encryption on locks them to a key that only your browser \
                 ever holds."
            </p>

            {move || words().why.map(|why| view! {
                <p class="text-sm text-amber-800 bg-amber-50 border border-amber-200 rounded p-3 mb-4">
                    {why}
                </p>
            })}

            <div class="rounded border border-red-200 bg-red-50 p-3 mb-4">
                <p class="text-sm font-semibold text-red-900 mb-1">
                    {move || words().warning_heading}
                </p>
                <p class="text-sm text-red-900">{move || words().warning}</p>
            </div>

            <p class="text-sm font-medium text-gray-800 mb-1">"What happens when you turn it on"</p>
            <ul class="list-disc pl-5 text-sm text-gray-600 mb-4 space-y-1">
                <li>{move || words().first_step}</li>
                <li>{move || words().code_step}</li>
                <li>{move || words().later_passkey}</li>
            </ul>

            <label class="flex items-start gap-2 text-sm text-gray-700 mb-4">
                <input
                    type="checkbox"
                    class="mt-0.5"
                    prop:checked=move || understood.get()
                    on:change=move |ev| understood.set(event_target_checked(&ev))
                />
                <span>{move || words().acknowledgement}</span>
            </label>

            <button
                type="button"
                class="bg-blue-600 text-white text-sm font-semibold rounded px-4 py-2 hover:bg-blue-700 disabled:opacity-60"
                disabled=move || busy.get() || !understood.get() || route().is_none()
                on:click=move |_| {
                    if let Some(route) = route_of(overview.get_untracked()) {
                        on_enable(route);
                    }
                }
            >
                {move || words().button}
            </button>
        </div>
    }
}

/// The panel for an account that is already encrypted (spec sections 6.5,
/// 6.6 and 6.7).
#[component]
fn ManageSection(
    unlocked: bool,
    overview: RwSignal<Fetched>,
    busy: RwSignal<bool>,
    on_lock: impl Fn() + Copy + Send + 'static,
    on_reissue: impl Fn() + Copy + Send + 'static,
    on_give_key: impl Fn(String, Vec<u8>) + Copy + Send + 'static,
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
            {move || match overview.get().loaded() {
                None => Either::Left(view! { <p class="text-sm text-gray-500">"Loading…"</p> }),
                Some(overview) => Either::Right(view! {
                    <div>
                        // Answers the heading before the list qualifies it. A
                        // list where every row says "won't open your entries" —
                        // or no rows at all — is the ordinary screen for an
                        // account enabled by the recovery-only route, and a
                        // heading followed by nothing but bad news reads as a
                        // failure to load rather than as the truth.
                        //
                        // Conditioned on the recovery wrap so it cannot appear
                        // beside the red warning below, which is the same account
                        // one step worse off and the more urgent thing to read.
                        // Written above the list because the list *consumes*
                        // `routes`, and this has to read them.
                        {(overview.has_recovery_wrap
                            && !overview.routes.iter().any(|r| r.status == RouteStatus::CanUnlock))
                            .then(|| view! {
                                <p class="text-sm text-gray-700 bg-gray-50 border border-gray-200 rounded p-3 mb-2">
                                    "Your recovery code is the only thing that opens your \
                                     entries right now. If you enrol a passkey whose \
                                     authenticator can hold a key, you can give it one from \
                                     here using that code."
                                </p>
                            })}
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
                    </div>
                }),
            }}

            <p class="text-xs text-gray-500 mt-3">
                "Adding a passkey to an encrypted account takes three passkey prompts: one to \
                 create it, one against a passkey that can already unlock, and one against the \
                 new one. An unlocked session doesn't save a prompt — the key it holds is \
                 sealed and can't be copied out. Your recovery code can take the place of the \
                 middle prompt, which is what to use if none of your passkeys can unlock."
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
                    "Opens with a passkey or with the code you have now, then shows a new code \
                     once. Your current code stops working as soon as the new one is stored."
                </p>
            </div>
        </div>
    }
}

/// The words one [`OpenerChoice`] wears.
///
/// A value rather than six props, so the two cards that share the control
/// cannot come to share a sentence that is only true for one of them: the
/// give-a-key route costs an authenticator prompt for the *new* passkey
/// afterwards and the re-issue route does not, and each says so.
#[derive(Clone, Copy)]
struct OpenerWords {
    /// What is being opened, and why. The paragraph under the heading.
    intro: &'static str,
    /// The button that starts the passkey route.
    passkey: &'static str,
    /// What that route costs, in authenticator prompts.
    passkey_hint: &'static str,
    /// The label over the recovery-code field.
    recovery_label: &'static str,
    /// The button that starts the recovery route.
    recovery: &'static str,
    /// When to reach for it.
    recovery_hint: &'static str,
    /// What is left when nothing on the account can open it.
    nothing: &'static str,
    /// The recovery field's `id`, which its `<label>` points at.
    input_id: &'static str,
}

/// Choosing which of the account's secrets will open its data key.
///
/// Shared by the two ceremonies that need the raw key and so cannot use the
/// one this session may already hold (invariant E5): giving a keyless passkey
/// a copy (spec section 6.5) and minting a fresh recovery code (spec 6.4).
///
/// The recovery route is on this screen because of what leaving it off
/// costs. A user who lost every passkey and got back in with their code has
/// no passkey that can open anything — so a passkey-only ceremony refuses,
/// after spending an authenticator prompt to find out, and that account
/// stays as it is: unable to key a replacement passkey, and unable to
/// replace the code its owner has just read aloud into a laptop. Both routes
/// are offered when both exist, because a passkey prompt is less to get
/// wrong than thirty-two typed characters.
#[component]
fn OpenerChoice(
    words: OpenerWords,
    overview: RwSignal<Fetched>,
    busy: RwSignal<bool>,
    on_open: impl Fn(KeySource) + Copy + Send + 'static,
) -> impl IntoView {
    let typed_code = RwSignal::new(String::new());

    view! {
        <p class="text-sm text-gray-600 mb-4">{words.intro}</p>

        {move || match overview.get().loaded().map(|overview| Openers::of(&overview)) {
            // The list has not arrived, so nothing is known about what could
            // open this account — and claiming either answer here would be a
            // guess the user would act on.
            None => EitherOf3::A(view! {
                <p class="text-sm text-gray-500">"Loading…"</p>
            }),
            // Not a state a healthy account reaches: `encryption_enable`
            // writes a recovery wrap in the same transaction that turns
            // encryption on. Said plainly anyway, because an account here has
            // already lost its entries and a spinner would be the worst way
            // to find that out.
            Some(Openers::Nothing) => EitherOf3::B(view! {
                <p class="text-sm text-red-700 bg-red-50 border border-red-200 rounded p-3 mb-4">
                    {words.nothing}
                </p>
            }),
            Some(openers) => EitherOf3::C(view! {
                <div>
                    {openers.passkey().then(|| view! {
                        <div class="mb-4">
                            <button
                                type="button"
                                class="bg-blue-600 text-white text-sm font-semibold rounded px-4 py-2 hover:bg-blue-700 disabled:opacity-60"
                                disabled=move || busy.get()
                                on:click=move |_| on_open(KeySource::Passkey)
                            >
                                {words.passkey}
                            </button>
                            <p class="text-xs text-gray-500 mt-1">{words.passkey_hint}</p>
                        </div>
                    })}
                    {openers.recovery().then(|| view! {
                        <div>
                            <label
                                class="block text-sm font-medium text-gray-800 mb-1"
                                for=words.input_id
                            >
                                {words.recovery_label}
                            </label>
                            <input
                                id=words.input_id
                                type="text"
                                autocomplete="off"
                                spellcheck="false"
                                class="w-full border border-gray-300 rounded px-2 py-1.5 text-sm mb-2 font-mono focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                                placeholder="0000-0000-0000-0000-0000-0000-0000-0000"
                                prop:value=move || typed_code.get()
                                on:input=move |ev| typed_code.set(event_target_value(&ev))
                            />
                            <button
                                type="button"
                                class="border border-gray-300 text-sm rounded px-3 py-1.5 hover:bg-gray-50 disabled:opacity-60"
                                disabled=move || busy.get()
                                on:click=move |_| on_open(
                                    KeySource::Recovery(typed_code.get_untracked()),
                                )
                            >
                                {words.recovery}
                            </button>
                            <p class="text-xs text-gray-500 mt-1">{words.recovery_hint}</p>
                        </div>
                    })}
                </div>
            }),
        }}
    }
}

/// The control that closes a card without doing anything.
#[component]
fn CancelCard(busy: RwSignal<bool>, on_cancel: impl Fn() + Copy + Send + 'static) -> impl IntoView {
    view! {
        <div class="mt-6 pt-4 border-t border-gray-100">
            <button
                type="button"
                class="text-sm text-gray-600 hover:text-gray-900 underline disabled:opacity-60"
                disabled=move || busy.get()
                on:click=move |_| on_cancel()
            >
                "Cancel"
            </button>
        </div>
    }
}

/// The words [`GiveKeyCard`] puts on the choice.
const GIVE_KEY_WORDS: OpenerWords = OpenerWords {
    intro: "Your entries are encrypted, so this passkey needs its own copy of the key. Open \
            them with something that can already read them, and your browser will ask for this \
            passkey once more to finish.",
    passkey: "Use another passkey",
    passkey_hint: "Two prompts: one for a passkey that can already open your entries, then one \
                   for this one.",
    recovery_label: "Or use your recovery code",
    recovery: "Use my recovery code",
    recovery_hint: "One prompt, for this passkey. This is the route to use when none of your \
                    other passkeys can open your entries — after a recovery, it is the only one \
                    that works.",
    nothing: "Nothing on this account can open your entries: no passkey here holds a key, and \
              there's no recovery code on file. There is no way to give this passkey one.",
    input_id: "give-key-recovery-code",
};

/// Giving a keyless passkey its own copy of the data key (spec section 6.5).
#[component]
fn GiveKeyCard(
    name: String,
    credential_id: Vec<u8>,
    overview: RwSignal<Fetched>,
    busy: RwSignal<bool>,
    on_open: impl Fn(Vec<u8>, KeySource) + Copy + Send + 'static,
    on_cancel: impl Fn() + Copy + Send + 'static,
) -> impl IntoView {
    // Stored rather than cloned into each handler: both routes need the same
    // credential, and the reactive block inside `OpenerChoice` rebuilds them
    // whenever the overview lands.
    let credential = StoredValue::new(credential_id);

    view! {
        <div>
            <h2 class="text-lg font-semibold text-gray-800 mb-1">
                {format!("Give “{name}” an unlock key")}
            </h2>
            <OpenerChoice
                words=GIVE_KEY_WORDS
                overview=overview
                busy=busy
                on_open=move |source| on_open(credential.get_value(), source)
            />
            <CancelCard busy=busy on_cancel=on_cancel/>
        </div>
    }
}

/// The words [`ReissueCard`] puts on the same choice.
const REISSUE_WORDS: OpenerWords = OpenerWords {
    intro: "A new code has to be wrapped around the key your entries are encrypted with, so \
            something that can already open them has to do it. Your current code keeps working \
            until the new one is stored — and if we can't confirm that it was, we'll say so \
            rather than let you rely on either.",
    passkey: "Use a passkey",
    passkey_hint: "One prompt, for a passkey that can already open your entries.",
    recovery_label: "Or use the code you have now",
    recovery: "Use my current code",
    recovery_hint: "No passkey prompt. This is the route to use when none of your passkeys can \
                    open your entries — after a recovery, it is the only one that works.",
    nothing: "Nothing on this account can open your entries: no passkey here holds a key, and \
              there's no recovery code on file. There is nothing left to wrap a new code around.",
    input_id: "reissue-recovery-code",
};

/// Minting a fresh recovery code, which needs the raw data key and so needs a
/// route to it (spec section 6.4).
///
/// A choice rather than a straight assertion, and that is the whole point of
/// the card. An account whose every passkey is keyless — which is where a
/// user lands after recovering with their code — has no passkey opener, so
/// the passkey-only version spent an authenticator prompt to arrive at "that
/// passkey can't open this account's entries" and left them unable to replace
/// the code they had just typed. `ManageSection`'s "No recovery code is on
/// file … Generate one now" pointed at that control.
#[component]
fn ReissueCard(
    overview: RwSignal<Fetched>,
    busy: RwSignal<bool>,
    on_open: impl Fn(KeySource) + Copy + Send + 'static,
    on_cancel: impl Fn() + Copy + Send + 'static,
) -> impl IntoView {
    view! {
        <div>
            <h2 class="text-lg font-semibold text-gray-800 mb-1">
                "Generate a new recovery code"
            </h2>
            <OpenerChoice words=REISSUE_WORDS overview=overview busy=busy on_open=on_open/>
            <CancelCard busy=busy on_cancel=on_cancel/>
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
    on_give_key: impl Fn(String, Vec<u8>) + Copy + Send + 'static,
) -> impl IntoView {
    let PasskeyRoute {
        name,
        credential_id,
        status,
    } = route;
    // Taken before `name` is moved into the row's own text, so the repair
    // control can name the passkey it is about to key.
    let repair = (status == RouteStatus::NoKeyYet).then(|| (name.clone(), credential_id));

    view! {
        <li class="flex items-start justify-between gap-3 py-2">
            <div class="min-w-0">
                <p class="text-sm font-medium text-gray-900">
                    {name}
                    <span class="ml-2 text-xs font-normal text-gray-500">{status.label()}</span>
                </p>
                <p class="text-xs text-gray-500">{status.explanation()}</p>
            </div>
            {repair.map(|(name, credential_id)| view! {
                <button
                    type="button"
                    class="text-sm text-blue-600 hover:text-blue-800 shrink-0 disabled:opacity-60"
                    disabled=move || busy.get()
                    on:click=move |_| on_give_key(name.clone(), credential_id.clone())
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
    use super::{Overview, classify};
    use crate::crypto::flow::{self, PrfAssertion};
    use crate::crypto::{Enabled, Forgets, SessionKey, choose_route, enable, enable_recovery_only};
    use crate::dto::PasskeyWrapDto;
    use crate::server_fns::encryption::{encryption_enable, encryption_wraps};
    use crate::server_fns::passkey::passkey_list;

    /// Fetches everything the panel reports on.
    ///
    /// `encrypted` is whether the account is encrypted, and so whether its
    /// wraps are worth asking for at all.
    pub async fn load_overview(encrypted: bool) -> Result<Overview, String> {
        let rows = passkey_list().await.map_err(flow::server_unreachable)?;
        let wraps = if encrypted {
            encryption_wraps().await.map_err(flow::server_unreachable)?
        } else {
            Vec::new()
        };

        Ok(Overview {
            routes: rows.into_iter().map(|row| classify(row, &wraps)).collect(),
            has_recovery_wrap: choose_route(&wraps, None).is_some(),
        })
    }

    /// The enable ceremony, paused with the recovery code on screen.
    ///
    /// Everything the account needs already exists — a data key, its wraps
    /// and a code — and the server still knows none of it, so the account is
    /// *not* encrypted. That gap is the point of the type: it holds the
    /// ceremony open across the one-time display of the code, so the user
    /// has saved it before the transaction that makes it their only backup.
    ///
    /// Flattened out of the [`Enabled`] it is built from so the passkey wrap
    /// travels joined to the credential it will be filed under. The two are
    /// present or absent together — [`enable`] produces both,
    /// [`enable_recovery_only`] neither — and keeping them as one field is
    /// what stops a later edit from carrying a wrap with nothing to file it
    /// under, or a credential id with nothing to store.
    pub struct PendingEnable {
        session_key: SessionKey,
        recovery_code: String,
        /// `None` on the recovery-code-only route.
        passkey: Option<PasskeyWrapDto>,
        recovery_wrap: Vec<u8>,
    }

    impl PendingEnable {
        /// The code to show once, before committing to it.
        pub fn recovery_code(&self) -> &str {
            &self.recovery_code
        }
    }

    /// What a browser that cannot do the WebCrypto half is told. Shared by
    /// both routes because it is the same failure: neither one has reached
    /// the server or the keystore by the time it can happen.
    const KEY_GENERATION_FAILED: &str = "This browser couldn't generate an encryption key.";

    /// Everything turning encryption on does before the server hears about
    /// it, on the route that has a PRF-capable passkey: spec section 6.1's
    /// steps 1 to 3.
    ///
    /// Abandoning a `PendingEnable` — closing the tab on the code screen —
    /// costs nothing. `encrypted_at` is unset, so the next probe reports
    /// `Disabled`, and the code the user may have saved simply opens nothing.
    pub async fn begin_enable(user: &str) -> Result<PendingEnable, String> {
        // Captured here, before this ceremony's first await, not inside
        // `crypto::enable` — which does not run until the assertion below
        // has already returned. A sign-out or a "Lock now" issued during it
        // must still outrank the keystore write `remember` makes once this
        // ceremony's key reaches `EncryptionCtx::unlock` (spec section 6.7,
        // see `crypto::Forgets`).
        let forgets = Forgets::now();
        let PrfAssertion {
            credential_id,
            prf_output,
        } = flow::assert_with_prf(user)
            .await
            .map_err(flow::assertion_message)?;

        let Enabled {
            session_key,
            recovery_code,
            passkey_wrap,
            recovery_wrap,
        } = enable(&prf_output, user, forgets)
            .await
            .map_err(|_| KEY_GENERATION_FAILED.to_string())?;

        Ok(PendingEnable {
            session_key,
            recovery_code,
            passkey: passkey_wrap.map(|wrapped_key| PasskeyWrapDto {
                credential_id,
                wrapped_key,
            }),
            recovery_wrap,
        })
    }

    /// The same pause, on the route with no passkey wrap at all (spec
    /// section 6.1's second route).
    ///
    /// Shorter by an assertion, and that absence is the whole difference:
    /// there is no credential to derive key material from, so `Forgets::now`
    /// here really is the ceremony's first step rather than a capture made
    /// after one. The code this leaves on screen is the account's only key,
    /// which is why the card showing it says so in its own words — see
    /// [`CodeKind`](super::CodeKind).
    ///
    /// The ceremony itself cannot be tested on the host: `enable_recovery_only`
    /// reaches WebCrypto for the data key, the KEK and the wrap, and there is
    /// no host equivalent and no wasm test runner in this project. What is
    /// covered is the choice put in front of the user and the server's half.
    pub async fn begin_enable_recovery_only(user: &str) -> Result<PendingEnable, String> {
        let forgets = Forgets::now();
        let Enabled {
            session_key,
            recovery_code,
            passkey_wrap: _,
            recovery_wrap,
        } = enable_recovery_only(user, forgets)
            .await
            .map_err(|_| KEY_GENERATION_FAILED.to_string())?;

        Ok(PendingEnable {
            session_key,
            recovery_code,
            passkey: None,
            recovery_wrap,
        })
    }

    /// Step 4, run only once the user has confirmed they hold the code —
    /// which is why it comes *after* step 5 (spec section 6.1's second
    /// amendment).
    ///
    /// The failure worth spelling out is the *lost response*, the same shape
    /// `flow::reissue`'s retry exists for and the one case a retry cannot
    /// fix: the transaction commits and the reply never arrives. Ordering
    /// the code screen first is what makes that survivable — if it committed,
    /// the code the user just saved is the account's live one; if it did not,
    /// they saved a code for an account that is not encrypted, and the next
    /// attempt mints another. The caller cannot tell those apart from here,
    /// so the message says how to find out and what each answer means.
    pub async fn commit_enable(pending: PendingEnable) -> Result<SessionKey, String> {
        let PendingEnable {
            session_key,
            recovery_code: _,
            passkey,
            recovery_wrap,
        } = pending;

        encryption_enable(passkey, recovery_wrap)
            .await
            .map_err(|err| {
                format!(
                    "{} We couldn't confirm encryption was turned on. Reload this page and \
                     read this panel: if it says encryption is on, the code you just saved is \
                     the right one — keep it. If it still offers to turn encryption on, \
                     nothing was changed and you can try again.",
                    crate::webauthn_browser::friendly_error(err.to_string())
                )
            })?;

        Ok(session_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::wire::{self, WrapKind};

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

    /// Which of spec section 6.1's two routes an account gets, and it is the
    /// account's capability that decides — not a preference.
    ///
    /// An account whose only passkeys are PRF-incapable cannot complete the
    /// two-wrap ceremony at all: the assertion returns no key material. It
    /// used to be refused outright and told to enrol a better passkey, which
    /// is advice with nowhere to go when the authenticator in question never
    /// implemented the extension — a browser extension with no PRF support
    /// is the case this route exists for. What it gets instead is the
    /// recovery-only route, whose cost is stated in its own words.
    #[test]
    fn the_route_on_offer_follows_what_the_accounts_passkeys_can_hold() {
        assert_eq!(
            EnableRoute::of(&Overview::default()),
            EnableRoute::RecoveryOnly,
            "an account with no passkeys at all still has a way to encrypt"
        );

        let incapable = Overview {
            routes: vec![classify(passkey("Old token", b"cred-c", false), &[])],
            ..Overview::default()
        };
        assert_eq!(EnableRoute::of(&incapable), EnableRoute::RecoveryOnly);

        // One capable passkey is enough, wrap or no wrap: enabling derives
        // the wrap from a fresh assertion, so `NoKeyYet` is the state every
        // account is in a moment before it turns encryption on.
        let capable = Overview {
            routes: vec![
                classify(passkey("Old token", b"cred-c", false), &[]),
                classify(passkey("Phone", b"cred-b", true), &[]),
            ],
            ..Overview::default()
        };
        assert_eq!(EnableRoute::of(&capable), EnableRoute::PasskeyAndRecovery);
    }

    /// The two routes must not share a warning. Losing the code costs
    /// everything on one of them and nothing on its own on the other, and a
    /// user who read the two-wrap sentence over a one-wrap account has been
    /// told they have slack they do not have.
    #[test]
    fn the_recovery_only_route_states_that_the_code_is_the_only_key() {
        let only = EnableRoute::RecoveryOnly.words();
        let both = EnableRoute::PasskeyAndRecovery.words();

        assert!(
            only.warning_heading.contains("only key"),
            "the heading must name the code as the only key: {}",
            only.warning_heading
        );
        assert!(
            only.warning.contains("no second way in"),
            "the warning must say there is nothing to fall back on: {}",
            only.warning
        );
        assert!(
            only.warning.contains("gone forever"),
            "and must state the loss as loss, not hedge it: {}",
            only.warning
        );
        assert!(
            !only.warning.contains("every passkey"),
            "the two-wrap wording implies a passkey could have saved them: {}",
            only.warning
        );
        assert!(
            !only.acknowledgement.contains("every passkey"),
            "and so does the two-wrap acknowledgement: {}",
            only.acknowledgement
        );

        assert_ne!(only.warning, both.warning);
        assert_ne!(only.acknowledgement, both.acknowledgement);
        assert_ne!(only.button, both.button);
    }

    /// The precedence the whole recovery story hangs on. A code on screen
    /// has to outrank the account's state, and neither code-bearing mode
    /// lines up with a phase that would render it: `NewCode` is shown while
    /// the account is still `Off`, `ReissuedCode` while it is `Unlocked`. If
    /// `Phase` won, the panel would paint the enable pitch or the manage
    /// view over a code that had just been made the account's only backup —
    /// and nothing would fail, because the ceremony would have succeeded.
    ///
    /// The phase arrives as a closure that panics, which pins the second
    /// half of the same rule: not only does the code win, the phase is never
    /// *read*. Reading it subscribes the card's reactive closure to it, and
    /// a rebuild on any phase change takes the "Copied." confirmation with
    /// it.
    #[test]
    fn a_code_on_screen_outranks_the_account_state() {
        let unread = || panic!("the phase must not be read while a code is on screen");
        assert_eq!(
            Screen::of(
                Mode::NewCode {
                    code: "K7M2".to_string(),
                    route: EnableRoute::RecoveryOnly,
                },
                unread,
            ),
            Screen::Code {
                code: "K7M2".to_string(),
                kind: CodeKind::New(EnableRoute::RecoveryOnly),
            },
        );
        assert_eq!(
            Screen::of(Mode::ReissuedCode("K7M2".to_string()), unread),
            Screen::Code {
                code: "K7M2".to_string(),
                kind: CodeKind::Reissued,
            },
        );
        // The same rule, one ceremony over. Nothing irreplaceable is on this
        // screen, but a half-typed recovery code painted over by a re-render
        // of the manage view is the same class of loss.
        assert_eq!(
            Screen::of(
                Mode::GiveKey {
                    credential_id: b"cred-b".to_vec(),
                    name: "New phone".to_string(),
                },
                unread,
            ),
            Screen::GiveKey {
                credential_id: b"cred-b".to_vec(),
                name: "New phone".to_string(),
            },
        );
    }

    /// The same rule for the screen this round adds. A half-typed recovery
    /// code on the re-issue card must not be painted over by the manage view
    /// the account's phase would otherwise call for — and the phase *is*
    /// `Unlocked` throughout, since only an encrypted account offers this.
    #[test]
    fn the_reissue_choice_outranks_the_account_state() {
        let unread = || panic!("the phase must not be read while a card is up");
        assert_eq!(Screen::of(Mode::Reissue, unread), Screen::Reissue);
    }

    /// And with no ceremony of its own running, the panel shows what the
    /// account's state calls for — including the `Checking` branch the
    /// server renders for everybody (invariant E2).
    #[test]
    fn an_idle_panel_follows_the_account_state() {
        assert_eq!(Screen::of(Mode::Idle, || Phase::Checking), Screen::Checking);
        assert_eq!(
            Screen::of(Mode::Idle, || Phase::Unreachable),
            Screen::Unreachable
        );
        assert_eq!(Screen::of(Mode::Idle, || Phase::Off), Screen::Enable);
        assert_eq!(
            Screen::of(Mode::Idle, || Phase::Locked),
            Screen::Manage { unlocked: false }
        );
        assert_eq!(
            Screen::of(Mode::Idle, || Phase::Unlocked),
            Screen::Manage { unlocked: true }
        );
    }

    /// A1's route selection, and the account it exists for. Somebody who
    /// lost every passkey and got back in with their recovery code has no
    /// passkey opener to offer — so a ceremony that only ever asked for one
    /// would refuse to key the replacement passkey they have just enrolled,
    /// and the account would stay recovery-code-only on every device, for
    /// good. Recovering is meant to get them back in, not cost them the way
    /// back.
    ///
    /// What this pins is the choice put in front of the user. The ceremony
    /// behind it cannot be tested here at all: it reaches WebAuthn for the
    /// new credential's PRF output, and there is no host equivalent and no
    /// wasm test runner in this project.
    #[test]
    fn a_recovered_account_can_still_key_a_new_passkey() {
        let wraps = vec![passkey_wrap(b"cred-a")];
        let recovered = Overview {
            // The replacement, enrolled after the recovery: capable, but
            // with no wrap of its own yet.
            routes: vec![classify(passkey("New phone", b"cred-b", true), &[])],
            has_recovery_wrap: true,
        };
        assert_eq!(Openers::of(&recovered), Openers::RecoveryOnly);
        assert!(
            Openers::of(&recovered).recovery(),
            "the code that got this user back in must also be able to key a passkey"
        );
        assert!(!Openers::of(&recovered).passkey());

        // The ordinary account keeps both, because a passkey prompt is less
        // to get wrong than thirty-two typed characters.
        let healthy = Overview {
            routes: vec![
                classify(passkey("Laptop", b"cred-a", true), &wraps),
                classify(passkey("New phone", b"cred-b", true), &wraps),
            ],
            has_recovery_wrap: true,
        };
        assert_eq!(Openers::of(&healthy), Openers::Either);
    }

    /// The two ends of the same selection. An account with a working passkey
    /// and no recovery wrap has one route; an account with neither has none,
    /// and offering a ceremony there would send the user through an
    /// authenticator prompt to reach a failure.
    #[test]
    fn an_account_with_nothing_that_opens_it_is_offered_no_route() {
        let wraps = vec![passkey_wrap(b"cred-a")];
        let no_code = Overview {
            routes: vec![classify(passkey("Laptop", b"cred-a", true), &wraps)],
            has_recovery_wrap: false,
        };
        assert_eq!(Openers::of(&no_code), Openers::PasskeyOnly);

        let nothing = Overview {
            routes: vec![classify(passkey("New phone", b"cred-b", true), &wraps)],
            has_recovery_wrap: false,
        };
        assert_eq!(Openers::of(&nothing), Openers::Nothing);
        assert!(!Openers::of(&nothing).passkey());
        assert!(!Openers::of(&nothing).recovery());
    }

    /// The code screens say different things, and saying the wrong one is a
    /// lie the user cannot check: "your previous code no longer works" over
    /// a first code would send somebody looking for a code they never had.
    ///
    /// The two *enable* screens are the pair that matters most. On the
    /// two-wrap route the code is a backup behind a passkey; on the
    /// recovery-only route it is the account, and a user shown the first
    /// sentence over the second kind of code has been told they have a
    /// fallback that does not exist.
    #[test]
    fn each_code_screen_carries_its_own_words() {
        let with_passkey = CodeKind::New(EnableRoute::PasskeyAndRecovery);
        let recovery_only = CodeKind::New(EnableRoute::RecoveryOnly);

        assert!(with_passkey.confirm().contains("turning on encryption"));
        assert!(recovery_only.confirm().contains("turning on encryption"));
        assert!(CodeKind::Reissued.intro().contains("no longer works"));
        assert!(!with_passkey.intro().contains("no longer works"));

        assert!(
            with_passkey.intro().contains("if you lose every passkey"),
            "the two-wrap code is a backup behind a passkey, and says so"
        );
        assert!(
            !recovery_only.intro().contains("if you lose every passkey"),
            "the recovery-only code must not be described as a passkey's backup"
        );
        assert!(
            recovery_only.intro().contains("it is the key"),
            "the recovery-only code must be named as the only key: {}",
            recovery_only.intro()
        );
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

    /// Renders the enable pitch with the account's routes at `overview` and
    /// the acknowledgement checkbox at `understood`.
    ///
    /// `understood` is a parameter and not a fixed `false` because the gate
    /// is an `||` chain: with the box unticked the button is disabled
    /// whatever else is true, so every assertion about the *capability* half
    /// of that gate passes vacuously. Ticking it is what makes the
    /// capability check the only thing left holding the button shut.
    #[cfg(feature = "ssr")]
    fn render_enable(overview: Fetched, understood: bool) -> String {
        let runtime = Owner::new();
        let html = runtime.with(move || {
            view! {
                <EnableSection
                    overview=RwSignal::new(overview)
                    understood=RwSignal::new(understood)
                    busy=RwSignal::new(false)
                    on_enable=|_| {}
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
                    overview=RwSignal::new(Fetched::Loaded(overview))
                    busy=RwSignal::new(false)
                    on_lock=|| {}
                    on_reissue=|| {}
                    on_give_key=|_, _| {}
                />
            }
            .to_html()
        });
        runtime.cleanup();
        html
    }

    #[cfg(feature = "ssr")]
    fn render_give_key(overview: Fetched) -> String {
        let runtime = Owner::new();
        let html = runtime.with(move || {
            view! {
                <GiveKeyCard
                    name="New phone".to_string()
                    credential_id=b"cred-b".to_vec()
                    overview=RwSignal::new(overview)
                    busy=RwSignal::new(false)
                    on_open=|_, _| {}
                    on_cancel=|| {}
                />
            }
            .to_html()
        });
        runtime.cleanup();
        html
    }

    /// A1 at the view. The card must offer the recovery code when that is
    /// all the account has, must not offer a passkey route that would find
    /// no opener, and must not pre-judge either while the list is still on
    /// its way.
    #[cfg(feature = "ssr")]
    #[test]
    fn the_give_key_card_offers_the_routes_the_account_actually_has() {
        let recovered = render_give_key(Fetched::Loaded(Overview {
            routes: vec![classify(passkey("New phone", b"cred-b", true), &[])],
            has_recovery_wrap: true,
        }));
        assert!(recovered.contains("Use my recovery code"));
        assert!(
            !recovered.contains("Use another passkey"),
            "an account with no passkey that can unlock must not be sent to look for one"
        );

        let wraps = vec![passkey_wrap(b"cred-a")];
        let healthy = render_give_key(Fetched::Loaded(Overview {
            routes: vec![
                classify(passkey("Laptop", b"cred-a", true), &wraps),
                classify(passkey("New phone", b"cred-b", true), &wraps),
            ],
            has_recovery_wrap: true,
        }));
        assert!(healthy.contains("Use another passkey"));
        assert!(healthy.contains("Use my recovery code"));

        let unknown = render_give_key(Fetched::Pending);
        for control in ["Use another passkey", "Use my recovery code"] {
            assert!(
                !unknown.contains(control),
                "`{control}` was offered before the account's routes were known"
            );
        }
    }

    #[cfg(feature = "ssr")]
    fn render_reissue(overview: Fetched) -> String {
        let runtime = Owner::new();
        let html = runtime.with(move || {
            view! {
                <ReissueCard
                    overview=RwSignal::new(overview)
                    busy=RwSignal::new(false)
                    on_open=|_| {}
                    on_cancel=|| {}
                />
            }
            .to_html()
        });
        runtime.cleanup();
        html
    }

    /// The route this round adds, and the account it exists for. Somebody
    /// who lost every passkey and got back in with their code has just typed
    /// it into a laptop and should replace it — but every passkey on that
    /// account is keyless, so the passkey-only re-issue spent an
    /// authenticator prompt to reach "that passkey can't open this account's
    /// entries" and left them with no way to mint a replacement at all.
    ///
    /// The healthy half is asserted too, so this cannot be satisfied by
    /// offering the code and dropping the passkey route that costs one
    /// prompt instead of thirty-two typed characters.
    #[cfg(feature = "ssr")]
    #[test]
    fn a_recovery_only_account_can_still_mint_a_new_code() {
        let recovered = render_reissue(Fetched::Loaded(Overview {
            routes: vec![classify(passkey("New phone", b"cred-b", true), &[])],
            has_recovery_wrap: true,
        }));
        assert!(recovered.contains("Use my current code"));
        assert!(
            !recovered.contains("Use a passkey"),
            "no passkey on this account can open it, so none must be offered as the opener"
        );

        let wraps = vec![passkey_wrap(b"cred-a")];
        let healthy = render_reissue(Fetched::Loaded(Overview {
            routes: vec![classify(passkey("Laptop", b"cred-a", true), &wraps)],
            has_recovery_wrap: true,
        }));
        assert!(healthy.contains("Use a passkey"));
        assert!(healthy.contains("Use my current code"));

        let unknown = render_reissue(Fetched::Pending);
        for control in ["Use a passkey", "Use my current code"] {
            assert!(
                !unknown.contains(control),
                "`{control}` was offered before the account's routes were known"
            );
        }
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
                    busy=RwSignal::new(false)
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
        assert!(
            html.contains("before encryption is switched on"),
            "the code is promised before the switch, because that is the order it runs in"
        );
        assert!(
            !html.contains("re-encrypted in place"),
            "there is no migration pass left to make that promise"
        );
    }

    /// The gate, in the state the server renders: nothing is known about the
    /// account's passkeys yet, and "not known" must hold the ceremony shut
    /// rather than start one that would fail at its first assertion.
    ///
    /// It must not yet *claim* there is no usable passkey either — that
    /// sentence is only true once the list has arrived, and rendering it
    /// here would flash a false alarm on every visit.
    ///
    /// Rendered with the acknowledgement already ticked, and against a
    /// control that renders enabled. The gate is `busy || !understood ||
    /// !capable`, so an unticked box shuts the button on its own and an
    /// assertion made under one holds however the capability check behaves
    /// — including if it were deleted.
    #[cfg(feature = "ssr")]
    #[test]
    fn enabling_is_shut_until_the_account_is_known() {
        let unknown = render_enable(Fetched::Pending, true);
        assert!(
            unknown.contains(r#"<button type="button" disabled"#),
            "the enable button must render disabled while nothing is known: {unknown}"
        );
        assert!(
            !unknown.contains("Encryption needs a passkey"),
            "an unknown passkey list must not read as a missing one"
        );

        let known = render_enable(
            Fetched::Loaded(Overview {
                routes: vec![classify(passkey("Phone", b"cred-b", true), &[])],
                ..Overview::default()
            }),
            true,
        );
        assert!(
            !known.contains(r#"<button type="button" disabled"#),
            "an account that can enable, from a user who has acknowledged the loss, must be \
             offered the ceremony: {known}"
        );
    }

    /// And once the list *is* in and holds nothing PRF-capable, the panel
    /// offers the recovery-only route rather than a dead control. This is
    /// the case the second route was added for: an authenticator with no PRF
    /// support — a browser extension that never implemented the extension,
    /// say — makes the two-wrap ceremony permanently impossible, and the
    /// account the old dead end left behind was a plaintext one.
    ///
    /// Ticked, for the reason the test above gives: an unticked box would
    /// shut the button by itself and the `disabled` assertion would prove
    /// nothing about the check it is aimed at.
    ///
    /// The words are asserted here as well as in
    /// [`the_recovery_only_route_states_that_the_code_is_the_only_key`],
    /// because that test pins the constants and this one pins that the
    /// section actually renders *these* constants for *this* account.
    #[cfg(feature = "ssr")]
    #[test]
    fn an_account_with_no_capable_passkey_is_offered_the_recovery_only_route() {
        let html = render_enable(
            Fetched::Loaded(Overview {
                routes: vec![classify(passkey("Old token", b"cred-c", false), &[])],
                ..Overview::default()
            }),
            true,
        );
        assert!(
            !html.contains(r#"<button type="button" disabled"#),
            "an account with no capable passkey must be offered a route, not a dead end: {html}"
        );
        assert!(html.contains("Turn on encryption with a recovery code only"));
        assert!(
            html.contains("Your recovery code will be the only key."),
            "the panel must say the code is the only key: {html}"
        );
        assert!(
            html.contains("no second way in and nothing to fall back on"),
            "and that there is nothing behind it: {html}"
        );
        assert!(
            !html.contains("losing every passkey and my recovery code"),
            "the two-wrap acknowledgement claims a fallback this account has not got: {html}"
        );

        let capable = render_enable(
            Fetched::Loaded(Overview {
                routes: vec![classify(passkey("Phone", b"cred-b", true), &[])],
                ..Overview::default()
            }),
            true,
        );
        assert!(
            !capable.contains("Turn on encryption with a recovery code only"),
            "an account that can hold a passkey wrap must not be offered the weaker route"
        );
        assert!(
            capable.contains("There is no reset."),
            "and must keep the two-wrap warning: {capable}"
        );
    }

    /// The other half of the gate, which the two tests above deliberately
    /// tick past: the acknowledgement is not decoration. A user who has not
    /// said they understand that losing every passkey and their recovery
    /// code loses their entries must not be able to start the one ceremony
    /// in this application that cannot be undone.
    #[cfg(feature = "ssr")]
    #[test]
    fn enabling_is_shut_until_the_loss_is_acknowledged() {
        let capable = Fetched::Loaded(Overview {
            routes: vec![classify(passkey("Phone", b"cred-b", true), &[])],
            ..Overview::default()
        });
        let html = render_enable(capable, false);
        assert!(
            html.contains(r#"<button type="button" disabled"#),
            "an unacknowledged warning must hold the ceremony shut: {html}"
        );
    }

    /// The state a failed probe leaves behind, which nothing else on this
    /// panel can end. It has to say that nothing is being saved — that is
    /// the part the user would otherwise discover by losing an entry — and
    /// offer the retry, which is the only way out of `Unreachable` short of
    /// a reload.
    #[cfg(feature = "ssr")]
    #[test]
    fn an_unanswered_probe_says_so_and_offers_another_try() {
        let html = render_panel(EncryptionState::Unreachable);
        assert!(html.contains("couldn't tell whether this account's entries are encrypted"));
        assert!(
            html.contains("Nothing is being saved"),
            "a state that refuses every write must say so"
        );
        assert!(html.contains("Try again"));
        for leaked in ["Encryption is on", "Turn on encryption"] {
            assert!(
                !html.contains(leaked),
                "a probe that answered nothing must not render `{leaked}`"
            );
        }
    }

    /// The manage view for an account enabled by the recovery-only route,
    /// which is now an ordinary account rather than a broken one: every
    /// passkey row says it will never open the entries, or there are no rows
    /// at all. A heading reading "What can unlock your entries" over nothing
    /// but that would look like a failed load, so the section says what does
    /// open the account and how that changes.
    ///
    /// The healthy account must not get the line — it would read as a
    /// warning where there is nothing wrong.
    #[cfg(feature = "ssr")]
    #[test]
    fn an_account_only_its_recovery_code_opens_is_told_so() {
        let only_the_code = "recovery code is the only thing that opens your entries";

        let incapable = render_manage(
            true,
            Overview {
                routes: vec![classify(passkey("Old token", b"cred-c", false), &[])],
                has_recovery_wrap: true,
            },
        );
        assert!(
            incapable.contains(only_the_code),
            "an account no passkey can open must say what can: {incapable}"
        );

        let no_passkeys = render_manage(
            true,
            Overview {
                has_recovery_wrap: true,
                ..Overview::default()
            },
        );
        assert!(
            no_passkeys.contains(only_the_code),
            "and so must one with no passkeys at all: {no_passkeys}"
        );

        let wraps = vec![passkey_wrap(b"cred-a")];
        let healthy = render_manage(
            true,
            Overview {
                routes: vec![classify(passkey("Laptop", b"cred-a", true), &wraps)],
                has_recovery_wrap: true,
            },
        );
        assert!(
            !healthy.contains(only_the_code),
            "an account a passkey opens must not be told otherwise: {healthy}"
        );
    }

    /// Never reached by a healthy account — `encryption_enable` writes the
    /// recovery wrap in the same transaction that turns encryption on, and
    /// re-issuing replaces it in one — but an account that got here is one
    /// lost authenticator away from unreadable, and silence is the worst
    /// possible way to report that.
    #[cfg(feature = "ssr")]
    #[test]
    fn an_account_with_no_recovery_wrap_is_told_it_has_none() {
        let wraps = vec![passkey_wrap(b"cred-a")];
        let routes = vec![classify(passkey("Laptop", b"cred-a", true), &wraps)];

        let missing = render_manage(
            true,
            Overview {
                routes: routes.clone(),
                has_recovery_wrap: false,
            },
        );
        assert!(missing.contains("No recovery code is on file for this account"));
        assert!(
            missing.contains("your entries are gone"),
            "the consequence must be stated, not left to be inferred"
        );

        let present = render_manage(
            true,
            Overview {
                routes,
                has_recovery_wrap: true,
            },
        );
        assert!(
            !present.contains("No recovery code is on file"),
            "an account that has one must not be told it does not"
        );
    }

    /// The other thing `Fetched` exists for: a failed refresh has a sentence
    /// of its own, and it renders beside `status` rather than inside it, so
    /// a ceremony's line and a refresh failure cannot paint over each other.
    /// Nothing rendered this branch before.
    #[cfg(feature = "ssr")]
    #[test]
    fn a_failed_refresh_is_reported_where_a_ceremony_cannot_paint_over_it() {
        let render = |fetched| {
            let runtime = Owner::new();
            let html = runtime
                .with(move || view! { <FetchProblem overview=RwSignal::new(fetched)/> }.to_html());
            runtime.cleanup();
            html
        };

        let failed = render(Fetched::Failed("Couldn't reach the server.".to_string()));
        assert!(failed.contains("Couldn't reach the server."));

        for quiet in [Fetched::Pending, Fetched::Loaded(Overview::default())] {
            assert!(
                !render(quiet).contains("Couldn't reach the server."),
                "a refresh that did not fail must say nothing"
            );
        }
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

    /// The migration pass is gone, and so is everything it used to report:
    /// no count of unencrypted days, no resume control, no unreadable-row
    /// warning, and none of the enable pitch's old promise to re-encrypt
    /// entries already saved. Rendered both unlocked and locked, and with a
    /// passkey on file, so this cannot pass by accident of an empty
    /// `Overview` — a heading with nothing to say beneath it would be the
    /// same failure the migration's removal must not leave behind.
    #[cfg(feature = "ssr")]
    #[test]
    fn the_manage_view_carries_no_migration_surface() {
        let overview = Overview {
            routes: vec![classify(passkey("Laptop", b"cred-a", true), &[])],
            has_recovery_wrap: true,
        };

        for html in [
            render_manage(true, overview.clone()),
            render_manage(false, overview),
        ] {
            assert!(html.contains("What can unlock your entries"));
            assert!(
                html.contains("Laptop"),
                "the heading must sit over real content: {html}"
            );
            for leaked in [
                "still stored unencrypted",
                "Finish encrypting",
                "could not be read",
            ] {
                assert!(!html.contains(leaked), "migration copy leaked: `{leaked}`");
            }
        }
    }
}
