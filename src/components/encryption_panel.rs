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

use chrono::NaiveDate;
use leptos::either::{Either, EitherOf3, EitherOf7};

#[cfg(any(feature = "hydrate", test))]
use crate::crypto::choose_route;
#[cfg(any(feature = "hydrate", test))]
use crate::crypto::flow;
#[cfg(any(feature = "hydrate", test))]
use crate::date::{parse_iso, to_iso};
#[cfg(any(feature = "hydrate", test))]
use crate::dto::{PasskeyListItem, WrapDto};
#[cfg(any(feature = "hydrate", test))]
use crate::storage::envelope::{ReadPlan, plan_read};
#[cfg(any(feature = "hydrate", test))]
use crate::storage::{StorageError, StorageKey};
#[cfg(any(feature = "hydrate", test))]
use crate::webauthn_browser::server_refusal;

#[cfg(feature = "hydrate")]
use leptos::task::spawn_local;

#[cfg(feature = "hydrate")]
use crate::storage::Generation;
#[cfg(feature = "hydrate")]
use ceremony::{PendingEnable, Refresh};

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

/// One row the migration is going to re-write.
///
/// A struct rather than the `(String, String)` it arrived as, and the date
/// is parsed on the way in. Both halves were `String` and the pass carries
/// them together through a seal step before handing them to the storage
/// seam: swapping them would have compiled, and would have filed every entry
/// under a date made of its own text. Parsing here also means an
/// uninterpretable date is caught by the pass, which can name it, rather
/// than by `entry_save_many`, which refuses the whole batch over it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(not(feature = "hydrate"), allow(dead_code))]
struct PendingRow {
    date: NaiveDate,
    /// The plaintext, already unwrapped from its v1 envelope.
    body: String,
}

/// What one pass over `entries_all()` found, and so what the migration will
/// and will not touch.
///
/// The server cannot produce this: answering "which rows are still
/// plaintext" means reading each row's envelope version, which is parsing a
/// body, which invariant E1 forbids outright. So the classification happens
/// in the browser (spec section 8).
///
/// The two halves are separate because they need different handling and
/// different words on screen. `pending` is work the pass does; `unreadable`
/// is work it refuses to do, and reports instead.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
#[cfg_attr(not(feature = "hydrate"), allow(dead_code))]
struct MigrationPlan {
    /// Every row still stored as v1, with the body ready to seal.
    pending: Vec<PendingRow>,
    /// The dates of rows this build could not interpret at all — named, not
    /// counted. Guessing at one would destroy it, and skipping it silently
    /// would leave it plaintext forever with nobody told which day it was.
    unreadable: Vec<String>,
}

impl MigrationPlan {
    /// Sorts `entries_all()`'s rows into the ones the migration must
    /// re-write and the ones it must leave alone.
    ///
    /// Pure, and the only part of the migration a host test can reach —
    /// sealing a body goes through WebCrypto, which has no host equivalent.
    /// Dispatch is on each row's own envelope version, never on account
    /// state, which is what makes the pass resumable: run it again and it
    /// simply finds fewer v1 rows. A v2 row is left strictly alone rather
    /// than re-sealed, because re-sealing means decrypting first and a bug
    /// on that path destroys data (spec E3, section 8).
    #[cfg(any(feature = "hydrate", test))]
    fn of(rows: Vec<(String, String)>) -> Self {
        let mut plan = Self::default();
        for (date, raw) in rows {
            // A date this build cannot read is as unreadable as a body it
            // cannot parse, and belongs in the same list: the pass would
            // otherwise have to guess which day the row is, and sending it
            // on would have `entry_save_many` refuse — and roll back — the
            // entire batch over the one row.
            let Some(day) = parse_iso(&date) else {
                plan.unreadable.push(date);
                continue;
            };
            match plan_read(&raw) {
                Ok(ReadPlan::Plaintext(body)) => plan.pending.push(PendingRow { date: day, body }),
                Ok(ReadPlan::Sealed(_)) => {}
                Err(_) => plan.unreadable.push(date),
            }
        }
        plan
    }

    /// The pass's work, in the shape the storage seam takes.
    #[cfg(feature = "hydrate")]
    fn into_rows(self) -> Vec<(NaiveDate, String)> {
        self.pending
            .into_iter()
            .map(|row| (row.date, row.body))
            .collect()
    }
}

/// Everything the panel fetches about the account in one go.
#[derive(Clone, Default)]
#[cfg_attr(not(feature = "hydrate"), allow(dead_code))]
struct Overview {
    routes: Vec<PasskeyRoute>,
    /// Whether a recovery wrap this build can open is on file.
    has_recovery_wrap: bool,
    unencrypted_days: usize,
    /// The dates of rows nothing here can read. Dates rather than a count:
    /// this is the one thing on the panel the user has to act on by hand,
    /// and "2 days couldn't be read" tells them nothing about which two.
    unreadable_dates: Vec<String>,
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
/// gave that line two writers, and they raced: a refresh failing during a
/// migration painted over "Encrypting your entries… day 3 of 40", and the
/// pass's next progress line painted over the failure. Keeping the fetch's
/// own answer here leaves `status` with exactly one writer.
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
    /// knows nothing. Confirming it is what turns encryption on: the
    /// server call, then the key, then the migration.
    NewCode(String),
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
    /// Minted by the enable ceremony, with the server not yet told.
    New,
    /// Minted by a re-issue, replacing one that has stopped working.
    Reissued,
}

impl CodeKind {
    fn heading(self) -> &'static str {
        match self {
            CodeKind::New => "Save your recovery code",
            CodeKind::Reissued => "Your new recovery code",
        }
    }

    fn intro(self) -> &'static str {
        match self {
            CodeKind::New => {
                "This is the only thing that opens your entries if you lose every passkey. It \
                 is shown once — leaving this page without it means generating a replacement \
                 from this panel while you still have a passkey that works."
            }
            CodeKind::Reissued => {
                "Your previous code no longer works. This one is shown once and never again."
            }
        }
    }

    fn confirm(self) -> &'static str {
        match self {
            CodeKind::New => "I've saved it — finish turning on encryption",
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
            Mode::NewCode(code) => Screen::Code {
                code,
                kind: CodeKind::New,
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

/// "1 day" / "2 days", so counts read as English.
fn days(n: usize) -> String {
    format!("{n} {}", if n == 1 { "day" } else { "days" })
}

/// What a failed migration pass leaves the user holding.
///
/// Out here rather than inside the `hydrate`-only `ceremony` module below
/// precisely so it has a test: what it decides is the only thing a user gets
/// to act on when a pass stops, and each of its three answers sends them
/// somewhere different.
///
/// A seal failure names its day. One body this build cannot seal blocks the
/// rest of the account's pass every time it is run, forever, and the only
/// remedy is a person opening that day and editing what is in it — so a
/// message that says "this browser couldn't encrypt your entries" points at
/// the browser, which is not where the problem is. The date is recoverable
/// because `store_many` keys the error by [`StorageKey::as_key`], and
/// [`StorageKey::parse`] reads it back.
///
/// A refusal the server explained is repeated verbatim: `server_err`
/// guarantees it carries no internal detail, and "that's too many entries in
/// one request" is not a connection problem. Only a call that never got an
/// answer earns the connection hint — see
/// [`webauthn_browser::server_refusal`](crate::webauthn_browser::server_refusal).
///
/// Every message says what the pass left behind, because chunking means the
/// answer is no longer "nothing": days sealed before the failure stay
/// sealed.
#[cfg(any(feature = "hydrate", test))]
fn pass_failed(err: StorageError) -> String {
    match err {
        StorageError::Crypto { key, .. } => match StorageKey::parse(&key) {
            Some(key) => format!(
                "This browser couldn't encrypt the entry for {}, so the pass stopped there. \
                 Days encrypted before it stayed encrypted. Open that day, check what's in \
                 it, and try again.",
                to_iso(key.date()),
            ),
            // Only reachable if the seam ever keys a `Crypto` error by
            // something other than a storage key. Says less rather than
            // guessing at a day.
            None => "This browser couldn't encrypt one of your entries, so the pass stopped \
                     there. Days encrypted before it stayed encrypted."
                .to_string(),
        },
        StorageError::Server(message) => match server_refusal(&message) {
            Some(refusal) => format!(
                "{refusal}. Days encrypted before that stayed encrypted; try again to finish."
            ),
            None => flow::SERVER_UNREACHABLE.to_string(),
        },
        _ => flow::SERVER_UNREACHABLE.to_string(),
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

    // Whether a migration pass is running. A `StoredValue` rather than a
    // signal precisely because the overview effect below reads it and must
    // not become its subscriber: this says "skip work that is about to be
    // redone", and re-running the effect to learn that would be the very
    // fetch it exists to avoid.
    #[cfg(feature = "hydrate")]
    let migrating = StoredValue::new(false);

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
            let refresh = Refresh {
                encrypted,
                // Enabling encryption wakes this effect and starts a
                // migration from the same click, and that pass reads every
                // row itself. Surveying them here too would be a second full
                // `entries_all()` for numbers the pass replaces with better
                // ones a moment later.
                survey_entries: encrypted && !migrating.get_value(),
            };

            spawn_local(async move {
                let loaded = ceremony::load_overview(refresh).await;
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

    // Re-encrypts whatever is left in the clear. Shared by the tail of the
    // enable ceremony and the resume control, which are the same operation
    // reached from two places — the second exists precisely because the
    // first can be interrupted (spec section 8).
    let run_migration = move || {
        #[cfg(feature = "hydrate")]
        {
            busy.set(true);
            // Set before the spawn, so the overview effect that the same
            // click wakes — via the phase change enabling produces — sees it
            // and skips its own survey of the rows this pass is about to
            // re-write.
            migrating.set_value(true);
            status.set(Some(Status::Note(
                "Encrypting the entries already saved…".to_string(),
            )));
            spawn_local(async move {
                // The key is read here rather than carried in, so a lock or
                // a sign-out that landed while this was queued is seen.
                let state = encryption.state_untracked();
                let outcome = match state.key() {
                    // Sealing is one WebCrypto round trip per row, so a
                    // large account spends a while here with nothing to
                    // show for it. The callback lands between rows, on the
                    // await that yields to the event loop, so the line on
                    // screen actually moves.
                    Some(key) => {
                        ceremony::migrate(key, |at| {
                            status.set(Some(Status::Note(format!(
                                "Encrypting your entries… day {} of {}.",
                                at.day, at.total,
                            ))));
                        })
                        .await
                    }
                    None => Err("This device is locked, so nothing could be re-encrypted \
                                 yet."
                        .to_string()),
                };
                busy.set(false);
                migrating.set_value(false);
                let done = match outcome {
                    Ok(done) => done,
                    Err(message) => {
                        // A pass is a sequence of chunks, not one
                        // transaction, so a failure may have left some days
                        // sealed and others not — and the counts on screen
                        // were computed before any of it. `reload` is what
                        // re-surveys them, and it is safe here because the
                        // pass is over: `migrating` is already back to false,
                        // so the effect it wakes does look at the rows.
                        status.set(Some(Status::Problem(message)));
                        reload.update(|n| *n += 1);
                        return;
                    }
                };
                // The pass has just surveyed every row in the account, so it
                // knows the new numbers exactly — better than a refetch
                // would, and without the third `entries_all()` a `reload`
                // bump would have cost. Nothing about the account's passkeys
                // changed here, which is the other thing `reload` refreshes.
                overview.update(|fetched| {
                    if let Fetched::Loaded(overview) = fetched {
                        overview.unencrypted_days = 0;
                        overview.unreadable_dates.clone_from(&done.unreadable);
                    }
                });
                if done.unreadable.is_empty() {
                    status.set(Some(Status::Note(match done.encrypted {
                        0 => "Everything is already encrypted.".to_string(),
                        count => format!("Encrypted {}.", days(count)),
                    })));
                    return;
                }
                // A row the pass could not read is the one outcome that
                // needs the user, so it is reported as a problem even when
                // the rest of the account went through — and by date,
                // because "look at these two days" is the only action
                // available to them.
                let encrypted = match done.encrypted {
                    0 => String::new(),
                    count => format!("Encrypted {}. ", days(count)),
                };
                status.set(Some(Status::Problem(format!(
                    "{encrypted}{} could not be read at all and stayed unencrypted: {}.",
                    days(done.unreadable.len()),
                    done.unreadable.join(", "),
                ))));
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
                let outcome = ceremony::begin_enable(&user).await;
                busy.set(false);
                match outcome {
                    Ok(pending) => {
                        let code = pending.recovery_code().to_string();
                        pending_enable.set_value(Some(pending));
                        mode.set(Mode::NewCode(code));
                    }
                    Err(message) => status.set(Some(Status::Problem(message))),
                }
            });
        }
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
                        // the keystore write lives behind that check, and
                        // because the migration below needs the key
                        // published first.
                        encryption.unlock(key).await;
                        run_migration();
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
                            CodeKind::New => confirm_new_code(),
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
                        on_migrate=run_migration
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
/// each other mid-migration — see [`Fetched`] — and a component rather than
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
#[component]
fn EnableSection(
    overview: RwSignal<Fetched>,
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
    let known = move || overview.get().loaded().is_some();
    let capable = move || {
        overview
            .get()
            .loaded()
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
                    "You're shown a recovery code, once, before encryption is switched on. \
                     Save it before you go on — it is never shown again."
                </li>
                <li>"Entries you've already saved are re-encrypted in place. Nothing is deleted."</li>
                <li>
                    "Adding another passkey afterwards takes three passkey prompts, unless you \
                     use your recovery code in place of one of them. That's a consequence of \
                     the key never leaving your authenticator in a copyable form, not a bug to \
                     be fixed later."
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
    overview: RwSignal<Fetched>,
    busy: RwSignal<bool>,
    on_lock: impl Fn() + Copy + Send + 'static,
    on_reissue: impl Fn() + Copy + Send + 'static,
    on_migrate: impl Fn() + Copy + Send + 'static,
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
                        // Named, not counted. This is the only thing on the
                        // panel the user has to go and look at by hand, and
                        // a bare number tells them nothing about where.
                        {(!overview.unreadable_dates.is_empty()).then(|| view! {
                            <p class="text-sm text-red-700 mb-2">
                                {format!(
                                    "{} could not be read at all, and nothing was changed \
                                     there: {}.",
                                    days(overview.unreadable_dates.len()),
                                    overview.unreadable_dates.join(", "),
                                )}
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
            until the new one is stored.",
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
    use super::{MigrationPlan, Overview, classify, pass_failed};
    use crate::crypto::flow::{self, PrfAssertion};
    use crate::crypto::{Enabled, Forgets, SessionKey, choose_route, enable};
    use crate::server_fns::encryption::{encryption_enable, encryption_wraps};
    use crate::server_fns::entries::entries_all;
    use crate::server_fns::passkey::passkey_list;
    use crate::storage::{Progress, WriteKey, store_many};

    /// What one refresh of the panel's overview should go and ask for.
    ///
    /// A named pair rather than two `bool` arguments, which a caller could
    /// swap without the compiler minding. They ask for very different
    /// amounts of data — a list of passkeys against every row in the account
    /// — so swapping them would either skip the wraps the panel classifies
    /// by, or pull the whole account down for nothing.
    #[derive(Clone, Copy)]
    pub struct Refresh {
        /// Whether the account is encrypted, and so whether its wraps are
        /// worth asking for at all.
        pub encrypted: bool,
        /// Whether to survey every row for un-migrated bodies. Skipped while
        /// a migration is running: that pass reads the same rows and reports
        /// better numbers a moment later, and enabling encryption starts
        /// both from one click.
        pub survey_entries: bool,
    }

    /// Fetches everything the panel reports on.
    ///
    /// `entries_all` is only called when the panel actually needs the count,
    /// and only because there is no server-side answer to "how many rows are
    /// still plaintext": producing one would mean the server parsing bodies,
    /// which invariant E1 forbids (see `dto::EncryptionStatus`).
    pub async fn load_overview(refresh: Refresh) -> Result<Overview, String> {
        let rows = passkey_list().await.map_err(flow::server_unreachable)?;
        let wraps = if refresh.encrypted {
            encryption_wraps().await.map_err(flow::server_unreachable)?
        } else {
            Vec::new()
        };
        let plan = if refresh.survey_entries {
            MigrationPlan::of(entries_all().await.map_err(flow::server_unreachable)?)
        } else {
            MigrationPlan::default()
        };

        Ok(Overview {
            routes: rows.into_iter().map(|row| classify(row, &wraps)).collect(),
            has_recovery_wrap: choose_route(&wraps, None).is_some(),
            unencrypted_days: plan.pending.len(),
            unreadable_dates: plan.unreadable,
        })
    }

    /// The enable ceremony, paused with the recovery code on screen.
    ///
    /// Everything the account needs already exists — a data key, both wraps,
    /// a code, and this device's keystore record — and the server still
    /// knows none of it, so the account is *not* encrypted. That gap is the
    /// point of the type: it holds the ceremony open across the one-time
    /// display of the code, so the user has saved it before the transaction
    /// that makes it their only backup.
    pub struct PendingEnable {
        enabled: Enabled,
        /// The credential that asserted, filed alongside its own wrap.
        credential_id: Vec<u8>,
    }

    impl PendingEnable {
        /// The code to show once, before committing to it.
        pub fn recovery_code(&self) -> &str {
            &self.enabled.recovery_code
        }
    }

    /// Everything turning encryption on does before the server hears about
    /// it: spec section 6.1's steps 1 to 3, plus step 6's keystore write,
    /// which `crypto::enable` performs on the way through (see its doc).
    ///
    /// Abandoning a `PendingEnable` — closing the tab on the code screen —
    /// costs nothing. `encrypted_at` is unset, so the next probe reports
    /// `Disabled`, the keystore record is never consulted, and the code the
    /// user may have saved simply opens nothing.
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

        let enabled = enable(&prf_output, user, forgets)
            .await
            .map_err(|_| "This browser couldn't generate an encryption key.".to_string())?;

        Ok(PendingEnable {
            enabled,
            credential_id,
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
            enabled,
            credential_id,
        } = pending;

        encryption_enable(enabled.passkey_wrap, credential_id, enabled.recovery_wrap)
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

        Ok(enabled.session_key)
    }

    /// What one migration pass did, and what it declined to touch.
    pub struct MigrationOutcome {
        /// How many days this pass re-wrote as v2.
        pub encrypted: usize,
        /// The dates it could not read, and so left exactly as they were.
        /// Carried out rather than dropped: this is the pass's only chance
        /// to tell anyone, and a later run will find the same rows and say
        /// the same thing to nobody.
        pub unreadable: Vec<String>,
    }

    /// Re-encrypts every row still stored as v1 (spec section 8), calling
    /// `progress` as it reaches each row.
    ///
    /// Through the storage seam's [`store_many`], not around it: `WriteKey`
    /// is what stops a session that cannot seal writing plaintext into an
    /// encrypted account, and a pass with a write path of its own would be
    /// the one place that guard did not apply (invariant E7).
    ///
    /// Resumable by construction, and by per-row dispatch rather than by
    /// atomicity: `store_many` sends the pass in chunks, so a run that stops
    /// partway leaves the chunks that landed sealed and fewer v1 rows for
    /// the next run to find. A v2 row is never re-sent — re-sealing one
    /// means decrypting it first, work with nothing to gain and data to
    /// lose. Rows this build cannot read at all are not sent either, for the
    /// same reason, and come back named in the outcome.
    pub async fn migrate(
        key: &SessionKey,
        progress: impl Fn(Progress),
    ) -> Result<MigrationOutcome, String> {
        let rows = entries_all().await.map_err(flow::server_unreachable)?;
        let plan = MigrationPlan::of(rows);
        let unreadable = plan.unreadable.clone();
        let encrypted = plan.pending.len();

        store_many(plan.into_rows(), WriteKey::Sealed(key), progress)
            .await
            .map_err(pass_failed)?;

        Ok(MigrationOutcome {
            encrypted,
            unreadable,
        })
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

    fn pending(date: &str, body: &str) -> PendingRow {
        PendingRow {
            date: parse_iso(date).expect("valid date"),
            body: body.to_string(),
        }
    }

    fn sealed_row(ciphertext: Vec<u8>) -> String {
        wire::encode_v2(&wire::Sealed {
            nonce: vec![0; wire::NONCE_LEN],
            ciphertext,
        })
    }

    /// The selection the migration acts on, and the count the panel reports
    /// from it. A v2 row re-sent through the pass would be decrypted and
    /// re-sealed for nothing, and a bug in that path destroys data — so
    /// "already encrypted" must be excluded, not merely harmless.
    #[test]
    fn only_plaintext_rows_are_pending() {
        let plan = MigrationPlan::of(vec![
            ("2026-09-01".to_string(), wrap_v1("morning")),
            ("2026-09-02".to_string(), sealed_row(vec![1, 2, 3])),
            ("2026-09-03".to_string(), wrap_v1("")),
        ]);

        assert_eq!(
            plan.pending,
            vec![
                pending("2026-09-01", "morning"),
                // An empty body is a real saved state, not an absence, and
                // leaving it as the account's one v1 row would keep the
                // panel reporting unfinished work forever.
                pending("2026-09-03", ""),
            ]
        );
        assert!(plan.unreadable.is_empty());
    }

    /// A row nobody can interpret is named, not dropped and not reduced to
    /// a number. Silently skipping it would leave it plaintext forever with
    /// nothing to say so, and a count would tell the user something is
    /// wrong without telling them where to look — the one outcome a
    /// one-shot migration cannot recover from on a later run.
    #[test]
    fn an_unreadable_row_is_reported_rather_than_skipped() {
        let plan = MigrationPlan::of(vec![
            ("2026-09-01".to_string(), "not an envelope".to_string()),
            (
                "2026-09-02".to_string(),
                r#"{"v":9,"alg":"future"}"#.to_string(),
            ),
            // A key this build cannot read as a date belongs in the same
            // list: sending it on would have `entry_save_many` refuse — and
            // roll back — the whole batch over the one row, so a readable
            // body under an unreadable date is still work the pass must
            // decline and name.
            ("not-a-date".to_string(), wrap_v1("stranded")),
            ("2026-09-03".to_string(), wrap_v1("real")),
        ]);

        assert_eq!(
            plan.unreadable,
            vec![
                "2026-09-01".to_string(),
                "2026-09-02".to_string(),
                "not-a-date".to_string()
            ]
        );
        assert_eq!(plan.pending, vec![pending("2026-09-03", "real")]);
    }

    /// Resumability at the boundary: an account with nothing left to do
    /// reports nothing to do, so the panel stops offering a pass that would
    /// re-write every row for no reason.
    /// The message a blocked account lives with. One body this build cannot
    /// seal stops the pass every time it runs — for good, since nothing
    /// retries differently — and the only remedy is a person opening that
    /// day. Naming it is the difference between an action and a shrug.
    #[test]
    fn a_seal_failure_names_the_day_it_stopped_on() {
        let message = pass_failed(StorageError::Crypto {
            key: StorageKey::TimeEntry(parse_iso("2026-09-04").expect("valid date")).as_key(),
            detail: "OperationError".to_string(),
        });
        assert!(
            message.contains("2026-09-04"),
            "the day is the only thing the user can act on: {message}"
        );
        assert!(
            !message.contains("nothing was changed"),
            "a chunked pass may already have sealed earlier days: {message}"
        );
    }

    /// A refusal the server explained is not a connection problem, and
    /// telling the user to check their network hides the sentence the server
    /// was trying to give them — "that's too many entries in one request" is
    /// not something a reconnect fixes.
    #[test]
    fn a_refusal_the_server_explained_is_repeated() {
        let refused: ServerFnError =
            ServerFnError::ServerError("That's too many entries in one request".to_string());
        let message = pass_failed(StorageError::Server(refused.to_string()));
        assert!(
            message.contains("too many entries"),
            "the server's own words must survive: {message}"
        );
        assert!(
            !message.contains("Check your connection"),
            "an answered request is not a connection failure: {message}"
        );
    }

    /// The complement, and the reason the two are told apart at all: a call
    /// that never landed has no sentence to repeat, so the connection hint
    /// is the useful thing left to say.
    #[test]
    fn a_call_that_never_landed_gets_the_connection_hint() {
        let dropped = pass_failed(StorageError::Server(
            "error reaching server to call server function: offline".to_string(),
        ));
        assert_eq!(dropped, crate::crypto::flow::SERVER_UNREACHABLE);
        assert_eq!(
            pass_failed(StorageError::Unavailable),
            crate::crypto::flow::SERVER_UNREACHABLE
        );
    }

    #[test]
    fn an_account_with_no_plaintext_rows_needs_no_work() {
        assert_eq!(MigrationPlan::of(Vec::new()), MigrationPlan::default());

        let plan = MigrationPlan::of(vec![("2026-09-01".to_string(), sealed_row(vec![4]))]);
        assert_eq!(plan, MigrationPlan::default());
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
            Screen::of(Mode::NewCode("K7M2".to_string()), unread),
            Screen::Code {
                code: "K7M2".to_string(),
                kind: CodeKind::New,
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
            ..Overview::default()
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
            ..Overview::default()
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
            ..Overview::default()
        };
        assert_eq!(Openers::of(&no_code), Openers::PasskeyOnly);

        let nothing = Overview {
            routes: vec![classify(passkey("New phone", b"cred-b", true), &wraps)],
            has_recovery_wrap: false,
            ..Overview::default()
        };
        assert_eq!(Openers::of(&nothing), Openers::Nothing);
        assert!(!Openers::of(&nothing).passkey());
        assert!(!Openers::of(&nothing).recovery());
    }

    /// The two cards say different things, and saying the wrong one is a
    /// lie the user cannot check: "your previous code no longer works" over
    /// a first code would send somebody looking for a code they never had.
    #[test]
    fn each_code_screen_carries_its_own_words() {
        assert!(CodeKind::New.confirm().contains("turning on encryption"));
        assert!(CodeKind::Reissued.intro().contains("no longer works"));
        assert!(!CodeKind::New.intro().contains("no longer works"));
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
                    overview=RwSignal::new(Fetched::Loaded(overview))
                    busy=RwSignal::new(false)
                    on_lock=|| {}
                    on_reissue=|| {}
                    on_migrate=|| {}
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
            ..Overview::default()
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
            ..Overview::default()
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
            ..Overview::default()
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
            ..Overview::default()
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

    /// And once the list *is* in and holds nothing usable, the panel says so
    /// rather than presenting a dead control with no explanation. The
    /// ceremony would fail at its first assertion, and "the button does
    /// nothing" is the least useful way to learn that.
    ///
    /// Ticked here too, and for the same reason: an unticked box would shut
    /// the button by itself and the `disabled` assertion would prove nothing
    /// about the capability check it is aimed at.
    #[cfg(feature = "ssr")]
    #[test]
    fn an_account_with_no_usable_passkey_is_told_why_it_cannot_enable() {
        let html = render_enable(
            Fetched::Loaded(Overview {
                routes: vec![classify(passkey("Old token", b"cred-c", false), &[])],
                ..Overview::default()
            }),
            true,
        );
        assert!(
            html.contains(r#"<button type="button" disabled"#),
            "an account with no capable passkey must not be offered the ceremony: {html}"
        );
        assert!(html.contains("Encryption needs a passkey that can hold a key"));

        let usable = render_enable(
            Fetched::Loaded(Overview {
                routes: vec![classify(passkey("Phone", b"cred-b", true), &[])],
                ..Overview::default()
            }),
            true,
        );
        assert!(
            !usable.contains("Encryption needs a passkey"),
            "an account that can enable must not be told it cannot"
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
                ..Overview::default()
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
                ..Overview::default()
            },
        );
        assert!(
            !present.contains("No recovery code is on file"),
            "an account that has one must not be told it does not"
        );
    }

    /// The other thing `Fetched` exists for: a failed refresh has a sentence
    /// of its own, and it renders beside `status` rather than inside it, so
    /// a migration's progress line and a refresh failure cannot paint over
    /// each other. Nothing rendered this branch before.
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

    /// Spec section 8's report, at the view. A row that failed to read is a
    /// one-time event with no automatic remedy: the pass will find it again
    /// and again and change nothing. So the panel names the days rather
    /// than counting them, which is the difference between the user being
    /// able to go and look and the user only knowing that something,
    /// somewhere, did not migrate.
    #[cfg(feature = "ssr")]
    #[test]
    fn unreadable_days_are_named_not_counted() {
        let html = render_manage(
            true,
            Overview {
                has_recovery_wrap: true,
                unreadable_dates: vec!["2026-09-01".to_string(), "2026-09-04".to_string()],
                ..Overview::default()
            },
        );
        assert!(html.contains("2 days could not be read"));
        for date in ["2026-09-01", "2026-09-04"] {
            assert!(html.contains(date), "`{date}` was reduced to a count");
        }
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
