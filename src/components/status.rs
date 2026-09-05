//! The one line a page talks back through, and how loud it is.

/// Something a ceremony has to say, and whether it went well.
///
/// Two variants rather than a bare `String` because the severity has to
/// reach the styling, and every ceremony these pages run can half-finish: a
/// passkey enrolled with no unlock key, a lock whose keystore clear failed,
/// a deletion the server refused because it was the last thing that could
/// open the account. A failure rendered in the same muted grey as "Passkey
/// renamed." is a failure the user scrolls past.
///
/// Shared by `/account`'s two halves — the passkey list and the encryption
/// panel — because the same refusal can arrive at either, and a message that
/// reads as an aside on one and as an alarm on the other would be reporting
/// the same fact two different ways.
#[derive(Clone)]
pub enum Status {
    /// Something worked, or is under way.
    Note(String),
    /// Something did not.
    Problem(String),
}

impl Status {
    pub fn message(&self) -> &str {
        match self {
            Status::Note(message) | Status::Problem(message) => message,
        }
    }

    /// The classes that carry the severity, and only those.
    ///
    /// Layout is the caller's, because the two callers put this line in
    /// different places: the encryption panel above the screen it belongs
    /// to, the passkey list below the controls that produced it.
    pub fn tone(&self) -> &'static str {
        match self {
            Status::Note(_) => "text-sm text-gray-600",
            Status::Problem(_) => "text-sm text-red-700",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The reason this is an enum and not a `String`. Spec section 6.6's
    /// refusal — "that is the last passkey that can unlock your entries" —
    /// is the message it was invented for, and a refusal rendered in the
    /// same muted grey as "Passkey renamed." is one the user scrolls past
    /// and then tries again.
    #[test]
    fn a_problem_does_not_look_like_a_note() {
        let note = Status::Note("Passkey renamed.".to_string());
        let problem = Status::Problem("That is your last unlock route.".to_string());
        assert_ne!(note.tone(), problem.tone());
        assert!(
            problem.tone().contains("red"),
            "a refusal must read as one: {}",
            problem.tone()
        );
    }

    /// Layout is the caller's, and stays that way: the two callers put this
    /// line above and below their content respectively, so a margin baked in
    /// here would be wrong for one of them.
    #[test]
    fn the_tone_carries_no_layout() {
        for status in [
            Status::Note("x".to_string()),
            Status::Problem("x".to_string()),
        ] {
            let tone = status.tone();
            assert!(
                !tone.contains("mb-") && !tone.contains("mt-"),
                "`{tone}` decides spacing its callers disagree about"
            );
        }
    }
}
