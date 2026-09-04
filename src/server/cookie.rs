//! Shared `Set-Cookie` construction.
//!
//! One shape for both cookies this app sets: `Path=/`, `HttpOnly`,
//! `SameSite=Lax`, and `Secure` outside debug builds. Pass an empty value
//! with `max_age = 0` to clear.

/// Builds an `HttpOnly; SameSite=Lax` cookie header scoped to `Path=/`.
pub fn http_only(name: &str, value: &str, max_age: i64) -> String {
    let secure = if cfg!(debug_assertions) {
        ""
    } else {
        "; Secure"
    };
    format!("{name}={value}; Path=/; HttpOnly; SameSite=Lax{secure}; Max-Age={max_age}")
}

#[cfg(test)]
mod tests {
    use super::http_only;

    /// `Secure` is build-mode dependent, so assert it against the same cfg
    /// the helper uses rather than hardcoding one build's answer.
    fn secure_suffix() -> &'static str {
        if cfg!(debug_assertions) {
            ""
        } else {
            "; Secure"
        }
    }

    #[test]
    fn sets_a_session_cookie() {
        assert_eq!(
            http_only("tt_session", "abc", 2_592_000),
            format!(
                "tt_session=abc; Path=/; HttpOnly; SameSite=Lax{}; Max-Age=2592000",
                secure_suffix()
            )
        );
    }

    #[test]
    fn clears_with_an_empty_value_and_zero_age() {
        assert_eq!(
            http_only("tt_session", "", 0),
            format!(
                "tt_session=; Path=/; HttpOnly; SameSite=Lax{}; Max-Age=0",
                secure_suffix()
            )
        );
    }
}
