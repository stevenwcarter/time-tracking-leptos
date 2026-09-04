//! Outbound email. Task 10 replaces this stub with the real transports.

#[derive(Clone)]
pub enum Mailer {
    Disabled,
}

impl Mailer {
    pub fn from_env() -> Self {
        Mailer::Disabled
    }
}
