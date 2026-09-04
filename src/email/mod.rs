//! Outbound email.
//!
//! Three transports: `Smtp` for production, `Capture` so tests can assert on
//! a message without a relay, and `Disabled` for a development run with no
//! SMTP configured — which logs the link instead of sending it.
//!
//! There is deliberately **no durable outbox**. photo365 has one (a table, a
//! worker, exponential backoff) because it sends order notifications that
//! must not be lost. This app sends exactly one kind of message, a sign-in
//! link that expires in fifteen minutes and that the user can re-request by
//! clicking a button. Retry machinery would cost more than it buys.
//! Sends are `tokio::spawn`ed by the caller so a slow relay never parks a
//! request.

use std::sync::{Arc, Mutex};

/// A message ready to send, independent of transport.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutboundEmail {
    pub to: String,
    pub subject: String,
    pub text: String,
    pub html: Option<String>,
}

/// Records sent messages in memory instead of relaying them, for tests.
#[derive(Clone, Default)]
pub struct CaptureMailer {
    sent: Arc<Mutex<Vec<OutboundEmail>>>,
}

/// A STARTTLS SMTP relay, built once at startup and cloned per request.
#[derive(Clone)]
pub struct SmtpMailer {
    from: String,
    transport: lettre::AsyncSmtpTransport<lettre::Tokio1Executor>,
}

/// The outbound-email transport in effect for this process.
#[derive(Clone)]
pub enum Mailer {
    Smtp(SmtpMailer),
    Capture(CaptureMailer),
    /// No SMTP configured. Sends log the message and succeed.
    Disabled,
}

impl Mailer {
    /// Builds the production transport, or `Disabled` when `SMTP_HOST` is
    /// unset. Unset is a supported development mode, not an error.
    pub fn from_env() -> Self {
        match SmtpMailer::from_env() {
            Some(m) => Mailer::Smtp(m),
            None => {
                tracing::warn!("SMTP_HOST is unset; magic links will be logged, not emailed");
                Mailer::Disabled
            }
        }
    }

    pub fn capture() -> Self {
        Mailer::Capture(CaptureMailer::default())
    }

    pub async fn send(&self, email: OutboundEmail) -> anyhow::Result<()> {
        match self {
            Mailer::Smtp(m) => m.send(email).await,
            Mailer::Capture(m) => {
                m.sent.lock().unwrap_or_else(|p| p.into_inner()).push(email);
                Ok(())
            }
            Mailer::Disabled => {
                tracing::info!(to = %email.to, "email not sent (no SMTP configured):\n{}", email.text);
                Ok(())
            }
        }
    }

    /// Test support: read back what `Capture` recorded. Empty for the other
    /// variants — meaningless outside tests, so callers never need to
    /// `match` on it.
    pub fn captured(&self) -> Vec<OutboundEmail> {
        match self {
            Mailer::Capture(m) => m.sent.lock().unwrap_or_else(|p| p.into_inner()).clone(),
            _ => Vec::new(),
        }
    }
}

impl SmtpMailer {
    fn from_env() -> Option<Self> {
        use lettre::transport::smtp::authentication::Credentials;

        let host = std::env::var("SMTP_HOST").ok().filter(|s| !s.is_empty())?;
        let port = std::env::var("SMTP_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(587);
        let user = std::env::var("SMTP_USER").ok().filter(|s| !s.is_empty())?;
        let pass = std::env::var("SMTP_PASS").ok().filter(|s| !s.is_empty())?;
        let from = std::env::var("SMTP_FROM").ok().filter(|s| !s.is_empty())?;

        let transport = lettre::AsyncSmtpTransport::<lettre::Tokio1Executor>::starttls_relay(&host)
            .ok()?
            .port(port)
            .credentials(Credentials::new(user, pass))
            .build();
        Some(Self { from, transport })
    }

    async fn send(&self, email: OutboundEmail) -> anyhow::Result<()> {
        use lettre::AsyncTransport;
        use lettre::message::{MultiPart, SinglePart, header};

        let builder = lettre::Message::builder()
            .from(self.from.parse()?)
            .to(email.to.parse()?)
            .subject(&email.subject);

        let message = match email.html {
            Some(html) => builder.multipart(MultiPart::alternative_plain_html(email.text, html))?,
            None => builder.singlepart(
                SinglePart::builder()
                    .header(header::ContentType::TEXT_PLAIN)
                    .body(email.text),
            )?,
        };
        self.transport.send(message).await?;
        Ok(())
    }
}

/// The absolute base the magic-link URL is built from.
pub fn site_base_url() -> String {
    std::env::var("SITE_BASE_URL").unwrap_or_else(|_| "http://localhost:3000".to_string())
}

/// The sign-in email's plain-text and HTML bodies.
pub fn magic_link_email(url: &str, ttl_seconds: i64) -> (String, String) {
    let minutes = ttl_seconds / 60;
    let text = format!(
        "Here's your sign-in link for Time Tracker:\n\n  {url}\n\n\
         It expires in {minutes} minutes and can only be used once.\n\n\
         If you didn't request this, you can ignore this email.\n"
    );
    let html = format!(
        "<p>Here's your sign-in link for Time Tracker:</p>\
         <p><a href=\"{url}\">{url}</a></p>\
         <p>It expires in {minutes} minutes and can only be used once.</p>\
         <p>If you didn't request this, you can ignore this email.</p>"
    );
    (text, html)
}

/// Partially hides an address for display on the "check your email" screen.
/// Display-only — not a security control.
pub fn mask(email: &str) -> String {
    let Some((local, domain)) = email.split_once('@') else {
        return "•••".to_string();
    };
    if local.chars().count() <= 2 {
        return format!("•••@{domain}");
    }
    let head: String = local.chars().take(3).collect();
    format!("{head}•••@{domain}")
}

#[cfg(all(test, feature = "ssr"))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn capture_records_what_was_sent() {
        let mailer = Mailer::capture();
        mailer
            .send(OutboundEmail {
                to: "alice@example.com".into(),
                subject: "hi".into(),
                text: "body".into(),
                html: None,
            })
            .await
            .expect("capture send");
        let got = mailer.captured();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].to, "alice@example.com");
    }

    /// An unconfigured mailer must be a loud no-op, not an error that fails
    /// the sign-in request. Development runs this way by design.
    #[tokio::test]
    async fn disabled_send_succeeds_and_records_nothing() {
        let mailer = Mailer::Disabled;
        assert!(
            mailer
                .send(OutboundEmail {
                    to: "alice@example.com".into(),
                    subject: "hi".into(),
                    text: "body".into(),
                    html: None,
                })
                .await
                .is_ok()
        );
        assert!(mailer.captured().is_empty());
    }

    #[test]
    fn magic_link_email_contains_the_url_in_both_parts() {
        let (text, html) = magic_link_email("https://example.test/magic/abc", 900);
        assert!(text.contains("https://example.test/magic/abc"));
        assert!(html.contains("https://example.test/magic/abc"));
        assert!(text.contains("15 minutes"), "TTL must be stated in minutes");
    }

    /// The "check your email" screen echoes the address back. Masking keeps
    /// a shoulder-surfer from reading a full address off the screen while
    /// still letting the user confirm they typed the right one.
    #[test]
    fn masks_an_address_for_display() {
        assert_eq!(mask("alice@example.com"), "ali•••@example.com");
        assert_eq!(mask("ab@example.com"), "•••@example.com");
        assert_eq!(mask("not-an-address"), "•••");
    }
}
