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

/// An SMTP relay, built once at startup and cloned per request. STARTTLS by
/// default; plaintext only where `SMTP_INSECURE` explicitly asks for it.
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

/// How the SMTP connection is protected.
///
/// A local mail catcher — Mailpit, MailHog — speaks no TLS at all, so a
/// STARTTLS transport cannot talk to it: the connection dies at "STARTTLS is
/// not supported on this server" before a message is ever offered.
/// `Plaintext` exists for exactly that case and nothing else. Against a real
/// relay it puts the AUTH credentials on the wire in the clear.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SmtpSecurity {
    StartTls,
    Plaintext,
}

impl SmtpSecurity {
    /// Reads the posture from a raw `SMTP_INSECURE` value.
    ///
    /// Only `1` and `true` opt out of TLS, ignoring case and surrounding
    /// whitespace. Everything else keeps STARTTLS — including plausible
    /// near-misses like `yes` and `on`, so that no typo can quietly downgrade
    /// a production relay. Failing closed is the whole point: the cost of
    /// rejecting `yes` is one confused developer, and the cost of accepting a
    /// typo is credentials in cleartext.
    fn from_env_value(raw: Option<&str>) -> Self {
        match raw.map(|v| v.trim().to_ascii_lowercase()).as_deref() {
            Some("1" | "true") => Self::Plaintext,
            _ => Self::StartTls,
        }
    }
}

/// Everything `SmtpMailer` needs, separated from where it came from so a test
/// can build a transport without mutating the process environment.
struct SmtpSettings {
    host: String,
    port: u16,
    user: String,
    pass: String,
    from: String,
    security: SmtpSecurity,
}

impl SmtpSettings {
    fn from_env() -> Option<Self> {
        let insecure = std::env::var("SMTP_INSECURE").ok();
        Some(Self {
            host: std::env::var("SMTP_HOST").ok().filter(|s| !s.is_empty())?,
            port: std::env::var("SMTP_PORT")
                .ok()
                .and_then(|p| p.parse().ok())
                .unwrap_or(587),
            user: std::env::var("SMTP_USER").ok().filter(|s| !s.is_empty())?,
            pass: std::env::var("SMTP_PASS").ok().filter(|s| !s.is_empty())?,
            from: std::env::var("SMTP_FROM").ok().filter(|s| !s.is_empty())?,
            security: SmtpSecurity::from_env_value(insecure.as_deref()),
        })
    }
}

impl SmtpMailer {
    fn from_env() -> Option<Self> {
        Self::new(SmtpSettings::from_env()?)
    }

    fn new(settings: SmtpSettings) -> Option<Self> {
        use lettre::transport::smtp::authentication::Credentials;

        let builder = match settings.security {
            SmtpSecurity::StartTls => {
                lettre::AsyncSmtpTransport::<lettre::Tokio1Executor>::starttls_relay(&settings.host)
                    .ok()?
            }
            SmtpSecurity::Plaintext => {
                tracing::warn!(
                    host = %settings.host,
                    port = settings.port,
                    "SMTP_INSECURE is set: connecting without TLS. Credentials will \
                     cross the network in the clear — local mail catchers only."
                );
                lettre::AsyncSmtpTransport::<lettre::Tokio1Executor>::builder_dangerous(
                    &settings.host,
                )
            }
        };

        let transport = builder
            .port(settings.port)
            .credentials(Credentials::new(settings.user, settings.pass))
            .build();
        Some(Self {
            from: settings.from,
            transport,
        })
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

    /// `SMTP_INSECURE` fails closed. Only the two documented spellings turn
    /// TLS off; a typo leaves a production relay encrypted.
    #[test]
    fn only_1_and_true_disable_tls() {
        for on in ["1", "true", "TRUE", "  True  "] {
            assert_eq!(
                SmtpSecurity::from_env_value(Some(on)),
                SmtpSecurity::Plaintext,
                "{on:?} should disable TLS"
            );
        }
        for off in ["0", "false", "yes", "on", "ture", ""] {
            assert_eq!(
                SmtpSecurity::from_env_value(Some(off)),
                SmtpSecurity::StartTls,
                "{off:?} must not disable TLS"
            );
        }
        assert_eq!(
            SmtpSecurity::from_env_value(None),
            SmtpSecurity::StartTls,
            "an unset variable must not disable TLS"
        );
    }

    /// A single-connection SMTP server that speaks just enough of the protocol
    /// to accept one message, and that advertises **no STARTTLS**. That
    /// omission is the point: it is the shape of a local mail catcher, and the
    /// reason `SMTP_INSECURE` has to exist at all.
    ///
    /// Returns the port it listens on and the commands it received. Blocking
    /// std sockets on their own thread, so the test needs no extra tokio
    /// features and cannot deadlock the runtime driving lettre.
    fn spawn_smtp_stub() -> (u16, Arc<Mutex<Vec<String>>>) {
        use std::io::{BufRead, BufReader, Write};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind stub");
        let port = listener.local_addr().expect("stub address").port();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let recorder = Arc::clone(&seen);

        std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            let mut out = stream.try_clone().expect("clone stream");
            let mut reader = BufReader::new(stream);
            let mut in_data = false;
            let mut line = String::new();

            out.write_all(b"220 stub ESMTP\r\n").expect("greeting");
            loop {
                line.clear();
                if reader.read_line(&mut line).unwrap_or(0) == 0 {
                    break;
                }
                let command = line.trim_end_matches(['\r', '\n']).to_string();

                if in_data {
                    // Message body — everything up to the lone dot.
                    if command == "." {
                        in_data = false;
                        let _ = out.write_all(b"250 2.0.0 queued\r\n");
                    }
                    continue;
                }

                let upper = command.to_ascii_uppercase();
                recorder
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .push(command);

                let reply: &[u8] = if upper.starts_with("EHLO") || upper.starts_with("HELO") {
                    // Note what is absent: no `250-STARTTLS`.
                    b"250-stub\r\n250-AUTH PLAIN LOGIN\r\n250 8BITMIME\r\n"
                } else if upper.starts_with("AUTH") {
                    b"235 2.7.0 authenticated\r\n"
                } else if upper.starts_with("DATA") {
                    in_data = true;
                    b"354 go ahead\r\n"
                } else if upper.starts_with("QUIT") {
                    let _ = out.write_all(b"221 2.0.0 bye\r\n");
                    break;
                } else {
                    b"250 2.0.0 ok\r\n"
                };
                if out.write_all(reply).is_err() {
                    break;
                }
            }
        });

        (port, seen)
    }

    fn stub_settings(port: u16, security: SmtpSecurity) -> SmtpSettings {
        SmtpSettings {
            host: "127.0.0.1".into(),
            port,
            user: "dev".into(),
            pass: "dev".into(),
            from: "Dev <dev@example.com>".into(),
            security,
        }
    }

    fn sample_email() -> OutboundEmail {
        OutboundEmail {
            to: "alice@example.com".into(),
            subject: "sign in".into(),
            text: "link".into(),
            html: None,
        }
    }

    /// The regression this exists for: against a catcher with no TLS, the
    /// default transport cannot deliver at all.
    #[tokio::test]
    async fn starttls_cannot_reach_a_catcher_that_offers_no_starttls() {
        let (port, _seen) = spawn_smtp_stub();
        let mailer =
            SmtpMailer::new(stub_settings(port, SmtpSecurity::StartTls)).expect("build transport");

        let err = mailer
            .send(sample_email())
            .await
            .expect_err("a STARTTLS transport must refuse a server without it");
        assert!(
            err.to_string().to_lowercase().contains("starttls"),
            "expected a STARTTLS failure, got: {err}"
        );
    }

    /// …and with `SMTP_INSECURE` the same catcher receives the message,
    /// credentials and all.
    #[tokio::test]
    async fn plaintext_delivers_to_a_catcher_that_offers_no_starttls() {
        let (port, seen) = spawn_smtp_stub();
        let mailer =
            SmtpMailer::new(stub_settings(port, SmtpSecurity::Plaintext)).expect("build transport");

        mailer.send(sample_email()).await.expect("plaintext send");

        let commands = seen.lock().unwrap_or_else(|p| p.into_inner()).clone();
        let starts_with = |prefix: &str| {
            commands
                .iter()
                .any(|c| c.to_ascii_uppercase().starts_with(prefix))
        };
        assert!(
            starts_with("AUTH"),
            "credentials must still be offered on the plaintext transport: {commands:?}"
        );
        assert!(
            starts_with("DATA"),
            "the message must reach the catcher: {commands:?}"
        );
    }
}
