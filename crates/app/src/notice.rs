//! The one notification of the application: the sign-in has ended and has to be repeated.

use std::sync::atomic::{AtomicBool, Ordering};

use im_core::Platform;
use im_core::session::SessionView;
use tauri::{AppHandle, Runtime};
use tauri_plugin_notification::NotificationExt;
use url::Url;

const TITLE: &str = "Sign in again";

/// Shows a notification of the system.
pub trait Notifier: Send + Sync {
    fn notify(&self, title: &str, body: &str) -> Result<(), String>;
}

pub struct SystemNotifier<R: Runtime>(AppHandle<R>);

impl<R: Runtime> SystemNotifier<R> {
    pub fn new(app: &AppHandle<R>) -> Self {
        Self(app.clone())
    }
}

impl<R: Runtime> Notifier for SystemNotifier<R> {
    fn notify(&self, title: &str, body: &str) -> Result<(), String> {
        self.0
            .notification()
            .builder()
            .title(title)
            .body(body)
            .show()
            .map_err(|error| error.to_string())
    }
}

/// Says nothing: for the self-check and for tests that do not look at notifications.
pub struct Silent;

impl Notifier for Silent {
    fn notify(&self, _title: &str, _body: &str) -> Result<(), String> {
        Ok(())
    }
}

/// Sends the notification once for each sign-in that ends.
pub struct Notices {
    notifier: Box<dyn Notifier>,
    platform: Platform,
    sent: AtomicBool,
}

fn host(address: &str) -> String {
    Url::parse(address)
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned))
        .unwrap_or_else(|| address.to_owned())
}

fn body(host: &str, platform: Platform) -> String {
    let place = if platform == Platform::Macos {
        "the menu bar"
    } else {
        "the notification area"
    };
    format!("Your sign-in to {host} has ended. Use Identity Manager in {place} to sign in again.")
}

impl Notices {
    pub fn new(notifier: Box<dyn Notifier>, platform: Platform) -> Self {
        Self {
            notifier,
            platform,
            sent: AtomicBool::new(false),
        }
    }

    /// Takes each view the session reports.
    pub fn view(&self, view: &SessionView) {
        let SessionView::SignedOut {
            again: true,
            address,
            ..
        } = view
        else {
            self.sent.store(false, Ordering::SeqCst);
            return;
        };
        if self.sent.swap(true, Ordering::SeqCst) {
            return;
        }
        let host = host(address.as_deref().unwrap_or("ILM"));
        match self.notifier.notify(TITLE, &body(&host, self.platform)) {
            Ok(()) => log::info!("notified that the sign-in has ended"),
            Err(error) => log::warn!("the notification could not be shown: {error}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct Sent(Mutex<Vec<(String, String)>>);

    impl Notifier for Arc<Sent> {
        fn notify(&self, title: &str, body: &str) -> Result<(), String> {
            self.0
                .lock()
                .unwrap()
                .push((title.to_owned(), body.to_owned()));
            Ok(())
        }
    }

    struct Failing;

    impl Notifier for Failing {
        fn notify(&self, _: &str, _: &str) -> Result<(), String> {
            Err("no notification service".to_owned())
        }
    }

    fn ended() -> SessionView {
        SessionView::SignedOut {
            address: Some("https://ilm.example.com/prefix".to_owned()),
            locked: false,
            problem: Some("The sign-in has ended.".to_owned()),
            again: true,
        }
    }

    fn signed_out() -> SessionView {
        SessionView::SignedOut {
            address: Some("https://ilm.example.com".to_owned()),
            locked: false,
            problem: None,
            again: false,
        }
    }

    fn notices(platform: Platform) -> (Notices, Arc<Sent>) {
        let sent = Arc::new(Sent::default());
        (Notices::new(Box::new(sent.clone()), platform), sent)
    }

    #[test]
    fn an_ended_sign_in_is_announced_once_with_the_host() {
        let (notices, sent) = notices(Platform::Macos);

        notices.view(&ended());
        notices.view(&ended());

        assert_eq!(
            *sent.0.lock().unwrap(),
            [(
                "Sign in again".to_owned(),
                "Your sign-in to ilm.example.com has ended. Use Identity Manager in the menu bar to sign in again."
                    .to_owned()
            )]
        );
    }

    #[test]
    fn the_next_ended_sign_in_is_announced_again() {
        let (notices, sent) = notices(Platform::Windows);

        notices.view(&ended());
        notices.view(&SessionView::Starting);
        notices.view(&ended());

        let sent = sent.0.lock().unwrap();
        assert_eq!(sent.len(), 2);
        assert!(
            sent[0]
                .1
                .ends_with("in the notification area to sign in again.")
        );
    }

    #[test]
    fn a_sign_out_by_the_person_is_not_announced() {
        let (notices, sent) = notices(Platform::Linux);

        notices.view(&signed_out());
        notices.view(&SessionView::Locked {});

        assert!(sent.0.lock().unwrap().is_empty());
    }

    #[test]
    fn a_notification_that_fails_is_only_logged() {
        let notices = Notices::new(Box::new(Failing), Platform::Linux);

        notices.view(&ended());
    }

    #[test]
    fn the_host_falls_back_to_what_it_was_given() {
        assert_eq!(host("https://ilm.example.com:8443/x"), "ilm.example.com");
        assert_eq!(host("not an address"), "not an address");
    }
}
