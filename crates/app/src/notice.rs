//! The notifications of the application: the sign-in has ended and has to be repeated, and a certificate starts
//! expiring, has expired or was revoked in ILM.

use std::io::ErrorKind;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, PoisonError};

use im_core::Platform;
use im_core::identity::Fingerprint;
use im_core::inventory::{Item, Kind as Attention, Summary};
use im_core::session::SessionView;
use im_core::settings::store::write_atomically;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Runtime};
use tauri_plugin_notification::NotificationExt;
use url::Url;

use crate::local_time::date;

const TITLE: &str = "Sign in again";
/// Where the notifications already sent are remembered, in the folder of the settings.
const FILE: &str = "notified.json";
const VERSION: u32 = 1;
/// How many certificates are announced one by one when nothing has been announced before.
const FIRST_RUN_LIMIT: usize = 3;

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

/// What a certificate notification is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
enum Kind {
    Expiring,
    Expired,
    Revoked,
}

impl Kind {
    /// What the log says: the kind only.
    fn label(self) -> &'static str {
        match self {
            Kind::Expiring => "expiring",
            Kind::Expired => "expired",
            Kind::Revoked => "revoked",
        }
    }
}

/// One notification that was sent: a certificate and what it was told about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
struct Sent {
    fingerprint: Fingerprint,
    kind: Kind,
}

/// The content of `notified.json`.
#[derive(Serialize, Deserialize)]
struct Remembered {
    version: u32,
    sent: Vec<Sent>,
}

/// Sends the notification once for each sign-in that ends, and one for each certificate and kind of attention.
pub struct Notices {
    notifier: Box<dyn Notifier>,
    platform: Platform,
    sent: AtomicBool,
    file: PathBuf,
    /// What was sent, read from the file at the first summary.
    remembered: Mutex<Option<Vec<Sent>>>,
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

/// The notification of an item that has a certificate, with what it is remembered by.
fn certificate_notice(item: &Item) -> Option<(Sent, &'static str, String)> {
    let fingerprint = item.fingerprint?;
    let name = &item.name;
    let (kind, title, body) = match item.kind {
        Attention::Expiring { on, .. } => (
            Kind::Expiring,
            "Certificate expires soon",
            format!("{name} expires on {}.", date(on)),
        ),
        Attention::Expired { on } => (
            Kind::Expired,
            "Certificate expired",
            format!("{name} expired on {}.", date(on)),
        ),
        Attention::Revoked => (
            Kind::Revoked,
            "Certificate revoked",
            format!("{name} was revoked in ILM."),
        ),
        Attention::NotInIlm { .. } => return None,
    };
    Some((Sent { fingerprint, kind }, title, body))
}

fn more(count: usize) -> String {
    if count == 1 {
        "1 more certificate needs attention.".to_owned()
    } else {
        format!("{count} more certificates need attention.")
    }
}

impl Notices {
    /// `folder` holds the file that remembers what was sent.
    pub fn new(notifier: Box<dyn Notifier>, platform: Platform, folder: PathBuf) -> Self {
        Self {
            notifier,
            platform,
            sent: AtomicBool::new(false),
            file: folder.join(FILE),
            remembered: Mutex::new(None),
        }
    }

    fn show(&self, title: &str, body: &str, kind: &str) {
        match self.notifier.notify(title, body) {
            Ok(()) => log::info!("notification sent ({kind})"),
            Err(error) => log::warn!("the notification could not be shown: {error}"),
        }
    }

    /// Tells the person about each certificate in `summary` that starts expiring, has expired or was revoked, once
    /// for each kind, also after a restart. What was told about a certificate is forgotten only when it is not among
    /// the `local` certificates of this computer any more. When nothing has been sent yet, only the first few are
    /// told and the others are counted in one notification.
    /// `current` is asked once the record is held: when `summary` has been superseded, nothing changes. `may_tell`
    /// is asked before each notification; at the first no, telling stops, and only what was told is
    /// remembered.
    pub fn summary(
        &self,
        summary: &Summary,
        local: &[Fingerprint],
        current: impl Fn() -> bool,
        may_tell: impl Fn() -> bool,
    ) {
        let notices: Vec<_> = summary
            .attention
            .iter()
            .filter_map(certificate_notice)
            .filter(|(entry, ..)| local.contains(&entry.fingerprint))
            .collect();
        let mut remembered = self
            .remembered
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if !current() {
            return;
        }
        let held = remembered.get_or_insert_with(|| self.load());
        let mut kept = held.clone();
        kept.retain(|entry| local.contains(&entry.fingerprint));
        let pruned = kept.len() != held.len();
        let first = kept.is_empty();
        let fresh: Vec<_> = notices
            .iter()
            .filter(|(entry, ..)| !kept.contains(entry))
            .collect();
        let told = if first {
            FIRST_RUN_LIMIT.min(fresh.len())
        } else {
            fresh.len()
        };
        let mut complete = true;
        for (entry, title, body) in &fresh[..told] {
            if !may_tell() {
                complete = false;
                break;
            }
            self.show(title, body, entry.kind.label());
            kept.push(*entry);
        }
        if complete && told < fresh.len() && may_tell() {
            self.show(
                "Certificates need attention",
                &more(fresh.len() - told),
                "more",
            );
            kept.extend(fresh[told..].iter().map(|(entry, ..)| *entry));
        }
        if pruned || kept.len() != held.len() {
            *held = kept;
            self.save(held);
        }
    }

    /// Forgets what was sent, as a sign-out does: the next person is told again.
    pub fn forget(&self) {
        *self
            .remembered
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = None;
        if let Err(error) = std::fs::remove_file(&self.file)
            && error.kind() != ErrorKind::NotFound
        {
            log::warn!("the record of notifications could not be deleted: {error}");
        }
    }

    fn load(&self) -> Vec<Sent> {
        let text = match std::fs::read_to_string(&self.file) {
            Ok(text) => text,
            Err(error) => {
                if error.kind() != ErrorKind::NotFound {
                    log::warn!("the record of notifications could not be read: {error}");
                }
                return Vec::new();
            }
        };
        match serde_json::from_str::<Remembered>(&text) {
            Ok(file) if file.version == VERSION => file.sent,
            _ => {
                log::warn!("the record of notifications is not readable and is replaced");
                Vec::new()
            }
        }
    }

    fn save(&self, sent: &[Sent]) {
        let file = Remembered {
            version: VERSION,
            sent: sent.to_vec(),
        };
        let written = serde_json::to_string_pretty(&file)
            .map_err(std::io::Error::other)
            .and_then(|text| write_atomically(&self.file, &text));
        if let Err(error) = written {
            log::warn!("the record of notifications could not be saved: {error}");
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

    /// What was shown, and the folder of the record while the test runs.
    #[derive(Default)]
    struct Log(Mutex<Vec<(String, String)>>, Option<tempfile::TempDir>);

    impl Notifier for Arc<Log> {
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

    fn notices(platform: Platform) -> (Notices, Arc<Log>) {
        let folder = tempfile::tempdir().unwrap();
        let sent = Arc::new(Log(Mutex::default(), Some(folder)));
        let path = sent.1.as_ref().unwrap().path().to_owned();
        (Notices::new(Box::new(sent.clone()), platform, path), sent)
    }

    fn notices_in(folder: PathBuf, platform: Platform) -> (Notices, Arc<Log>) {
        let sent = Arc::new(Log::default());
        (Notices::new(Box::new(sent.clone()), platform, folder), sent)
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
        let notices = Notices::new(Box::new(Failing), Platform::Linux, PathBuf::new());

        notices.view(&ended());
    }

    #[test]
    fn the_host_falls_back_to_what_it_was_given() {
        assert_eq!(host("https://ilm.example.com:8443/x"), "ilm.example.com");
        assert_eq!(host("not an address"), "not an address");
    }

    use im_core::inventory::Counts;

    const DAY: i64 = 86_400_000;
    /// 3 December 2026, 11:00 UTC: the same date in nearly every time zone.
    const DEC_3: i64 = 1_796_256_000_000 + 11 * 3_600_000;

    fn item(name: &str, number: u8, kind: Attention) -> Item {
        Item {
            kind,
            fingerprint: Some(Fingerprint::of(&[number])),
            name: name.to_owned(),
        }
    }

    /// The fingerprints of the certificates `1..=count` on this computer.
    fn on_computer(count: u8) -> Vec<Fingerprint> {
        (1..=count)
            .map(|number| Fingerprint::of(&[number]))
            .collect()
    }

    fn expiring(name: &str, number: u8) -> Item {
        item(name, number, Attention::Expiring { days: 5, on: DEC_3 })
    }

    fn summary(attention: Vec<Item>) -> Summary {
        Summary {
            computed_at: DEC_3 - 5 * DAY,
            checked_at: Some(DEC_3 - 5 * DAY),
            listed: true,
            counts: Counts {
                valid: 0,
                expiring: 0,
                expired: 0,
                not_in_ilm: None,
            },
            attention,
            months: [0; 12],
        }
    }

    fn told(log: &Log) -> Vec<(String, String)> {
        std::mem::take(&mut *log.0.lock().unwrap())
    }

    fn pair(title: &str, body: &str) -> (String, String) {
        (title.to_owned(), body.to_owned())
    }

    #[test]
    fn each_kind_is_told_with_its_title_and_the_date_in_the_local_zone() {
        let (notices, log) = notices(Platform::Macos);
        let all = summary(vec![
            item("Revoked one", 1, Attention::Revoked),
            item("Old one", 2, Attention::Expired { on: DEC_3 - DAY }),
            expiring("Soon one", 3),
        ]);

        notices.summary(&all, &on_computer(3), || true, || true);

        assert_eq!(
            told(&log),
            [
                pair("Certificate revoked", "Revoked one was revoked in ILM."),
                pair("Certificate expired", "Old one expired on 2 Dec 2026."),
                pair(
                    "Certificate expires soon",
                    "Soon one expires on 3 Dec 2026."
                ),
            ]
        );
    }

    #[test]
    fn nothing_is_told_or_remembered_while_telling_is_not_allowed() {
        let folder = tempfile::tempdir().unwrap();
        let (notices, log) = notices_in(folder.path().to_owned(), Platform::Macos);
        let soon = summary(vec![expiring("Ada", 1)]);

        notices.summary(&soon, &on_computer(6), || true, || false);
        assert!(told(&log).is_empty());
        assert!(!folder.path().join("notified.json").exists());

        notices.summary(&soon, &on_computer(6), || true, || true);
        assert_eq!(told(&log).len(), 1);
    }

    #[test]
    fn a_certificate_that_left_the_computer_is_not_told_or_remembered() {
        let folder = tempfile::tempdir().unwrap();
        let (notices, log) = notices_in(folder.path().to_owned(), Platform::Macos);
        let stale = summary(vec![expiring("Ada", 1), expiring("Bob", 2)]);

        notices.summary(&stale, &[Fingerprint::of(&[1])], || true, || true);

        assert_eq!(told(&log).len(), 1);
        let file = std::fs::read_to_string(folder.path().join("notified.json")).unwrap();
        assert!(!file.contains(&Fingerprint::of(&[2]).to_string()));
    }

    #[test]
    fn telling_stops_at_the_first_no_and_remembers_only_what_was_told() {
        let (notices, log) = notices(Platform::Macos);
        let two = summary(vec![expiring("Ada", 1), expiring("Bob", 2)]);
        let asked = std::cell::Cell::new(0);

        notices.summary(
            &two,
            &on_computer(6),
            || true,
            || {
                asked.set(asked.get() + 1);
                asked.get() == 1
            },
        );
        assert_eq!(told(&log).len(), 1);

        notices.summary(&two, &on_computer(6), || true, || true);
        assert_eq!(
            told(&log),
            [pair(
                "Certificate expires soon",
                "Bob expires on 3 Dec 2026."
            )]
        );
    }

    #[test]
    fn a_superseded_summary_changes_neither_memory_nor_file() {
        let folder = tempfile::tempdir().unwrap();
        let (notices, log) = notices_in(folder.path().to_owned(), Platform::Macos);
        let soon = summary(vec![expiring("Ada", 1)]);
        notices.summary(&soon, &on_computer(6), || true, || true);
        let before = std::fs::read_to_string(folder.path().join("notified.json")).unwrap();
        told(&log);

        notices.summary(&summary(Vec::new()), &[], || false, || true);

        let after = std::fs::read_to_string(folder.path().join("notified.json")).unwrap();
        assert_eq!(after, before);
        notices.summary(&soon, &on_computer(6), || true, || true);
        assert!(told(&log).is_empty());
    }

    #[test]
    fn a_certificate_is_told_once_for_each_kind() {
        let (notices, log) = notices(Platform::Macos);
        let soon = summary(vec![expiring("Ada", 1)]);

        notices.summary(&soon, &on_computer(6), || true, || true);
        notices.summary(&soon, &on_computer(6), || true, || true);
        assert_eq!(told(&log).len(), 1);

        let gone = summary(vec![item("Ada", 1, Attention::Expired { on: DEC_3 })]);
        notices.summary(&gone, &on_computer(6), || true, || true);
        notices.summary(&gone, &on_computer(6), || true, || true);
        assert_eq!(
            told(&log),
            [pair("Certificate expired", "Ada expired on 3 Dec 2026.")]
        );
    }

    #[test]
    fn what_was_told_is_remembered_across_a_restart_in_the_file() {
        let folder = tempfile::tempdir().unwrap();
        let (first, log) = notices_in(folder.path().to_owned(), Platform::Macos);
        let soon = summary(vec![expiring("Ada", 1), item("Bob", 2, Attention::Revoked)]);
        first.summary(&soon, &on_computer(6), || true, || true);
        assert_eq!(told(&log).len(), 2);

        let (restarted, log) = notices_in(folder.path().to_owned(), Platform::Macos);
        restarted.summary(&soon, &on_computer(6), || true, || true);

        assert!(told(&log).is_empty());
        let file: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(folder.path().join("notified.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(file["version"], 1);
        assert_eq!(
            file["sent"],
            serde_json::json!([
                { "fingerprint": Fingerprint::of(&[1]).to_string(), "kind": "expiring" },
                { "fingerprint": Fingerprint::of(&[2]).to_string(), "kind": "revoked" },
            ])
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_file_is_readable_by_its_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let folder = tempfile::tempdir().unwrap();
        let (notices, _) = notices_in(folder.path().to_owned(), Platform::Macos);

        notices.summary(
            &summary(vec![expiring("Ada", 1)]),
            &on_computer(6),
            || true,
            || true,
        );

        let mode = std::fs::metadata(folder.path().join("notified.json"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn a_certificate_that_stops_needing_attention_and_comes_back_is_not_told_again() {
        let folder = tempfile::tempdir().unwrap();
        let (notices, log) = notices_in(folder.path().to_owned(), Platform::Macos);
        let on_computer = on_computer(1);
        let soon = summary(vec![expiring("Ada", 1)]);
        notices.summary(&soon, &on_computer, || true, || true);
        assert_eq!(told(&log).len(), 1);

        notices.summary(&summary(Vec::new()), &on_computer, || true, || true);
        notices.summary(&soon, &on_computer, || true, || true);

        assert!(told(&log).is_empty());
        let kept = std::fs::read_to_string(folder.path().join("notified.json")).unwrap();
        assert!(kept.contains(&Fingerprint::of(&[1]).to_string()));
    }

    #[test]
    fn entries_of_certificates_removed_from_the_computer_are_dropped_and_told_again_if_they_return()
    {
        let folder = tempfile::tempdir().unwrap();
        let (notices, log) = notices_in(folder.path().to_owned(), Platform::Macos);
        notices.summary(
            &summary(vec![expiring("Ada", 1), expiring("Bob", 2)]),
            &on_computer(2),
            || true,
            || true,
        );
        told(&log);

        notices.summary(
            &summary(vec![expiring("Bob", 2)]),
            &[Fingerprint::of(&[2])],
            || true,
            || true,
        );
        let kept = std::fs::read_to_string(folder.path().join("notified.json")).unwrap();
        assert!(kept.contains(&Fingerprint::of(&[2]).to_string()));
        assert!(!kept.contains(&Fingerprint::of(&[1]).to_string()));
        assert!(told(&log).is_empty());

        notices.summary(
            &summary(vec![expiring("Ada", 1), expiring("Bob", 2)]),
            &on_computer(2),
            || true,
            || true,
        );
        assert_eq!(
            told(&log),
            [pair(
                "Certificate expires soon",
                "Ada expires on 3 Dec 2026."
            )]
        );
    }

    #[test]
    fn a_first_run_tells_three_and_counts_the_rest_once() {
        let (notices, log) = notices(Platform::Macos);
        let many = summary(
            (1..=6)
                .map(|number| expiring(&format!("c{number}"), number))
                .collect(),
        );

        notices.summary(&many, &on_computer(6), || true, || true);

        let told_first = told(&log);
        assert_eq!(told_first.len(), 4);
        assert_eq!(told_first[2].1, "c3 expires on 3 Dec 2026.");
        assert_eq!(
            told_first[3],
            pair(
                "Certificates need attention",
                "3 more certificates need attention."
            )
        );

        notices.summary(&many, &on_computer(6), || true, || true);
        assert!(told(&log).is_empty());
    }

    #[test]
    fn one_certificate_over_the_limit_is_counted_in_the_singular() {
        let (notices, log) = notices(Platform::Macos);

        notices.summary(
            &summary((1..=4).map(|number| expiring("c", number)).collect()),
            &on_computer(6),
            || true,
            || true,
        );

        assert_eq!(
            told(&log).last().unwrap().1,
            "1 more certificate needs attention."
        );
    }

    #[test]
    fn certificates_that_come_later_are_told_one_by_one() {
        let (notices, log) = notices(Platform::Macos);
        notices.summary(
            &summary(vec![expiring("Ada", 1)]),
            &on_computer(6),
            || true,
            || true,
        );
        told(&log);

        notices.summary(
            &summary((1..=6).map(|number| expiring("c", number)).collect()),
            &on_computer(6),
            || true,
            || true,
        );

        assert_eq!(told(&log).len(), 5);
    }

    #[test]
    fn certificates_that_ilm_does_not_know_are_not_told() {
        let (notices, log) = notices(Platform::Macos);
        let mut unknown = summary(vec![Item {
            kind: Attention::NotInIlm { count: 2 },
            fingerprint: None,
            name: String::new(),
        }]);
        unknown.counts.not_in_ilm = Some(2);

        notices.summary(&unknown, &on_computer(6), || true, || true);

        assert!(told(&log).is_empty());
    }

    #[test]
    fn forgetting_deletes_the_file_and_the_next_person_is_told_again() {
        let folder = tempfile::tempdir().unwrap();
        let (notices, log) = notices_in(folder.path().to_owned(), Platform::Macos);
        let soon = summary(vec![expiring("Ada", 1)]);
        notices.summary(&soon, &on_computer(6), || true, || true);
        told(&log);
        assert!(folder.path().join("notified.json").exists());

        notices.forget();
        notices.forget();

        assert!(!folder.path().join("notified.json").exists());
        notices.summary(&soon, &on_computer(6), || true, || true);
        assert_eq!(told(&log).len(), 1);
    }

    #[test]
    fn a_file_that_is_broken_is_replaced_with_a_warning_and_told_again() {
        for broken in ["not json", r#"{"version":2,"sent":[]}"#, r#"{"sent":[]}"#] {
            let folder = tempfile::tempdir().unwrap();
            let file = folder.path().join("notified.json");
            std::fs::write(&file, broken).unwrap();
            let (notices, log) = notices_in(folder.path().to_owned(), Platform::Macos);

            notices.summary(&summary(Vec::new()), &on_computer(6), || true, || true);
            assert_eq!(std::fs::read_to_string(&file).unwrap(), broken, "{broken}");

            notices.summary(
                &summary(vec![expiring("Ada", 1)]),
                &on_computer(6),
                || true,
                || true,
            );
            assert_eq!(told(&log).len(), 1, "{broken}");
            let replaced: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
            assert_eq!(replaced["version"], 1, "{broken}");
            assert_eq!(replaced["sent"].as_array().unwrap().len(), 1, "{broken}");
        }
    }

    #[test]
    fn a_notification_that_fails_is_still_remembered() {
        let folder = tempfile::tempdir().unwrap();
        let failing = Notices::new(Box::new(Failing), Platform::Linux, folder.path().to_owned());
        let soon = summary(vec![expiring("Ada", 1)]);
        failing.summary(&soon, &on_computer(6), || true, || true);

        let (again, log) = notices_in(folder.path().to_owned(), Platform::Linux);
        again.summary(&soon, &on_computer(6), || true, || true);

        assert!(told(&log).is_empty());
    }

    #[test]
    fn a_folder_that_cannot_be_written_only_costs_the_memory() {
        let folder = tempfile::tempdir().unwrap();
        let blocked = folder.path().join("file");
        std::fs::write(&blocked, "").unwrap();
        let (notices, log) = notices_in(blocked, Platform::Linux);
        let soon = summary(vec![expiring("Ada", 1)]);

        notices.summary(&soon, &on_computer(6), || true, || true);
        notices.summary(&soon, &on_computer(6), || true, || true);

        assert_eq!(told(&log).len(), 1);
    }
}
