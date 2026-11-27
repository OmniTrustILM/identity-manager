//! How the certificates on this computer stand: counts, what needs attention, and the expiry over the next year.

use std::time::{SystemTime, UNIX_EPOCH};

use super::Snapshot;
use crate::identity::{Fingerprint, LocalCertificate};
use crate::ilm::approvals::ApprovalAction;
use crate::ilm::certificates::State;
use crate::settings::WarnDays;

const DAY_MILLIS: i64 = 86_400_000;

/// Why a certificate or a group of them needs the person's eye.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kind {
    /// Expires within the warning days; `days` is what is left, counted in calendar days of the local time zone, and `on` is the
    /// expiry, milliseconds since 1970 (UTC).
    Expiring { days: u32, on: i64 },
    /// Expired within the last warning days; `on` is the expiry, milliseconds since 1970 (UTC).
    Expired { on: i64 },
    /// Revoked in ILM.
    Revoked,
    /// Certificates on this computer that ILM does not know.
    NotInIlm { count: u32 },
    /// A request for a certificate that ILM has not issued yet; the item's name is the request's label.
    Waiting { state: WaitingState },
    /// A request of someone else that waits for the person's decision; the item's name is the certificate's and
    /// `uuid` is the approval's.
    Approval {
        uuid: String,
        action: ApprovalAction,
    },
    /// An RA Profile the organization's policy asks the person to request from; the item's name is the profile's
    /// and `uuid` is its own.
    Asked { uuid: String },
}

/// What ILM is doing with a request that is not yet a certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitingState {
    PendingApproval,
    BeingIssued,
}

/// One thing that needs attention.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    pub kind: Kind,
    /// None for the item about several certificates.
    pub fingerprint: Option<Fingerprint>,
    /// The certificate's name; empty for the item about several certificates.
    pub name: String,
}

/// How many certificates are in each state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Counts {
    /// Neither expiring nor expired, and not revoked in ILM; not yet valid counts here.
    pub valid: u32,
    /// Valid now and expiring within the warning days.
    pub expiring: u32,
    /// Past their expiry.
    pub expired: u32,
    /// Looked up in ILM and not found; none when certificates are not listed or ILM has not been checked.
    pub not_in_ilm: Option<u32>,
}

/// The certificates on this computer as of one moment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Summary {
    /// Milliseconds since 1970 (UTC).
    pub computed_at: i64,
    /// When ILM was last checked; none before the first check.
    pub checked_at: Option<i64>,
    /// Whether the person may list certificates in ILM.
    pub listed: bool,
    pub counts: Counts,
    /// Revoked, then expired (latest first), then expiring (soonest first), then the one not in ILM.
    pub attention: Vec<Item>,
    /// Certificates expiring in each calendar month, the current one first, in the local time zone; expired ones
    /// are not counted.
    pub months: [u32; 12],
}

impl Summary {
    /// Whether any certificate is expiring, expired or revoked. Certificates not in ILM and requests in progress do
    /// not count.
    pub fn needs_attention(&self) -> bool {
        self.needing_attention() > 0
    }

    /// How many items are about certificates that are expiring, expired or revoked.
    pub fn needing_attention(&self) -> usize {
        self.attention
            .iter()
            .filter(|item| {
                !matches!(
                    item.kind,
                    Kind::NotInIlm { .. }
                        | Kind::Waiting { .. }
                        | Kind::Approval { .. }
                        | Kind::Asked { .. }
                )
            })
            .count()
    }

    /// Lists the requests in progress, given as label and state, after what is expiring, expired or revoked and
    /// before the certificates ILM does not know.
    #[must_use]
    pub fn with_waiting(self, waiting: impl IntoIterator<Item = (String, WaitingState)>) -> Self {
        self.with_items(waiting.into_iter().map(|(name, state)| Item {
            kind: Kind::Waiting { state },
            fingerprint: None,
            name,
        }))
    }

    /// Lists the requests that wait for the person's approval, given as approval uuid, certificate name and action,
    /// after the requests in progress.
    #[must_use]
    pub fn with_approvals(
        self,
        approvals: impl IntoIterator<Item = (String, String, ApprovalAction)>,
    ) -> Self {
        self.with_items(approvals.into_iter().map(|(uuid, name, action)| Item {
            kind: Kind::Approval { uuid, action },
            fingerprint: None,
            name,
        }))
    }

    /// Lists the RA Profiles the organization asks the person to request from, given as uuid and name, after the
    /// approvals.
    #[must_use]
    pub fn with_asked(self, asked: impl IntoIterator<Item = (String, String)>) -> Self {
        self.with_items(asked.into_iter().map(|(uuid, name)| Item {
            kind: Kind::Asked { uuid },
            fingerprint: None,
            name,
        }))
    }

    /// Puts `items` before the certificates ILM does not know, or last.
    fn with_items(mut self, items: impl Iterator<Item = Item>) -> Self {
        let at = match self.attention.last() {
            Some(Item {
                kind: Kind::NotInIlm { .. },
                ..
            }) => self.attention.len() - 1,
            _ => self.attention.len(),
        };
        self.attention.splice(at..at, items);
        self
    }
}

/// Summarizes `local` as ILM's `snapshot` (none before the first check) knows them at `now`, milliseconds since
/// 1970 (UTC). `utc_offset_at` gives the local time zone's offset from UTC in seconds at an instant, which decides
/// the calendar months and days.
pub fn summarize(
    local: &[LocalCertificate],
    snapshot: Option<&Snapshot>,
    days: WarnDays,
    now: i64,
    utc_offset_at: impl Fn(i64) -> i32,
) -> Summary {
    let window = i64::from(days.get()) * DAY_MILLIS;
    let this_month = month_number(now, utc_offset_at(now));
    let mut counts = Counts {
        valid: 0,
        expiring: 0,
        expired: 0,
        not_in_ilm: None,
    };
    let mut months = [0; 12];
    let mut revoked = Vec::new();
    let mut expired = Vec::new();
    let mut expiring = Vec::new();
    let mut unknown = 0;
    for found in local {
        let ends = epoch_millis(found.not_after);
        let state = snapshot
            .and_then(|snapshot| snapshot.matches.get(&found.fingerprint))
            .map(|known| &known.state);
        let is_revoked = state == Some(&State::Revoked);
        let replaced =
            snapshot.is_some_and(|snapshot| snapshot.replaced.contains(&found.fingerprint));
        if snapshot.is_some_and(|snapshot| {
            snapshot.listed
                && snapshot.checked.contains(&found.fingerprint)
                && !snapshot.matches.contains_key(&found.fingerprint)
        }) {
            unknown += 1;
        }
        let item = |kind| Item {
            kind,
            fingerprint: Some(found.fingerprint),
            name: found.name.clone(),
        };
        if ends <= now {
            counts.expired += 1;
            if is_revoked {
                revoked.push(item(Kind::Revoked));
            } else if now - ends <= window && !replaced {
                expired.push((ends, item(Kind::Expired { on: ends })));
            }
            continue;
        }
        if let Some(slot) = usize::try_from(month_number(ends, utc_offset_at(ends)) - this_month)
            .ok()
            .and_then(|index| months.get_mut(index))
        {
            *slot += 1;
        }
        if is_revoked {
            revoked.push(item(Kind::Revoked));
        } else if ends - now <= window && !replaced {
            counts.expiring += 1;
            let left = u32::try_from(
                local_day(ends, utc_offset_at(ends)) - local_day(now, utc_offset_at(now)),
            )
            .unwrap_or(u32::MAX);
            expiring.push((
                ends,
                item(Kind::Expiring {
                    days: left,
                    on: ends,
                }),
            ));
        } else {
            counts.valid += 1;
        }
    }
    if snapshot.is_some_and(|snapshot| snapshot.listed) {
        counts.not_in_ilm = Some(unknown);
    }
    revoked.sort_by(|a, b| (&a.name, a.fingerprint).cmp(&(&b.name, b.fingerprint)));
    expired.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.name.cmp(&b.1.name)));
    expiring.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.name.cmp(&b.1.name)));
    let mut attention = revoked;
    attention.extend(expired.into_iter().map(|(_, item)| item));
    attention.extend(expiring.into_iter().map(|(_, item)| item));
    if unknown > 0 && counts.not_in_ilm.is_some() {
        attention.push(Item {
            kind: Kind::NotInIlm { count: unknown },
            fingerprint: None,
            name: String::new(),
        });
    }
    Summary {
        computed_at: now,
        checked_at: snapshot.map(|snapshot| snapshot.checked_at),
        listed: snapshot.is_some_and(|snapshot| snapshot.listed),
        counts,
        attention,
        months,
    }
}

fn epoch_millis(time: SystemTime) -> i64 {
    match time.duration_since(UNIX_EPOCH) {
        Ok(after) => i64::try_from(after.as_millis()).unwrap_or(i64::MAX),
        Err(before) => {
            i64::try_from(before.duration().as_millis()).map_or(i64::MIN, |millis| -millis)
        }
    }
}

/// The calendar day of `millis` (since 1970, UTC) at `utc_offset` seconds from UTC, counted from 1 January 1970.
fn local_day(millis: i64, utc_offset: i32) -> i64 {
    (millis.div_euclid(1000) + i64::from(utc_offset)).div_euclid(86_400)
}

/// The calendar month of `millis` (since 1970, UTC) at `utc_offset` seconds from UTC, counted from year 0.
fn month_number(millis: i64, utc_offset: i32) -> i64 {
    let days = local_day(millis, utc_offset);
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_from_march = (5 * day_of_year + 2) / 153;
    let month = if month_from_march < 10 {
        month_from_march + 3
    } else {
        month_from_march - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    year * 12 + month - 1
}

#[cfg(test)]
pub(super) mod tests {
    use std::collections::HashMap;
    use std::time::Duration;

    use super::*;
    use crate::identity::{KeyAlgorithm, KeyLocation};
    use crate::ilm::certificates::{IlmCertificate, ValidationStatus};

    const HOUR: i64 = 3_600_000;

    /// Milliseconds since 1970 (UTC) at `hour` o'clock on the given day.
    pub(in crate::inventory) fn utc(year: i64, month: i64, day: i64, hour: i64) -> i64 {
        let year = year - i64::from(month <= 2);
        let era = year.div_euclid(400);
        let year_of_era = year - era * 400;
        let shifted_month = (month + 9) % 12;
        let day_of_year = (153 * shifted_month + 2) / 5 + day - 1;
        let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
        let days = era * 146_097 + day_of_era - 719_468;
        days * DAY_MILLIS + hour * HOUR
    }

    fn time(millis: i64) -> SystemTime {
        UNIX_EPOCH + Duration::from_millis(u64::try_from(millis).unwrap())
    }

    pub(in crate::inventory) fn local(name: &str, number: u32, not_after: i64) -> LocalCertificate {
        LocalCertificate {
            fingerprint: Fingerprint::of(&number.to_be_bytes()),
            name: name.to_owned(),
            subject: format!("CN={name}"),
            issuer: "CA".to_owned(),
            issuer_name: "CN=CA".to_owned(),
            serial: "01".to_owned(),
            not_before: time(0),
            not_after: time(not_after),
            uses: Vec::new(),
            alternative_names: Vec::new(),
            key: KeyAlgorithm::Ed25519,
            location: KeyLocation::Software,
            card: None,
            sign_in: Ok(()),
        }
    }

    fn known(state: State) -> IlmCertificate {
        IlmCertificate {
            uuid: "u".to_owned(),
            name: "n".to_owned(),
            subject_dn: None,
            issuer_name: None,
            serial: None,
            not_before: None,
            not_after: None,
            fingerprint: None,
            key: None,
            state,
            validation_status: ValidationStatus::Valid,
            ra_profile: None,
            owner: None,
            groups: Vec::new(),
            archived: false,
        }
    }

    fn print(number: u32) -> Fingerprint {
        Fingerprint::of(&number.to_be_bytes())
    }

    /// ILM listed certificates and looked up `checked`; it knows `matched` in the given state.
    fn snapshot(checked: &[u32], matched: &[(u32, State)]) -> Snapshot {
        Snapshot {
            checked_at: 7,
            listed: true,
            checked: checked.iter().copied().map(print).collect(),
            matches: matched
                .iter()
                .map(|(number, state)| (print(*number), known(state.clone())))
                .collect(),
            sign_in: None,
            first_page: None,
            allowed: HashMap::new(),
            prepared: Vec::new(),
            approvals: Vec::new(),
            replaced: Default::default(),
        }
    }

    fn days(days: i64) -> WarnDays {
        WarnDays::new(days).unwrap()
    }

    fn now() -> i64 {
        utc(2026, 11, 20, 12)
    }

    fn in_days(count: i64) -> i64 {
        now() + count * DAY_MILLIS
    }

    fn kinds(summary: &Summary) -> Vec<(&str, Kind)> {
        summary
            .attention
            .iter()
            .map(|item| (item.name.as_str(), item.kind.clone()))
            .collect()
    }

    #[test]
    fn the_calendar_month_is_counted_in_the_local_zone() {
        assert_eq!(month_number(0, 0), 1970 * 12);
        assert_eq!(month_number(utc(2026, 11, 30, 23), 0), 2026 * 12 + 10);
        assert_eq!(month_number(utc(2026, 12, 1, 0), 0), 2026 * 12 + 11);
        assert_eq!(month_number(utc(2027, 1, 1, 0), 0), 2027 * 12);
        assert_eq!(month_number(utc(2024, 2, 29, 12), 0), 2024 * 12 + 1);
        assert_eq!(
            month_number(utc(2026, 11, 30, 23), 2 * 3600),
            2026 * 12 + 11
        );
        assert_eq!(month_number(utc(2026, 12, 1, 1), -2 * 3600), 2026 * 12 + 10);
        assert_eq!(month_number(utc(1969, 12, 31, 12), 0), 1969 * 12 + 11);
    }

    #[test]
    fn certificates_are_counted_as_valid_expiring_or_expired() {
        let local = [
            local("far", 1, in_days(31)),
            local("edge", 2, in_days(30)),
            local("soon", 3, in_days(2)),
            local("gone", 4, in_days(-1)),
            local("later", 5, in_days(400)),
        ];

        let summary = summarize(
            &local,
            Some(&snapshot(&[1, 2, 3, 4, 5], &[])),
            days(30),
            now(),
            |_| 0,
        );

        assert_eq!(summary.counts.valid, 2);
        assert_eq!(summary.counts.expiring, 2);
        assert_eq!(summary.counts.expired, 1);
        assert_eq!(summary.computed_at, now());
        assert_eq!(summary.checked_at, Some(7));
        assert!(summary.listed);
    }

    #[test]
    fn a_certificate_ending_at_this_instant_is_expired() {
        let local = [local("now", 1, now())];

        let summary = summarize(&local, None, days(30), now(), |_| 0);

        assert_eq!(summary.counts.expired, 1);
        assert_eq!(summary.counts.expiring, 0);
        assert_eq!(summary.months.iter().sum::<u32>(), 0);
        assert!(matches!(summary.attention[0].kind, Kind::Expired { .. }));
    }

    #[test]
    fn a_certificate_that_is_not_valid_yet_counts_as_valid() {
        let mut waiting = local("waiting", 1, in_days(200));
        waiting.not_before = time(in_days(10));

        let summary = summarize(&[waiting], None, days(30), now(), |_| 0);

        assert_eq!(summary.counts.valid, 1);
        assert!(summary.attention.is_empty());
    }

    #[test]
    fn the_months_start_with_the_current_one_and_split_on_the_last_day() {
        let local = [
            local("now", 1, utc(2026, 11, 21, 0)),
            local("last day", 2, utc(2026, 11, 30, 23)),
            local("first day", 3, utc(2026, 12, 1, 0)),
            local("year wrap", 4, utc(2027, 1, 15, 0)),
            local("last month", 5, utc(2027, 10, 31, 23)),
            local("beyond", 6, utc(2027, 11, 1, 0)),
        ];

        let summary = summarize(&local, None, days(30), now(), |_| 0);

        assert_eq!(summary.months, [2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    }

    #[test]
    fn the_time_zone_moves_a_certificate_across_the_month_line() {
        let local = [local("late", 1, utc(2026, 11, 30, 23) + HOUR / 2)];

        let east = summarize(&local, None, days(30), now(), |_| 3600);
        let utc_zone = summarize(&local, None, days(30), now(), |_| 0);
        let west = summarize(&local, None, days(30), now(), |_| -5 * 3600);

        assert_eq!(east.months[..2], [0, 1]);
        assert_eq!(utc_zone.months[..2], [1, 0]);
        assert_eq!(west.months[..2], [1, 0]);
    }

    #[test]
    fn the_time_zone_also_decides_the_current_month() {
        let local = [local("december", 1, utc(2026, 12, 20, 0))];
        let almost_december = utc(2026, 11, 30, 23);

        let east = summarize(&local, None, days(30), almost_december, |_| 2 * 3600);
        let utc_zone = summarize(&local, None, days(30), almost_december, |_| 0);

        assert_eq!(east.months[0], 1);
        assert_eq!(utc_zone.months[1], 1);
    }

    #[test]
    fn each_instant_has_the_offset_of_its_own_date() {
        let now = utc(2026, 3, 28, 12) - HOUR;
        let ends = utc(2026, 3, 31, 22) + HOUR / 2;
        let local = [local("daylight saving", 1, ends)];
        let zone = |millis: i64| {
            if millis < utc(2026, 3, 29, 1) {
                3600
            } else {
                7200
            }
        };

        let summary = summarize(&local, None, days(30), now, zone);

        assert_eq!(summary.months[..2], [0, 1]);
        let Kind::Expiring { days: left, .. } = summary.attention[0].kind else {
            panic!("the certificate is expiring");
        };
        assert_eq!(left, 4);
    }

    #[test]
    fn expired_certificates_are_not_in_the_months() {
        let local = [local("gone", 1, in_days(-3)), local("fine", 2, in_days(3))];

        let summary = summarize(&local, None, days(30), now(), |_| 0);

        assert_eq!(summary.months.iter().sum::<u32>(), 1);
    }

    #[test]
    fn attention_lists_revoked_then_expired_latest_first_then_expiring_soonest_first() {
        let local = [
            local("expiring later", 1, in_days(20)),
            local("revoked", 2, in_days(100)),
            local("expired long ago", 3, in_days(-20)),
            local("expiring first", 4, in_days(5)),
            local("expired lately", 5, in_days(-2)),
            local("fine", 6, in_days(100)),
        ];
        let snapshot = snapshot(
            &[1, 2, 3, 4, 5, 6],
            &[
                (1, State::Issued),
                (2, State::Revoked),
                (3, State::Issued),
                (4, State::Issued),
                (5, State::Issued),
                (6, State::Issued),
            ],
        );

        let summary = summarize(&local, Some(&snapshot), days(30), now(), |_| 0);

        assert_eq!(
            kinds(&summary),
            [
                ("revoked", Kind::Revoked),
                ("expired lately", Kind::Expired { on: in_days(-2) }),
                ("expired long ago", Kind::Expired { on: in_days(-20) }),
                (
                    "expiring first",
                    Kind::Expiring {
                        days: 5,
                        on: in_days(5)
                    }
                ),
                (
                    "expiring later",
                    Kind::Expiring {
                        days: 20,
                        on: in_days(20)
                    }
                ),
            ]
        );
        assert!(summary.needs_attention());
        assert_eq!(summary.needing_attention(), 5);
    }

    #[test]
    fn a_replaced_certificate_needs_no_attention_and_is_not_counted_as_expiring() {
        let local = [
            local("replaced expiring", 1, in_days(5)),
            local("replaced expired", 2, in_days(-2)),
            local("replaced revoked", 3, in_days(5)),
            local("expiring", 4, in_days(6)),
        ];
        let mut snapshot = snapshot(
            &[1, 2, 3, 4],
            &[
                (1, State::Issued),
                (2, State::Issued),
                (3, State::Revoked),
                (4, State::Issued),
            ],
        );
        snapshot.replaced = [print(1), print(2), print(3)].into();

        let summary = summarize(&local, Some(&snapshot), days(30), now(), |_| 0);

        assert_eq!(
            kinds(&summary),
            [
                ("replaced revoked", Kind::Revoked),
                (
                    "expiring",
                    Kind::Expiring {
                        days: 6,
                        on: in_days(6)
                    }
                )
            ]
        );
        assert_eq!(summary.counts.expiring, 1);
        assert_eq!(summary.counts.expired, 1);
        assert_eq!(summary.counts.valid, 1);
        assert_eq!(summary.needing_attention(), 2);
    }

    #[test]
    fn nothing_needs_attention_when_only_replaced_certificates_are_ending() {
        let local = [local("old", 1, in_days(3))];
        let mut snapshot = snapshot(&[1], &[(1, State::Issued)]);
        snapshot.replaced = [print(1)].into();

        let summary = summarize(&local, Some(&snapshot), days(30), now(), |_| 0);

        assert!(!summary.needs_attention());
    }

    #[test]
    fn the_days_left_are_calendar_days_in_the_local_zone() {
        let local = [
            local("today", 1, now() + HOUR),
            local("tomorrow", 2, now() + 13 * HOUR),
        ];

        let utc_zone = summarize(&local, None, days(7), now(), |_| 0);
        let west = summarize(&local, None, days(7), now(), |_| -2 * 3600);

        let left = |summary: &Summary| {
            summary
                .attention
                .iter()
                .map(|item| match item.kind {
                    Kind::Expiring { days, .. } => days,
                    _ => u32::MAX,
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(left(&utc_zone), [0, 1]);
        assert_eq!(left(&west), [0, 0]);
    }

    #[test]
    fn a_certificate_expired_longer_ago_than_the_warning_days_is_counted_but_not_listed() {
        let local = [
            local("edge", 1, in_days(-7)),
            local("older", 2, in_days(-8)),
        ];

        let summary = summarize(&local, None, days(7), now(), |_| 0);

        assert_eq!(summary.counts.expired, 2);
        assert_eq!(
            kinds(&summary),
            [("edge", Kind::Expired { on: in_days(-7) })]
        );
        let longer = summarize(&local, None, days(30), now(), |_| 0);
        assert_eq!(longer.attention.len(), 2);
    }

    #[test]
    fn a_revoked_certificate_is_listed_once_and_is_not_valid_or_expiring() {
        let local = [
            local("revoked and fine", 1, in_days(200)),
            local("revoked and expiring", 2, in_days(3)),
            local("revoked and expired", 3, in_days(-3)),
        ];
        let snapshot = snapshot(
            &[1, 2, 3],
            &[
                (1, State::Revoked),
                (2, State::Revoked),
                (3, State::Revoked),
            ],
        );

        let summary = summarize(&local, Some(&snapshot), days(30), now(), |_| 0);

        assert_eq!(
            (
                summary.counts.valid,
                summary.counts.expiring,
                summary.counts.expired
            ),
            (0, 0, 1)
        );
        assert_eq!(summary.attention.len(), 3);
        assert!(
            summary
                .attention
                .iter()
                .all(|item| item.kind == Kind::Revoked)
        );
        assert_eq!(summary.months.iter().sum::<u32>(), 2);
    }

    #[test]
    fn certificates_ilm_does_not_know_are_one_item_that_does_not_need_attention() {
        let local = [
            local("known", 1, in_days(100)),
            local("missing a", 2, in_days(100)),
            local("missing b", 3, in_days(100)),
            local("not looked up", 4, in_days(100)),
        ];
        let snapshot = snapshot(&[1, 2, 3], &[(1, State::Issued)]);

        let summary = summarize(&local, Some(&snapshot), days(30), now(), |_| 0);

        assert_eq!(summary.counts.not_in_ilm, Some(2));
        assert_eq!(summary.counts.valid, 4);
        assert_eq!(kinds(&summary), [("", Kind::NotInIlm { count: 2 })]);
        assert_eq!(summary.attention[0].fingerprint, None);
        assert!(!summary.needs_attention());
    }

    #[test]
    fn the_not_in_ilm_item_comes_last() {
        let local = [
            local("missing", 1, in_days(100)),
            local("soon", 2, in_days(1)),
        ];
        let snapshot = snapshot(&[1, 2], &[(2, State::Issued)]);

        let summary = summarize(&local, Some(&snapshot), days(30), now(), |_| 0);

        assert_eq!(
            kinds(&summary),
            [
                (
                    "soon",
                    Kind::Expiring {
                        days: 1,
                        on: in_days(1)
                    }
                ),
                ("", Kind::NotInIlm { count: 1 }),
            ]
        );
        assert!(summary.needs_attention());
    }

    #[test]
    fn without_the_listing_nothing_is_said_about_ilm() {
        let local = [local("missing", 1, in_days(100))];
        let mut snapshot = snapshot(&[], &[]);
        snapshot.listed = false;

        let summary = summarize(&local, Some(&snapshot), days(30), now(), |_| 0);

        assert_eq!(summary.counts.not_in_ilm, None);
        assert!(!summary.listed);
        assert!(summary.attention.is_empty());
        assert_eq!(summary.counts.valid, 1);
    }

    #[test]
    fn before_the_first_check_ilm_is_not_judged_but_the_expiry_is() {
        let local = [local("soon", 1, in_days(3)), local("fine", 2, in_days(100))];

        let summary = summarize(&local, None, days(30), now(), |_| 0);

        assert_eq!(summary.counts.not_in_ilm, None);
        assert_eq!(summary.checked_at, None);
        assert!(!summary.listed);
        assert_eq!(
            kinds(&summary),
            [(
                "soon",
                Kind::Expiring {
                    days: 3,
                    on: in_days(3)
                }
            )]
        );
    }

    #[test]
    fn requests_in_progress_are_listed_before_the_unknown_certificates_and_need_no_attention() {
        let local = [
            local("missing", 1, in_days(100)),
            local("soon", 2, in_days(1)),
        ];
        let snapshot = snapshot(&[1, 2], &[(2, State::Issued)]);
        let waiting = [
            ("User mTLS".to_owned(), WaitingState::PendingApproval),
            ("Code signing".to_owned(), WaitingState::BeingIssued),
        ];

        let summary =
            summarize(&local, Some(&snapshot), days(30), now(), |_| 0).with_waiting(waiting);

        let waiting_kinds: Vec<_> = summary
            .attention
            .iter()
            .map(|item| (item.name.as_str(), item.kind.clone()))
            .collect();
        assert_eq!(
            waiting_kinds[1..],
            [
                (
                    "User mTLS",
                    Kind::Waiting {
                        state: WaitingState::PendingApproval
                    }
                ),
                (
                    "Code signing",
                    Kind::Waiting {
                        state: WaitingState::BeingIssued
                    }
                ),
                ("", Kind::NotInIlm { count: 1 }),
            ]
        );
        assert_eq!(summary.attention[1].fingerprint, None);
        assert_eq!(summary.needing_attention(), 1);
    }

    #[test]
    fn requests_in_progress_alone_do_not_switch_the_attention_on() {
        let summary = summarize(&[], None, days(30), now(), |_| 0)
            .with_waiting([("User mTLS".to_owned(), WaitingState::PendingApproval)]);

        assert_eq!(summary.attention.len(), 1);
        assert!(!summary.needs_attention());
        assert_eq!(summary.needing_attention(), 0);
    }

    #[test]
    fn approvals_are_listed_after_the_requests_in_progress_without_switching_the_attention_on() {
        let summary = summarize(&[], None, days(30), now(), |_| 0)
            .with_waiting([("User mTLS".to_owned(), WaitingState::BeingIssued)])
            .with_approvals([(
                "a-1".to_owned(),
                "demo220".to_owned(),
                ApprovalAction::Renew,
            )]);

        let kinds: Vec<_> = summary
            .attention
            .iter()
            .map(|item| (item.name.as_str(), item.kind.clone()))
            .collect();
        assert_eq!(
            kinds,
            [
                (
                    "User mTLS",
                    Kind::Waiting {
                        state: WaitingState::BeingIssued
                    }
                ),
                (
                    "demo220",
                    Kind::Approval {
                        uuid: "a-1".to_owned(),
                        action: ApprovalAction::Renew
                    }
                ),
            ]
        );
        assert_eq!(summary.needing_attention(), 0);
        assert!(!summary.needs_attention());
    }

    #[test]
    fn asked_profiles_are_listed_after_the_approvals_without_switching_the_attention_on() {
        let summary = summarize(&[], None, days(30), now(), |_| 0)
            .with_approvals([(
                "a-1".to_owned(),
                "demo220".to_owned(),
                ApprovalAction::Renew,
            )])
            .with_asked([("ra-1".to_owned(), "Servers".to_owned())]);

        let last = summary.attention.last().unwrap();
        assert_eq!(last.name, "Servers");
        assert_eq!(
            last.kind,
            Kind::Asked {
                uuid: "ra-1".to_owned()
            }
        );
        assert_eq!(summary.attention.len(), 2);
        assert!(!summary.needs_attention());
    }

    #[test]
    fn no_certificates_make_an_empty_summary() {
        let summary = summarize(&[], Some(&snapshot(&[], &[])), days(30), now(), |_| 0);

        assert_eq!(
            summary.counts,
            Counts {
                valid: 0,
                expiring: 0,
                expired: 0,
                not_in_ilm: Some(0)
            }
        );
        assert!(summary.attention.is_empty() && !summary.needs_attention());
        assert_eq!(summary.months, [0; 12]);
    }
}
