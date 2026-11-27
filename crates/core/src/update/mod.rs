//! When to look for an update and whether an offered version is newer.

use std::cmp::Ordering;

use jiff::{SignedDuration, Timestamp};
use semver::Version;

/// How long to wait after a check before the next one.
pub const CHECK_EVERY: SignedDuration = SignedDuration::from_hours(24);

/// Whether a check is due: updates are on and the last check is a day old, missing, or in the future
/// because the clock moved back.
pub fn due(now: Timestamp, last: Option<Timestamp>, enabled: bool) -> bool {
    enabled && last.is_none_or(|last| last > now || now.duration_since(last) >= CHECK_EVERY)
}

/// Whether `offered` is a later version than `current`; build metadata is ignored, a leading `v` is accepted on
/// `offered`, and a version that does not parse is never newer.
pub fn newer(current: &str, offered: &str) -> bool {
    let offered = offered.strip_prefix('v').unwrap_or(offered);
    match (Version::parse(current), Version::parse(offered)) {
        (Ok(current), Ok(offered)) => offered.cmp_precedence(&current) == Ordering::Greater,
        _ => false,
    }
}

#[cfg(test)]
mod tests;
