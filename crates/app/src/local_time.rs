//! The local time zone, for the calendar months of the summary and the dates in notifications.

use std::sync::OnceLock;

use jiff::{Timestamp, tz::TimeZone};

/// The system time zone, or UTC when it cannot be found.
fn system_zone() -> &'static TimeZone {
    static ZONE: OnceLock<TimeZone> = OnceLock::new();
    ZONE.get_or_init(|| {
        TimeZone::try_system().unwrap_or_else(|error| {
            log::warn!("The system time zone is unknown, using UTC: {error}");
            TimeZone::UTC
        })
    })
}

/// The local time zone's offset from UTC in seconds at `millis` (since 1970, UTC), east positive.
pub fn utc_offset_at(millis: i64) -> i32 {
    Timestamp::from_millisecond(millis)
        .map_or(0, |instant| system_zone().to_offset(instant).seconds())
}

/// The date of `millis` (since 1970, UTC) in the local time zone as it is on that date, like "3 Dec 2026".
pub fn date(millis: i64) -> String {
    in_zone(millis, system_zone())
}

fn in_zone(millis: i64, zone: &TimeZone) -> String {
    Timestamp::from_millisecond(millis).map_or_else(
        |_| "an unknown date".to_owned(),
        |instant| {
            instant
                .to_zoned(zone.clone())
                .strftime("%-d %b %Y")
                .to_string()
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use jiff::tz::Offset;

    /// 3 December 2026, 00:00 UTC.
    const DEC_3: i64 = 1_796_256_000_000;

    fn fixed(hours: i8) -> TimeZone {
        TimeZone::fixed(Offset::constant(hours))
    }

    #[test]
    fn the_system_gives_an_offset_within_a_day() {
        assert!(utc_offset_at(DEC_3).abs() < 24 * 3600);
        assert_eq!(utc_offset_at(i64::MAX), 0);
    }

    #[test]
    fn a_date_is_day_month_name_and_year() {
        assert_eq!(in_zone(0, &TimeZone::UTC), "1 Jan 1970");
        assert_eq!(in_zone(DEC_3, &TimeZone::UTC), "3 Dec 2026");
        assert_eq!(in_zone(1_709_164_800_000, &TimeZone::UTC), "29 Feb 2024");
    }

    #[test]
    fn the_local_date_has_the_same_form_and_follows_the_local_zone() {
        let midday = DEC_3 + 12 * 3_600_000;
        assert_eq!(date(midday), in_zone(midday, system_zone()));
        let words: Vec<_> = date(midday).split(' ').map(str::to_owned).collect();
        assert_eq!(words.len(), 3);
        assert_eq!(words[1], "Dec");
        assert_eq!(words[2], "2026");
    }

    #[test]
    fn the_zone_moves_the_date_across_midnight() {
        let late = DEC_3 - 1000;
        assert_eq!(in_zone(late, &TimeZone::UTC), "2 Dec 2026");
        assert_eq!(in_zone(late, &fixed(1)), "3 Dec 2026");
        assert_eq!(in_zone(late + 1000, &fixed(-1)), "2 Dec 2026");
    }

    #[test]
    fn a_date_before_1970_counts_back() {
        assert_eq!(in_zone(-1, &TimeZone::UTC), "31 Dec 1969");
    }

    #[test]
    fn a_time_out_of_range_is_not_a_date() {
        assert_eq!(in_zone(i64::MAX, &TimeZone::UTC), "an unknown date");
    }
}
