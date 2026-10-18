//! `aap.time_windows`: *when the agent may act*, judged on the verifier's
//! clock only (v0 bug 1: never on a time the agent writes itself).
//!
//! A window is a set of weekdays, a local start and end time, and an IANA
//! time zone:
//!
//! ```json
//! {"days": ["fri", "sat"], "start": "22:00", "end": "02:00", "timezone": "Europe/Vienna"}
//! ```
//!
//! - `start` is inclusive, `end` exclusive, both `HH:MM`; `end` may be
//!   `24:00`.
//! - `start > end` runs over midnight: the window opens on a listed day and
//!   closes on the following day, so the example covers Saturday 01:30 and
//!   Sunday 01:30, but not Friday 01:30.
//! - `start == end` is rejected: it could mean "never" or "all day".
//!
//! Internally a window is a list of half-open intervals of local
//! minute-of-week (Monday 00:00 = 0). Evaluation and `narrows` both use that
//! one representation, so "child window inside parent window" means exactly
//! "every instant the child accepts, the parent accepts" for windows in the
//! same zone. Windows in different zones are never compared: daylight
//! saving makes their relation change over the year.

use chrono::{DateTime, Datelike, Timelike};
use chrono_tz::Tz;
use serde_json::Value;

use crate::schema::{Fields, SchemaError};

const DAY: u32 = 24 * 60;
const WEEK: u32 = 7 * DAY;
const DAYS: [&str; 7] = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeWindow {
    /// 0 = Monday.
    days: Vec<u32>,
    start: u32,
    end: u32,
    timezone: Tz,
}

impl TimeWindow {
    pub fn parse(value: &Value) -> Result<Self, SchemaError> {
        let mut f = Fields::new(value, "time window")?;
        let mut days = Vec::new();
        for d in f.strings("days")? {
            match DAYS.iter().position(|x| *x == d) {
                Some(i) => days.push(i as u32),
                None => return Err(f.error(format!("{d:?} is not a weekday (mon..sun)"))),
            }
        }
        let start = f.string("start")?;
        let end = f.string("end")?;
        let start = parse_hm(&start, false).ok_or_else(|| f.error("start must be HH:MM"))?;
        let end = parse_hm(&end, true).ok_or_else(|| f.error("end must be HH:MM or 24:00"))?;
        if start == end {
            return Err(f.error("start equals end: ambiguous (never, or all day)"));
        }
        let tz = f.string("timezone")?;
        let timezone = tz
            .parse::<Tz>()
            .map_err(|_| f.error(format!("{tz:?} is not an IANA time zone")))?;
        f.finish()?;
        days.sort_unstable();
        Ok(TimeWindow {
            days,
            start,
            end,
            timezone,
        })
    }

    /// The half-open local minute-of-week intervals this window covers.
    fn intervals(&self) -> Vec<(u32, u32)> {
        let mut out = Vec::new();
        for &d in &self.days {
            let base = d * DAY;
            if self.start < self.end {
                out.push((base + self.start, base + self.end));
            } else {
                out.push((base + self.start, base + DAY));
                if self.end > 0 {
                    let next = ((d + 1) % 7) * DAY;
                    out.push((next, next + self.end));
                }
            }
        }
        out
    }

    /// Whether the verifier's clock `now` (seconds since the epoch) falls in
    /// this window. A time outside chrono's range does not match.
    pub fn contains(&self, now: i64) -> bool {
        let Some(utc) = DateTime::from_timestamp(now, 0) else {
            return false;
        };
        let local = utc.with_timezone(&self.timezone);
        let m = local.weekday().num_days_from_monday() * DAY + local.hour() * 60 + local.minute();
        self.intervals().iter().any(|&(a, b)| a <= m && m < b)
    }

    /// Whether every instant in `self` is also in the union of `parents`
    /// (only parents in the same time zone count).
    pub fn covered_by(&self, parents: &[TimeWindow]) -> bool {
        let mut merged: Vec<(u32, u32)> = parents
            .iter()
            .filter(|p| p.timezone == self.timezone)
            .flat_map(TimeWindow::intervals)
            .collect();
        merged.sort_unstable();
        let mut union: Vec<(u32, u32)> = Vec::new();
        for (a, b) in merged {
            match union.last_mut() {
                Some(last) if a <= last.1 => last.1 = last.1.max(b),
                _ => union.push((a, b)),
            }
        }
        debug_assert!(union.iter().all(|&(_, b)| b <= WEEK));
        self.intervals()
            .iter()
            .all(|&(a, b)| union.iter().any(|&(x, y)| x <= a && b <= y))
    }
}

fn parse_hm(s: &str, allow_24: bool) -> Option<u32> {
    let (h, m) = s.split_once(':')?;
    if h.len() != 2 || m.len() != 2 || !(h.bytes().chain(m.bytes())).all(|b| b.is_ascii_digit()) {
        return None;
    }
    let (h, m): (u32, u32) = (h.parse().ok()?, m.parse().ok()?);
    match (h, m) {
        (24, 0) if allow_24 => Some(DAY),
        (0..=23, 0..=59) => Some(h * 60 + m),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn w(days: &[&str], start: &str, end: &str, tz: &str) -> TimeWindow {
        TimeWindow::parse(&json!({"days": days, "start": start, "end": end, "timezone": tz}))
            .unwrap()
    }

    /// Seconds since the epoch for a UTC date and time.
    fn utc(y: i32, mo: u32, d: u32, h: u32, mi: u32) -> i64 {
        chrono::NaiveDate::from_ymd_opt(y, mo, d)
            .unwrap()
            .and_hms_opt(h, mi, 0)
            .unwrap()
            .and_utc()
            .timestamp()
    }

    #[test]
    fn plain_window_is_start_inclusive_end_exclusive() {
        // 2026-10-19 is a Monday.
        let win = w(&["mon"], "09:00", "17:00", "UTC");
        assert!(!win.contains(utc(2026, 10, 19, 8, 59)));
        assert!(win.contains(utc(2026, 10, 19, 9, 0)));
        assert!(win.contains(utc(2026, 10, 19, 16, 59)));
        assert!(!win.contains(utc(2026, 10, 19, 17, 0)));
        assert!(!win.contains(utc(2026, 10, 20, 12, 0)), "Tuesday");
    }

    #[test]
    fn window_over_midnight_belongs_to_the_day_it_opens() {
        // Friday 22:00 to Saturday 02:00. 2026-10-23 is a Friday.
        let win = w(&["fri"], "22:00", "02:00", "UTC");
        assert!(win.contains(utc(2026, 10, 23, 23, 30)), "Friday night");
        assert!(win.contains(utc(2026, 10, 24, 1, 59)), "early Saturday");
        assert!(!win.contains(utc(2026, 10, 24, 2, 0)));
        assert!(
            !win.contains(utc(2026, 10, 23, 1, 0)),
            "early Friday is Thursday's night"
        );
        assert!(
            !win.contains(utc(2026, 10, 24, 23, 0)),
            "Saturday night not listed"
        );
    }

    #[test]
    fn sunday_night_wraps_to_monday_morning() {
        let win = w(&["sun"], "23:00", "01:00", "UTC");
        assert!(win.contains(utc(2026, 10, 26, 0, 30)), "Monday 00:30");
        assert!(win.contains(utc(2026, 10, 25, 23, 30)), "Sunday 23:30");
    }

    #[test]
    fn evaluated_in_the_window_time_zone() {
        // 08:30 UTC is 10:30 in Vienna in summer time (2026-06-01, Monday).
        let win = w(&["mon"], "10:00", "11:00", "Europe/Vienna");
        assert!(win.contains(utc(2026, 6, 1, 8, 30)));
        assert!(!win.contains(utc(2026, 6, 1, 10, 30)));
    }

    #[test]
    fn malformed_windows_are_rejected() {
        for bad in [
            json!({"days": ["mon"], "start": "09:00", "end": "09:00", "timezone": "UTC"}),
            json!({"days": [], "start": "09:00", "end": "10:00", "timezone": "UTC"}),
            json!({"days": ["monday"], "start": "09:00", "end": "10:00", "timezone": "UTC"}),
            json!({"days": ["mon"], "start": "9:00", "end": "10:00", "timezone": "UTC"}),
            json!({"days": ["mon"], "start": "24:00", "end": "10:00", "timezone": "UTC"}),
            json!({"days": ["mon"], "start": "09:00", "end": "10:60", "timezone": "UTC"}),
            json!({"days": ["mon"], "start": "09:00", "end": "10:00", "timezone": "Mars/Base"}),
            json!({"days": ["mon"], "start": "09:00", "end": "10:00"}),
            json!({"days": ["mon", "mon"], "start": "09:00", "end": "10:00", "timezone": "UTC"}),
            json!({"days": ["mon"], "start": "09:00", "end": "10:00", "timezone": "UTC", "x": 1}),
        ] {
            assert!(TimeWindow::parse(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn coverage_uses_the_union_of_parent_windows() {
        let parents = [
            w(&["fri"], "18:00", "24:00", "UTC"),
            w(&["sat"], "00:00", "06:00", "UTC"),
        ];
        assert!(w(&["fri"], "22:00", "02:00", "UTC").covered_by(&parents));
        assert!(!w(&["fri"], "22:00", "07:00", "UTC").covered_by(&parents));
        assert!(!w(&["fri"], "22:00", "02:00", "Europe/Vienna").covered_by(&parents));
    }
}
