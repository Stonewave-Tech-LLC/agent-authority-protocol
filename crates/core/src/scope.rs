//! Deterministic scope matching. No LLM, no heuristics — pure functions over
//! structured data, per spec/scope-matching.md. This is the actual trust
//! boundary of the protocol; keep it boring and exhaustively testable.

use chrono::{DateTime, Datelike, Timelike, Utc, Weekday as ChronoWeekday};
use chrono_tz::Tz;

use crate::types::{ActionRequest, Amount, Scope, TimeWindow, Weekday};

/// An amount is only meaningful if it is a finite, non-negative number.
/// A negative value would otherwise sit "under" every ceiling, and NaN or
/// infinity can never be compared honestly. Direction of money (refunds,
/// reversals) belongs in the `action`, never in the sign.
fn valid_amount(a: &Amount) -> bool {
    a.value.is_finite() && a.value >= 0.0
}

fn weekday_matches(w: Weekday, cw: ChronoWeekday) -> bool {
    matches!(
        (w, cw),
        (Weekday::Mon, ChronoWeekday::Mon)
            | (Weekday::Tue, ChronoWeekday::Tue)
            | (Weekday::Wed, ChronoWeekday::Wed)
            | (Weekday::Thu, ChronoWeekday::Thu)
            | (Weekday::Fri, ChronoWeekday::Fri)
            | (Weekday::Sat, ChronoWeekday::Sat)
            | (Weekday::Sun, ChronoWeekday::Sun)
    )
}

/// Parses a strict 24-hour `HH:MM` (the pattern in `scope.schema.json`) into
/// minutes since midnight. Anything else, such as `9:00`, `16:120`, `24:00`
/// or `+1:00`, is `None`. A lenient parser would let a window like
/// `00:00-00:1439` look like "the first minutes after midnight" to a human
/// and to `narrows`, while covering the whole day.
fn parse_hm(s: &str) -> Option<u32> {
    let b = s.as_bytes();
    if b.len() != 5 || b[2] != b':' || !b[..2].iter().chain(&b[3..]).all(u8::is_ascii_digit) {
        return None;
    }
    let (h, m) = (
        u32::from(b[0] - b'0') * 10 + u32::from(b[1] - b'0'),
        u32::from(b[3] - b'0') * 10 + u32::from(b[4] - b'0'),
    );
    (h < 24 && m < 60).then_some(h * 60 + m)
}

/// Whether `ts` falls inside `window`, evaluated in the window's own timezone.
/// An unparseable timezone or time string is treated as "does not match" —
/// fail closed, never fail open on malformed scope data.
fn timestamp_in_window(ts: &DateTime<Utc>, window: &TimeWindow) -> bool {
    let Ok(tz) = window.timezone.parse::<Tz>() else {
        return false;
    };
    let local = ts.with_timezone(&tz);
    if !window
        .days
        .iter()
        .any(|d| weekday_matches(*d, local.weekday()))
    {
        return false;
    }
    let (Some(start), Some(end)) = (parse_hm(&window.start), parse_hm(&window.end)) else {
        return false;
    };
    let minute_of_day = local.hour() * 60 + local.minute();
    minute_of_day >= start && minute_of_day <= end
}

/// Step-by-step per spec/scope-matching.md `matches(scope, request, now)`.
///
/// `now` is the Verifier's own evaluation time. Time windows are checked
/// against it, never against `request.timestamp`: that field is written and
/// signed by the agent itself, so trusting it would let an agent claim any
/// time it likes.
pub fn matches(scope: &Scope, request: &ActionRequest, now: DateTime<Utc>) -> bool {
    // 1. action allow-list
    if !scope.actions.iter().any(|a| a == &request.action) {
        return false;
    }

    // 2. resources
    if let Some(resources) = &scope.resources {
        match &request.resource {
            Some(r) if resources.iter().any(|x| x == r) => {}
            _ => return false,
        }
    }

    // 3. max_amount
    if let Some(max) = &scope.max_amount {
        match &request.amount {
            Some(amt)
                if valid_amount(amt)
                    && valid_amount(max)
                    && amt.currency == max.currency
                    && amt.value <= max.value => {}
            _ => return false,
        }
    } else if request.amount.is_some() {
        // request carries money but scope never mentioned any — deny,
        // never let an amount through an undefined ceiling.
        return false;
    }

    // 4 & 5. counterparties
    if let Some(cps) = &scope.counterparties {
        if let (Some(deny), Some(cp)) = (&cps.deny, &request.counterparty) {
            if deny.iter().any(|d| d == cp) {
                return false;
            }
        }
        if let Some(allow) = &cps.allow {
            match &request.counterparty {
                Some(cp) if allow.iter().any(|a| a == cp) => {}
                _ => return false,
            }
        }
    }

    // 6. data categories
    if let Some(allowed) = &scope.data_categories {
        if let Some(requested) = &request.data_categories {
            if !requested.iter().all(|c| allowed.contains(c)) {
                return false;
            }
        }
    }

    // 7. time windows
    if let Some(windows) = &scope.time_windows {
        if !windows.iter().any(|w| timestamp_in_window(&now, w)) {
            return false;
        }
    }

    true
}

/// `narrows(parent, child)` per spec/scope-matching.md — is `child` a valid
/// (non-privilege-escalating) sub-delegation of `parent`?
///
/// Note on time_windows: for v1 this checks each child window against a
/// *single* matching parent window (same timezone, superset of days,
/// containing time range) rather than the full union of parent windows.
/// Stricter than necessary in some valid edge cases, but never permissive —
/// acceptable for a first version of a security-relevant check.
pub fn narrows(parent: &Scope, child: &Scope) -> bool {
    // 1. actions
    if !child.actions.iter().all(|a| parent.actions.contains(a)) {
        return false;
    }

    // 2. resources
    if let Some(pr) = &parent.resources {
        match &child.resources {
            Some(cr) if cr.iter().all(|r| pr.contains(r)) => {}
            _ => return false,
        }
    }

    // 3. max_amount
    if let Some(pmax) = &parent.max_amount {
        match &child.max_amount {
            Some(cmax)
                if valid_amount(cmax)
                    && valid_amount(pmax)
                    && cmax.currency == pmax.currency
                    && cmax.value <= pmax.value => {}
            _ => return false,
        }
    } else if child.max_amount.is_some() {
        // A parent without a ceiling allows no amounts at all (see
        // `matches`, step 3), so any ceiling on the child would grant money
        // the parent never did.
        return false;
    }

    // 4. counterparties: child allow ⊆ parent allow; child deny ⊇ parent deny
    let parent_cps = parent.counterparties.clone().unwrap_or_default();
    let child_cps = child.counterparties.clone().unwrap_or_default();
    if let Some(pallow) = &parent_cps.allow {
        match &child_cps.allow {
            Some(callow) if callow.iter().all(|c| pallow.contains(c)) => {}
            _ => return false,
        }
    }
    if let Some(pdeny) = &parent_cps.deny {
        let cdeny = child_cps.deny.unwrap_or_default();
        if !pdeny.iter().all(|d| cdeny.contains(d)) {
            return false;
        }
    }

    // 5. data categories
    if let Some(pdc) = &parent.data_categories {
        match &child.data_categories {
            Some(cdc) if cdc.iter().all(|c| pdc.contains(c)) => {}
            _ => return false,
        }
    }

    // 6. time windows
    if let Some(pw) = &parent.time_windows {
        let cw = match &child.time_windows {
            Some(cw) => cw,
            None => return false, // parent restricted time, child must too
        };
        for child_window in cw {
            let contained = pw.iter().any(|parent_window| {
                parent_window.timezone == child_window.timezone
                    && child_window
                        .days
                        .iter()
                        .all(|d| parent_window.days.contains(d))
                    && parse_hm(&child_window.start)
                        .zip(parse_hm(&parent_window.start))
                        .is_some_and(|(c, p)| c >= p)
                    && parse_hm(&child_window.end)
                        .zip(parse_hm(&parent_window.end))
                        .is_some_and(|(c, p)| c <= p)
            });
            if !contained {
                return false;
            }
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Amount, Counterparties};
    use chrono::TimeZone;

    fn base_scope() -> Scope {
        Scope {
            actions: vec!["create_payment".into(), "read_invoice".into()],
            ..Default::default()
        }
    }

    fn base_request() -> ActionRequest {
        ActionRequest {
            action: "create_payment".into(),
            timestamp: Utc::now(),
            ..Default::default()
        }
    }

    #[test]
    fn denies_action_not_in_allow_list() {
        let scope = base_scope();
        let mut req = base_request();
        req.action = "delete_account".into();
        assert!(!matches(&scope, &req, Utc::now()));
    }

    #[test]
    fn allows_action_in_allow_list() {
        assert!(matches(&base_scope(), &base_request(), Utc::now()));
    }

    #[test]
    fn denies_amount_over_ceiling() {
        let mut scope = base_scope();
        scope.max_amount = Some(Amount {
            value: 100.0,
            currency: "EUR".into(),
        });
        let mut req = base_request();
        req.amount = Some(Amount {
            value: 150.0,
            currency: "EUR".into(),
        });
        assert!(!matches(&scope, &req, Utc::now()));
    }

    #[test]
    fn allows_amount_under_ceiling() {
        let mut scope = base_scope();
        scope.max_amount = Some(Amount {
            value: 100.0,
            currency: "EUR".into(),
        });
        let mut req = base_request();
        req.amount = Some(Amount {
            value: 50.0,
            currency: "EUR".into(),
        });
        assert!(matches(&scope, &req, Utc::now()));
    }

    #[test]
    fn denies_amount_when_scope_never_mentioned_money() {
        let scope = base_scope();
        let mut req = base_request();
        req.amount = Some(Amount {
            value: 1.0,
            currency: "EUR".into(),
        });
        assert!(!matches(&scope, &req, Utc::now()));
    }

    #[test]
    fn denies_currency_mismatch_even_under_ceiling() {
        let mut scope = base_scope();
        scope.max_amount = Some(Amount {
            value: 100.0,
            currency: "EUR".into(),
        });
        let mut req = base_request();
        req.amount = Some(Amount {
            value: 1.0,
            currency: "USD".into(),
        });
        assert!(!matches(&scope, &req, Utc::now()));
    }

    #[test]
    fn deny_list_wins_even_if_also_on_allow_list() {
        let mut scope = base_scope();
        scope.counterparties = Some(Counterparties {
            allow: Some(vec!["acme".into()]),
            deny: Some(vec!["acme".into()]),
        });
        let mut req = base_request();
        req.counterparty = Some("acme".into());
        assert!(!matches(&scope, &req, Utc::now()));
    }

    #[test]
    fn counterparty_not_on_allow_list_is_denied() {
        let mut scope = base_scope();
        scope.counterparties = Some(Counterparties {
            allow: Some(vec!["acme".into()]),
            deny: None,
        });
        let mut req = base_request();
        req.counterparty = Some("someone_else".into());
        assert!(!matches(&scope, &req, Utc::now()));
    }

    #[test]
    fn narrows_rejects_widened_actions() {
        let parent = Scope {
            actions: vec!["read_invoice".into()],
            ..Default::default()
        };
        let child = Scope {
            actions: vec!["read_invoice".into(), "create_payment".into()],
            ..Default::default()
        };
        assert!(!narrows(&parent, &child));
    }

    #[test]
    fn narrows_accepts_subset_actions() {
        let parent = Scope {
            actions: vec!["read_invoice".into(), "create_payment".into()],
            ..Default::default()
        };
        let child = Scope {
            actions: vec!["read_invoice".into()],
            ..Default::default()
        };
        assert!(narrows(&parent, &child));
    }

    #[test]
    fn narrows_rejects_raised_amount_ceiling() {
        let parent = Scope {
            actions: vec!["create_payment".into()],
            max_amount: Some(Amount {
                value: 100.0,
                currency: "EUR".into(),
            }),
            ..Default::default()
        };
        let child = Scope {
            actions: vec!["create_payment".into()],
            max_amount: Some(Amount {
                value: 500.0,
                currency: "EUR".into(),
            }),
            ..Default::default()
        };
        assert!(!narrows(&parent, &child));
    }

    #[test]
    fn narrows_rejects_dropping_a_parent_deny_entry() {
        let parent = Scope {
            actions: vec!["create_payment".into()],
            counterparties: Some(Counterparties {
                allow: None,
                deny: Some(vec!["blocked_corp".into()]),
            }),
            ..Default::default()
        };
        let child = Scope {
            actions: vec!["create_payment".into()],
            counterparties: Some(Counterparties {
                allow: None,
                deny: None,
            }),
            ..Default::default()
        };
        assert!(!narrows(&parent, &child));
    }

    #[test]
    fn denies_negative_amount_even_though_it_is_under_the_ceiling() {
        let mut scope = base_scope();
        scope.max_amount = Some(Amount {
            value: 100.0,
            currency: "EUR".into(),
        });
        let mut req = base_request();
        req.amount = Some(Amount {
            value: -5000.0,
            currency: "EUR".into(),
        });
        assert!(!matches(&scope, &req, Utc::now()));
    }

    #[test]
    fn denies_non_finite_amounts() {
        let mut scope = base_scope();
        scope.max_amount = Some(Amount {
            value: f64::INFINITY,
            currency: "EUR".into(),
        });
        let mut req = base_request();
        req.amount = Some(Amount {
            value: 1.0,
            currency: "EUR".into(),
        });
        assert!(
            !matches(&scope, &req, Utc::now()),
            "an infinite ceiling is malformed scope data and must fail closed"
        );
    }

    #[test]
    fn narrows_rejects_negative_child_ceiling() {
        let parent = Scope {
            actions: vec!["create_payment".into()],
            max_amount: Some(Amount {
                value: 100.0,
                currency: "EUR".into(),
            }),
            ..Default::default()
        };
        let child = Scope {
            actions: vec!["create_payment".into()],
            max_amount: Some(Amount {
                value: -1.0,
                currency: "EUR".into(),
            }),
            ..Default::default()
        };
        assert!(!narrows(&parent, &child));
    }

    fn weekday_office_hours_vienna() -> TimeWindow {
        TimeWindow {
            days: vec![
                Weekday::Mon,
                Weekday::Tue,
                Weekday::Wed,
                Weekday::Thu,
                Weekday::Fri,
            ],
            start: "09:00".into(),
            end: "17:00".into(),
            timezone: "Europe/Vienna".into(),
        }
    }

    #[test]
    fn time_window_respects_named_timezone() {
        let mut scope = base_scope();
        scope.time_windows = Some(vec![weekday_office_hours_vienna()]);
        let req = base_request();
        // 2024-01-08 is a Monday. 08:00 UTC = 09:00 CET — right at the boundary, should pass.
        let monday_morning = Utc.with_ymd_and_hms(2024, 1, 8, 8, 0, 0).unwrap();
        assert!(matches(&scope, &req, monday_morning));
        // 2024-01-08 20:00 UTC = 21:00 CET — outside the window.
        let monday_evening = Utc.with_ymd_and_hms(2024, 1, 8, 20, 0, 0).unwrap();
        assert!(!matches(&scope, &req, monday_evening));
    }

    #[test]
    fn time_window_ignores_the_agent_supplied_timestamp() {
        let mut scope = base_scope();
        scope.time_windows = Some(vec![weekday_office_hours_vienna()]);
        let mut req = base_request();
        // The agent claims Monday 10:00 Vienna time...
        req.timestamp = Utc.with_ymd_and_hms(2024, 1, 8, 9, 0, 0).unwrap();
        // ...but the Verifier is evaluating on Sunday 2024-01-07, 15:00 Vienna time.
        let sunday = Utc.with_ymd_and_hms(2024, 1, 7, 14, 0, 0).unwrap();
        assert!(!matches(&scope, &req, sunday));
    }

    fn eur(value: f64) -> Amount {
        Amount {
            value,
            currency: "EUR".into(),
        }
    }

    #[test]
    fn narrows_rejects_a_ceiling_the_parent_never_granted() {
        // The parent allows no amounts at all (`matches` step 3). A child
        // ceiling, however small, would let money through.
        let parent = base_scope();
        let child = Scope {
            actions: vec!["create_payment".into()],
            max_amount: Some(eur(1_000_000_000.0)),
            ..Default::default()
        };
        assert!(!narrows(&parent, &child));

        let mut req = base_request();
        req.amount = Some(eur(999_999_999.0));
        assert!(!matches(&parent, &req, Utc::now()));
    }

    #[test]
    fn narrows_still_accepts_a_child_without_a_ceiling_under_a_parent_without_one() {
        let parent = base_scope();
        let child = Scope {
            actions: vec!["read_invoice".into()],
            ..Default::default()
        };
        assert!(narrows(&parent, &child));
    }

    #[test]
    fn parse_hm_accepts_only_strict_24_hour_times() {
        assert_eq!(parse_hm("00:00"), Some(0));
        assert_eq!(parse_hm("09:30"), Some(570));
        assert_eq!(parse_hm("23:59"), Some(1439));
        for bad in [
            "9:00",
            "09:0",
            "24:00",
            "23:60",
            "16:120",
            "00:1439",
            "+1:00",
            "1:000",
            "09-00",
            " 09:00",
            "09:00 ",
            "",
            "٠٩:٠٠",
        ] {
            assert_eq!(parse_hm(bad), None, "{bad:?} must not parse");
        }
    }

    fn all_days_utc(start: &str, end: &str) -> TimeWindow {
        TimeWindow {
            days: vec![
                Weekday::Mon,
                Weekday::Tue,
                Weekday::Wed,
                Weekday::Thu,
                Weekday::Fri,
                Weekday::Sat,
                Weekday::Sun,
            ],
            start: start.into(),
            end: end.into(),
            timezone: "UTC".into(),
        }
    }

    #[test]
    fn narrows_rejects_out_of_range_minutes_that_stretch_a_window() {
        // Compared as (hour, minute) tuples, (0, 1439) <= (1, 0) held, yet the
        // child window covered the whole day.
        let mut parent = base_scope();
        parent.time_windows = Some(vec![all_days_utc("00:00", "01:00")]);
        let mut child = base_scope();
        child.time_windows = Some(vec![all_days_utc("00:00", "00:1439")]);
        assert!(!narrows(&parent, &child));
    }

    #[test]
    fn malformed_window_never_matches() {
        let req = base_request();
        let morning = Utc.with_ymd_and_hms(2024, 1, 8, 8, 26, 0).unwrap();
        for (start, end) in [("00:00", "00:1439"), ("08:00", "24:00"), ("8:00", "09:00")] {
            let mut scope = base_scope();
            scope.time_windows = Some(vec![all_days_utc(start, end)]);
            assert!(!matches(&scope, &req, morning), "{start}-{end}");
        }
        let mut scope = base_scope();
        scope.time_windows = Some(vec![all_days_utc("08:00", "09:00")]);
        assert!(matches(&scope, &req, morning));
    }
}
