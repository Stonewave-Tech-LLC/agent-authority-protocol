//! Deterministic scope matching. No LLM, no heuristics — pure functions over
//! structured data, per spec/scope-matching.md. This is the actual trust
//! boundary of the protocol; keep it boring and exhaustively testable.

use chrono::{DateTime, Datelike, Timelike, Utc, Weekday as ChronoWeekday};
use chrono_tz::Tz;

use crate::types::{ActionRequest, Scope, TimeWindow, Weekday};

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

fn parse_hm(s: &str) -> Option<(u32, u32)> {
    let (h, m) = s.split_once(':')?;
    Some((h.parse().ok()?, m.parse().ok()?))
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
    let (Some((sh, sm)), Some((eh, em))) = (parse_hm(&window.start), parse_hm(&window.end)) else {
        return false;
    };
    let minute_of_day = local.hour() * 60 + local.minute();
    minute_of_day >= sh * 60 + sm && minute_of_day <= eh * 60 + em
}

/// Step-by-step per spec/scope-matching.md `matches(scope, request)`.
pub fn matches(scope: &Scope, request: &ActionRequest) -> bool {
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
            Some(amt) if amt.currency == max.currency && amt.value <= max.value => {}
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
        if !windows
            .iter()
            .any(|w| timestamp_in_window(&request.timestamp, w))
        {
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
            Some(cmax) if cmax.currency == pmax.currency && cmax.value <= pmax.value => {}
            _ => return false,
        }
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
                        .map(|(c, p)| c >= p)
                        .unwrap_or(false)
                    && parse_hm(&child_window.end)
                        .zip(parse_hm(&parent_window.end))
                        .map(|(c, p)| c <= p)
                        .unwrap_or(false)
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
        assert!(!matches(&scope, &req));
    }

    #[test]
    fn allows_action_in_allow_list() {
        assert!(matches(&base_scope(), &base_request()));
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
        assert!(!matches(&scope, &req));
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
        assert!(matches(&scope, &req));
    }

    #[test]
    fn denies_amount_when_scope_never_mentioned_money() {
        let scope = base_scope();
        let mut req = base_request();
        req.amount = Some(Amount {
            value: 1.0,
            currency: "EUR".into(),
        });
        assert!(!matches(&scope, &req));
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
        assert!(!matches(&scope, &req));
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
        assert!(!matches(&scope, &req));
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
        assert!(!matches(&scope, &req));
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
    fn time_window_respects_named_timezone() {
        let mut scope = base_scope();
        scope.time_windows = Some(vec![TimeWindow {
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
        }]);
        let mut req = base_request();
        // 2024-01-08 is a Monday. 08:00 UTC = 09:00 CET — right at the boundary, should pass.
        req.timestamp = Utc.with_ymd_and_hms(2024, 1, 8, 8, 0, 0).unwrap();
        assert!(matches(&scope, &req));
        // 2024-01-08 20:00 UTC = 21:00 CET — outside the window.
        req.timestamp = Utc.with_ymd_and_hms(2024, 1, 8, 20, 0, 0).unwrap();
        assert!(!matches(&scope, &req));
    }
}
