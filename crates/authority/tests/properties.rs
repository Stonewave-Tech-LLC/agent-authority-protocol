//! Property tests (0004 "Tests", item 4):
//!
//! 1. Cumulative evaluation never accepts what any single link's
//!    constraints reject; it accepts exactly when every link does. Checked
//!    on the pure evaluator and through the full verifier on signed chains.
//! 2. `narrows(p, c)` implies that everything `c` accepts, `p` accepts.
//!    Children are derived from parents by random narrowing, with random
//!    widening mixed in, so both outcomes of `narrows` are exercised; an
//!    honestly narrowed child must always be recognised.

mod common;

use aap_authority::{
    evaluate_chain, narrows, ClosedMandate, EvalEnv, Nonce, OpenMandate, TransactionContext,
    Verifier,
};
use aap_sdjwt::SigningKey;
use common::*;
use proptest::prelude::*;
use proptest::sample::subsequence;
use serde_json::{json, Value};

const ACTIONS: &[&str] = &["a", "b", "c", "d"];
const RESOURCES: &[&str] = &["r1", "r2", "r3"];
const PARTIES: &[&str] = &["p1", "p2", "p3", "p4"];
const CATEGORIES: &[&str] = &["c1", "c2", "c3"];
const DAYS: &[&str] = &["mon", "tue", "wed", "thu", "fri", "sat", "sun"];
const ZONES: &[&str] = &["UTC", "Europe/Vienna"];
const CURRENCIES: &[&str] = &["EUR", "USD"];

fn strings(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

fn subset(of: &'static [&'static str]) -> impl Strategy<Value = Vec<String>> {
    subsequence(of, 1..=of.len()).prop_map(|v| strings(&v))
}

#[derive(Debug, Clone)]
struct Window {
    days: Vec<String>,
    start: u32,
    end: u32,
    zone: &'static str,
}

fn hm(minutes: u32) -> String {
    format!("{:02}:{:02}", minutes / 60, minutes % 60)
}

fn window() -> impl Strategy<Value = Window> {
    (
        subset(DAYS),
        (0u32..48).prop_map(|h| h * 30),
        (1u32..48).prop_map(|h| h * 30),
        prop::sample::select(ZONES),
    )
        .prop_filter("start != end", |(_, s, e, _)| s != e)
        .prop_map(|(days, start, end, zone)| Window {
            days,
            start,
            end,
            zone,
        })
}

/// An AAP open mandate, before it becomes JSON.
#[derive(Debug, Clone)]
struct Spec {
    actions: Vec<String>,
    resources: Option<Vec<String>>,
    amount: Option<(u64, &'static str)>,
    allow: Option<Vec<String>>,
    deny: Option<Vec<String>>,
    categories: Option<Vec<String>>,
    windows: Option<Vec<Window>>,
    depth: Option<u32>,
}

impl Spec {
    fn json(&self) -> Value {
        let mut c = vec![json!({"type": "aap.actions", "allowed": self.actions})];
        if let Some(r) = &self.resources {
            c.push(json!({"type": "aap.resources", "allowed": r}));
        }
        if let Some((max, cur)) = self.amount {
            c.push(json!({"type": "aap.amount", "max": max, "currency": cur}));
        }
        if self.allow.is_some() || self.deny.is_some() {
            let mut cp = json!({"type": "aap.counterparties"});
            if let Some(a) = &self.allow {
                cp["allow"] = json!(a);
            }
            if let Some(d) = &self.deny {
                cp["deny"] = json!(d);
            }
            c.push(cp);
        }
        if let Some(cats) = &self.categories {
            c.push(json!({"type": "aap.data_categories", "allowed": cats}));
        }
        if let Some(ws) = &self.windows {
            let ws: Vec<Value> = ws
                .iter()
                .map(|w| json!({"days": w.days, "start": hm(w.start), "end": hm(w.end), "timezone": w.zone}))
                .collect();
            c.push(json!({"type": "aap.time_windows", "windows": ws}));
        }
        if let Some(d) = self.depth {
            c.push(json!({"type": "aap.delegation", "max_depth": d}));
        }
        authority(Value::Array(c))
    }

    fn open(&self) -> OpenMandate {
        OpenMandate::parse(&obj(self.json()), "k").unwrap()
    }
}

fn spec() -> impl Strategy<Value = Spec> {
    (
        subset(ACTIONS),
        prop::option::of(subset(RESOURCES)),
        prop::option::of((0u64..1000, prop::sample::select(CURRENCIES))),
        (
            prop::option::of(subset(PARTIES)),
            prop::option::of(subset(PARTIES)),
        ),
        prop::option::of(subset(CATEGORIES)),
        prop::option::of(prop::collection::vec(window(), 1..3)),
        prop::option::of(0u32..4),
    )
        .prop_map(
            |(actions, resources, amount, (allow, deny), categories, windows, depth)| Spec {
                actions,
                resources,
                amount,
                allow,
                deny,
                categories,
                windows,
                depth,
            },
        )
}

/// Keeps the elements whose bit in `mask` is set, and at least one.
fn keep<T: Clone>(items: &[T], mask: u64) -> Vec<T> {
    let kept: Vec<T> = items
        .iter()
        .enumerate()
        .filter(|(i, _)| mask >> (i % 64) & 1 == 1)
        .map(|(_, x)| x.clone())
        .collect();
    if kept.is_empty() {
        vec![items[0].clone()]
    } else {
        kept
    }
}

fn pick<T>(widen: bool, narrowed: T, wide: T) -> T {
    if widen {
        wide
    } else {
        narrowed
    }
}

/// A parent (allowed to delegate) and a child derived from it: each field
/// narrowed by a random mask, or, where `widen` says so, replaced by the
/// unrelated `other`'s field.
fn parent_and_child() -> impl Strategy<Value = (Spec, Spec, bool)> {
    (
        spec(),
        1u32..4,
        prop::array::uniform8(any::<u64>()),
        prop::array::uniform8(prop::bool::weighted(0.15)),
        spec(),
    )
        .prop_map(|(mut p, depth, masks, widen, other)| {
            p.depth = Some(depth);
            let child = Spec {
                actions: pick(widen[0], keep(&p.actions, masks[0]), other.actions.clone()),
                resources: pick(
                    widen[1],
                    p.resources.as_ref().map(|r| keep(r, masks[1])),
                    other.resources.clone(),
                ),
                amount: pick(
                    widen[2],
                    p.amount
                        .map(|(max, cur)| (max * (masks[2] % 101) / 100, cur)),
                    other.amount,
                ),
                allow: pick(
                    widen[3],
                    p.allow.as_ref().map(|a| keep(a, masks[3])),
                    other.allow.clone(),
                ),
                deny: pick(
                    widen[4],
                    match (&p.deny, &other.deny) {
                        (Some(d), extra) => {
                            let mut d = d.clone();
                            d.extend(
                                extra
                                    .iter()
                                    .flatten()
                                    .filter(|x| !d.contains(x))
                                    .cloned()
                                    .collect::<Vec<_>>(),
                            );
                            Some(d)
                        }
                        // Adding a deny list to an allow-only parent narrows.
                        (None, extra) if p.allow.is_some() => extra.clone(),
                        (None, _) => None,
                    },
                    other.deny.clone(),
                ),
                categories: pick(
                    widen[5],
                    p.categories.as_ref().map(|c| keep(c, masks[5])),
                    other.categories.clone(),
                ),
                windows: pick(
                    widen[6],
                    p.windows.as_ref().map(|w| keep(w, masks[6])),
                    other.windows.clone(),
                ),
                depth: pick(
                    widen[7],
                    depth.checked_sub(1).filter(|d| *d > 0),
                    other.depth,
                ),
            };
            (p, child, widen.iter().any(|w| *w))
        })
}

/// A closed `aap.action.1` and the verifier time to judge it at.
fn closed_action() -> impl Strategy<Value = (ClosedMandate, i64)> {
    let with_outsiders = |v: &[&'static str], extra: &'static str| {
        let mut all = v.to_vec();
        all.push(extra);
        all
    };
    (
        prop::sample::select(with_outsiders(ACTIONS, "z")),
        prop::option::of(prop::sample::select(with_outsiders(RESOURCES, "r9"))),
        prop::option::of((0u64..1200, prop::sample::select(CURRENCIES))),
        prop::option::of(prop::sample::select(with_outsiders(PARTIES, "p9"))),
        prop::option::of(subsequence(with_outsiders(CATEGORIES, "c9"), 1..=2)),
        0i64..(14 * 24 * 60),
    )
        .prop_map(|(a, r, amount, cp, cats, minute)| {
            let mut v = json!({"action": a});
            if let Some(r) = r {
                v["resource"] = json!(r);
            }
            if let Some((m, cur)) = amount {
                v["amount"] = json!({"amount": m, "currency": cur});
            }
            if let Some(cp) = cp {
                v["counterparty"] = json!(cp);
            }
            if let Some(cats) = cats {
                v["data_categories"] = json!(cats);
            }
            let closed = ClosedMandate::parse(&obj(action(v))).unwrap();
            (closed, NOW + minute * 60)
        })
}

fn tx() -> TransactionContext {
    TransactionContext::new(Nonce::Challenge(CHALLENGE.into()))
}

fn env(tx: &TransactionContext, now: i64) -> EvalEnv<'_> {
    EvalEnv {
        now,
        tx,
        ledger: None,
        checkout: None,
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1024))]

    #[test]
    fn cumulative_evaluation_accepts_exactly_what_every_link_accepts(
        chain in prop::collection::vec(spec(), 1..5),
        actions in prop::collection::vec(closed_action(), 24),
    ) {
        let opens: Vec<OpenMandate> = chain.iter().map(Spec::open).collect();
        let tx = tx();
        for (closed, now) in &actions {
            let env = env(&tx, *now);
            let each: Vec<bool> = opens.iter().map(|o| o.accepts(closed, &env).is_ok()).collect();
            match evaluate_chain(&opens, closed, &env) {
                Ok(()) => prop_assert!(each.iter().all(|ok| *ok)),
                Err(failure) => {
                    // The reported link rejects, and every earlier one accepts.
                    prop_assert!(!each[failure.link]);
                    prop_assert!(each[..failure.link].iter().all(|ok| *ok));
                }
            }
        }
    }

    #[test]
    fn narrows_implies_child_acceptance_is_parent_acceptance(
        (parent, child, widened) in parent_and_child(),
        actions in prop::collection::vec(closed_action(), 32),
    ) {
        let (p, c) = (parent.open(), child.open());
        let holds = narrows(&p, &c);
        // Completeness for honest narrowing: never refuse a child that was
        // only narrowed.
        if !widened {
            prop_assert!(holds, "honest child refused:\nparent {}\nchild {}", parent.json(), child.json());
        }
        if holds {
            let tx = tx();
            for (closed, now) in &actions {
                let env = env(&tx, *now);
                if c.accepts(closed, &env).is_ok() {
                    prop_assert!(
                        p.accepts(closed, &env).is_ok(),
                        "child accepts what parent rejects:\nparent {}\nchild {}\naction {:?} at {now}",
                        parent.json(), child.json(), closed.claims()
                    );
                }
            }
        }
    }
}

proptest! {
    // Signing makes these slower; fewer cases, same property, end to end.
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn the_verifier_never_accepts_what_a_link_rejects(
        chain in prop::collection::vec(spec(), 1..4),
        (closed, _) in closed_action(),
    ) {
        let keys = Keys::new();
        // Allow the chain's own depth so depth limits do not mask the
        // constraint check under test.
        let opens: Vec<Value> = chain
            .iter()
            .map(|s| Spec { depth: Some(3), ..s.clone() }.json())
            .collect();
        let presentation = Chain::new(&keys, opens.clone(), Value::Object(closed.claims().clone())).build();
        let receipt = SigningKey::generate_p256();
        let status = valid_status();
        let verifier = Verifier::new(policy(), VERIFIER, &receipt, &status);
        let accepted = run(&verifier, &keys, &presentation, &tx()).outcome().is_ok();

        let tx = tx();
        let env = env(&tx, NOW);
        let every_link = opens
            .iter()
            .all(|o| OpenMandate::parse(&obj(o.clone()), "k").unwrap().accepts(&closed, &env).is_ok());
        prop_assert_eq!(accepted, every_link);
    }
}

// ---- AP2 payment constraints ------------------------------------------------

const PAYEES: &[&str] = &["m1", "m2", "m3"];
const INSTRUMENTS: &[&str] = &["i1", "i2", "i3"];
/// 2026-04-01T00:00:00Z.
const APRIL: i64 = 1_775_001_600;

#[derive(Debug, Clone)]
struct PaymentSpec {
    range: Option<(u64, u64, &'static str)>,
    payees: Option<Vec<String>>,
    instruments: Option<Vec<String>>,
    /// Days after `APRIL`.
    dates: Option<(Option<u32>, Option<u32>)>,
    depth: Option<u32>,
}

fn day(n: u32) -> String {
    let t = chrono::DateTime::from_timestamp(APRIL + i64::from(n) * 86_400, 0).unwrap();
    t.format("%Y-%m-%d").to_string()
}

impl PaymentSpec {
    fn open(&self) -> OpenMandate {
        let mut c = Vec::new();
        if let Some((min, max, cur)) = self.range {
            c.push(
                json!({"type": "payment.amount_range", "currency": cur, "min": min, "max": max}),
            );
        }
        if let Some(p) = &self.payees {
            let p: Vec<Value> = p.iter().map(|id| json!({"id": id, "name": id})).collect();
            c.push(json!({"type": "payment.allowed_payees", "allowed": p}));
        }
        if let Some(i) = &self.instruments {
            let i: Vec<Value> = i
                .iter()
                .map(|id| json!({"id": id, "type": "card"}))
                .collect();
            c.push(json!({"type": "payment.allowed_payment_instruments", "allowed": i}));
        }
        if let Some((nb, na)) = self.dates {
            let mut d = json!({"type": "payment.execution_date"});
            if let Some(nb) = nb {
                d["not_before"] = json!(day(nb));
            }
            if let Some(na) = na {
                d["not_after"] = json!(day(na));
            }
            c.push(d);
        }
        if let Some(depth) = self.depth {
            c.push(json!({"type": "aap.delegation", "max_depth": depth}));
        }
        let m = json!({"vct": "mandate.payment.open.1", "constraints": c});
        OpenMandate::parse(&obj(m), "k").unwrap()
    }
}

fn payment_spec() -> impl Strategy<Value = PaymentSpec> {
    (
        prop::option::of((0u64..500, 0u64..1000, prop::sample::select(CURRENCIES))),
        prop::option::of(subset(PAYEES)),
        prop::option::of(subset(INSTRUMENTS)),
        prop::option::of((prop::option::of(0u32..20), prop::option::of(10u32..30))),
    )
        .prop_map(|(range, payees, instruments, dates)| PaymentSpec {
            range: range.map(|(a, b, cur)| (a.min(b), a.max(b), cur)),
            payees,
            instruments,
            dates: dates
                .filter(|(nb, na)| nb.is_some() || na.is_some())
                .map(|(nb, na)| match (nb, na) {
                    (Some(b), Some(a)) => (Some(b.min(a)), Some(b.max(a))),
                    other => other,
                }),
            depth: None,
        })
}

/// As `parent_and_child`, for payment mandates. The parent may delegate
/// once; the child delegates no further.
fn payment_parent_and_child() -> impl Strategy<Value = (PaymentSpec, PaymentSpec, bool)> {
    (
        payment_spec(),
        prop::array::uniform4(any::<u64>()),
        prop::array::uniform4(prop::bool::weighted(0.2)),
        payment_spec(),
    )
        .prop_map(|(mut p, masks, widen, other)| {
            p.depth = Some(1);
            let later = (masks[3] % 3) as u32;
            let child = PaymentSpec {
                range: pick(
                    widen[0],
                    p.range.map(|(min, max, cur)| {
                        let shrink = masks[0] % (max - min + 1) / 2;
                        (min + shrink, max - shrink, cur)
                    }),
                    other.range,
                ),
                payees: pick(
                    widen[1],
                    p.payees.as_ref().map(|x| keep(x, masks[1])),
                    other.payees.clone(),
                ),
                instruments: pick(
                    widen[2],
                    p.instruments.as_ref().map(|x| keep(x, masks[2])),
                    other.instruments.clone(),
                ),
                dates: pick(
                    widen[3],
                    p.dates.map(|(nb, na)| match (nb, na) {
                        (Some(b), Some(a)) => (Some((b + later).min(a)), Some(a)),
                        (Some(b), None) => (Some(b + later), None),
                        (None, a) => (None, a.map(|a| a.saturating_sub(later))),
                    }),
                    other.dates,
                ),
                depth: None,
            };
            (p, child, widen.iter().any(|w| *w))
        })
}

fn closed_payment() -> impl Strategy<Value = (ClosedMandate, i64)> {
    (
        prop::sample::select(vec!["m1", "m2", "m3", "m9"]),
        prop::sample::select(vec!["i1", "i2", "i3", "i9"]),
        0u64..1100,
        prop::sample::select(CURRENCIES),
        prop::option::of(0u32..32),
        0u32..32,
    )
        .prop_map(|(payee, instrument, amount, cur, date, today)| {
            let mut v = payment(payee, amount, cur);
            v["payment_instrument"]["id"] = json!(instrument);
            if let Some(d) = date {
                v["execution_date"] = json!(day(d));
            }
            let closed = ClosedMandate::parse(&obj(v)).unwrap();
            (closed, APRIL + i64::from(today) * 86_400 + 43_200)
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1024))]

    #[test]
    fn narrows_is_sound_for_payment_constraints(
        (parent, child, widened) in payment_parent_and_child(),
        payments in prop::collection::vec(closed_payment(), 32),
    ) {
        let (p, c) = (parent.open(), child.open());
        let holds = narrows(&p, &c);
        if !widened {
            prop_assert!(holds, "honest child refused: {parent:?} / {child:?}");
        }
        if holds {
            let tx = payment_tx();
            for (closed, now) in &payments {
                let env = env(&tx, *now);
                if c.accepts(closed, &env).is_ok() {
                    prop_assert!(
                        p.accepts(closed, &env).is_ok(),
                        "{parent:?} / {child:?} / {:?}", closed.claims()
                    );
                }
            }
        }
    }
}
