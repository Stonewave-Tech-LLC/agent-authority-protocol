//! AP2 v0.2 checkout and payment constraints, as the specification text
//! defines them (docs/ap2/checkout_mandate.md, payment_mandate.md at
//! e1ea56d). Where the reference SDK is looser than the text, the text wins
//! and the difference is noted at the item:
//!
//! - `checkout.line_items` requires the cart to fill every requirement
//!   exactly (the text: max flow equals *both* totals); the SDK only checks
//!   that the cart fits, and treats an empty `acceptable_items` as a
//!   wildcard. Here an empty list matches nothing.
//! - `payment.budget.max` is integer minor units, like every amount in AAP;
//!   the SDK reads a float and multiplies by 100.
//! - `payment.agent_recurrence` also enforces the spacing `frequency`
//!   implies; the SDK only counts occurrences.
//! - `payment.execution_date` compares instants, not strings, and an absent
//!   execution date means "now" (immediate execution), not "pass".
//! - Merchants and payees match by `id` only (0005 UC09-A2: identify
//!   accounts, never names); the SDK falls back to name + website.

use chrono::{DateTime, Months, NaiveDate};
use serde_json::Value;

use crate::amount::Currency;
use crate::context::EvalEnv;
use crate::mandate::PaymentMandate;
use crate::schema::{Fields, SchemaError};

use super::{unresolved, violated, Failure};

/// AP2 `Merchant`. Only `id` is used for matching.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Merchant {
    pub id: String,
    pub name: Option<String>,
    pub website: Option<String>,
}

impl Merchant {
    /// Lenient about extra members: a merchant object describes, it does
    /// not restrict. Strict about `id`, the only thing compared.
    pub fn parse(value: &Value) -> Result<Self, SchemaError> {
        let mut f = Fields::new(value, "merchant")?;
        Ok(Merchant {
            id: f.string("id")?,
            name: f.opt_string("name")?,
            website: f.opt_string("website")?,
        })
    }
}

/// AP2 `PaymentInstrument`. Matched by `id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentInstrument {
    pub id: String,
    pub kind: String,
}

impl PaymentInstrument {
    pub fn parse(value: &Value) -> Result<Self, SchemaError> {
        let mut f = Fields::new(value, "payment instrument")?;
        Ok(PaymentInstrument {
            id: f.string("id")?,
            kind: f.string("type")?,
        })
    }
}

/// AP2 `PISP`. Matched on all three names, as the SDK does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pisp {
    pub legal_name: String,
    pub brand_name: String,
    pub domain_name: String,
}

impl Pisp {
    pub fn parse(value: &Value) -> Result<Self, SchemaError> {
        let mut f = Fields::new(value, "pisp")?;
        Ok(Pisp {
            legal_name: f.string("legal_name")?,
            brand_name: f.string("brand_name")?,
            domain_name: f.string("domain_name")?,
        })
    }
}

/// One entry of `checkout.line_items`: `quantity` units drawn from the
/// revealed `acceptable_items`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LineItemRequirement {
    pub id: String,
    /// Item ids, sorted and de-duplicated so equal requirements compare
    /// equal.
    pub acceptable: Vec<String>,
    pub quantity: u64,
}

impl LineItemRequirement {
    pub fn parse(value: &Value) -> Result<Self, SchemaError> {
        let mut f = Fields::new(value, "line item requirement")?;
        let id = f.string("id")?;
        let mut acceptable = f.array("acceptable_items", |item| {
            Fields::new(item, "acceptable item")?.string("id")
        })?;
        acceptable.sort();
        acceptable.dedup();
        let quantity = f.uint("quantity")?;
        if quantity == 0 {
            return Err(f.error("quantity must be at least 1"));
        }
        f.finish()?;
        Ok(LineItemRequirement {
            id,
            acceptable,
            quantity,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AmountRange {
    pub currency: Currency,
    pub min: Option<u64>,
    pub max: u64,
}

impl AmountRange {
    pub(super) fn parse(f: &mut Fields<'_>) -> Result<Self, SchemaError> {
        let r = AmountRange {
            currency: f.currency("currency")?,
            min: f.opt_uint("min")?,
            max: f.uint("max")?,
        };
        if r.min.is_some_and(|min| min > r.max) {
            return Err(f.error("min is greater than max"));
        }
        Ok(r)
    }

    pub(super) fn evaluate(&self, p: &PaymentMandate) -> Result<(), Failure> {
        let amount = &p.payment_amount;
        if amount.currency != self.currency {
            return Err(violated(format!(
                "currency {} does not match {}",
                amount.currency, self.currency
            )));
        }
        if amount.minor > self.max {
            return Err(violated(format!(
                "amount {} exceeds maximum {}",
                amount.minor, self.max
            )));
        }
        match self.min {
            Some(min) if amount.minor < min => Err(violated(format!(
                "amount {} is below minimum {min}",
                amount.minor
            ))),
            _ => Ok(()),
        }
    }

    pub(super) fn covers(&self, child: &AmountRange) -> bool {
        self.currency == child.currency
            && child.max <= self.max
            && child.min.unwrap_or(0) >= self.min.unwrap_or(0)
    }
}

/// `payment.budget`: total over all uses of the mandate that carries it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Budget {
    pub max: u64,
    pub currency: Currency,
}

impl Budget {
    pub(super) fn parse(f: &mut Fields<'_>) -> Result<Self, SchemaError> {
        Ok(Budget {
            max: f.uint("max")?,
            currency: f.currency("currency")?,
        })
    }

    pub(super) fn evaluate(
        &self,
        p: &PaymentMandate,
        env: &EvalEnv<'_>,
        key: &str,
    ) -> Result<(), Failure> {
        if p.payment_amount.currency != self.currency {
            return Err(violated(format!(
                "currency {} does not match the budget's {}",
                p.payment_amount.currency, self.currency
            )));
        }
        let ledger = env
            .ledger
            .ok_or_else(|| unresolved("payment.budget needs a usage ledger"))?;
        let usage = ledger.usage(key).map_err(|e| unresolved(e.to_string()))?;
        match usage.total_minor.checked_add(p.payment_amount.minor) {
            Some(total) if total <= self.max => Ok(()),
            _ => Err(violated(format!(
                "cumulative spend would exceed the budget {} (spent {})",
                self.max, usage.total_minor
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Frequency {
    OnDemand,
    Daily,
    Weekly,
    Biweekly,
    Monthly,
    Quarterly,
    Annually,
}

impl Frequency {
    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "ON_DEMAND" => Frequency::OnDemand,
            "DAILY" => Frequency::Daily,
            "WEEKLY" => Frequency::Weekly,
            "BIWEEKLY" => Frequency::Biweekly,
            "MONTHLY" => Frequency::Monthly,
            "QUARTERLY" => Frequency::Quarterly,
            "ANNUALLY" => Frequency::Annually,
            _ => return None,
        })
    }

    /// The earliest verifier time the next use may happen after a use at
    /// `last`. Calendar months in UTC for the monthly kinds.
    fn next_after(self, last: i64) -> Option<i64> {
        const DAY: i64 = 86_400;
        let months = |n: u32| {
            DateTime::from_timestamp(last, 0)?
                .checked_add_months(Months::new(n))
                .map(|t| t.timestamp())
        };
        match self {
            Frequency::OnDemand => Some(last),
            Frequency::Daily => last.checked_add(DAY),
            Frequency::Weekly => last.checked_add(7 * DAY),
            Frequency::Biweekly => last.checked_add(14 * DAY),
            Frequency::Monthly => months(1),
            Frequency::Quarterly => months(3),
            Frequency::Annually => months(12),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentRecurrence {
    pub frequency: Frequency,
    pub max_occurrences: Option<u64>,
}

impl AgentRecurrence {
    pub(super) fn parse(f: &mut Fields<'_>) -> Result<Self, SchemaError> {
        let s = f.string("frequency")?;
        let frequency =
            Frequency::parse(&s).ok_or_else(|| f.error(format!("unknown frequency {s:?}")))?;
        Ok(AgentRecurrence {
            frequency,
            max_occurrences: f.opt_uint("max_occurrences")?,
        })
    }

    pub(super) fn evaluate(&self, env: &EvalEnv<'_>, key: &str) -> Result<(), Failure> {
        let ledger = env
            .ledger
            .ok_or_else(|| unresolved("payment.agent_recurrence needs a usage ledger"))?;
        let usage = ledger.usage(key).map_err(|e| unresolved(e.to_string()))?;
        if let Some(max) = self.max_occurrences {
            if usage.uses >= max {
                return Err(violated(format!(
                    "maximum occurrences reached ({} of {max})",
                    usage.uses
                )));
            }
        }
        if let Some(last) = usage.last_use {
            match self.frequency.next_after(last) {
                Some(next) if env.now >= next => {}
                _ => {
                    return Err(violated(
                        "too soon after the previous use for its frequency",
                    ))
                }
            }
        }
        Ok(())
    }

    pub(super) fn covers(&self, child: &AgentRecurrence) -> bool {
        self.frequency == child.frequency
            && match (self.max_occurrences, child.max_occurrences) {
                (None, _) => true,
                (Some(p), Some(c)) => c <= p,
                (Some(_), None) => false,
            }
    }
}

/// `payment.execution_date`, bounds as seconds since the epoch, inclusive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionDate {
    pub not_before: Option<i64>,
    pub not_after: Option<i64>,
}

impl ExecutionDate {
    pub(super) fn parse(f: &mut Fields<'_>) -> Result<Self, SchemaError> {
        let mut bound = |name, end_of_day| -> Result<Option<i64>, SchemaError> {
            match f.opt_string(name)? {
                None => Ok(None),
                Some(s) => instant_range(&s)
                    .map(|(start, end)| Some(if end_of_day { end } else { start }))
                    .ok_or_else(|| f.error(format!("{name} {s:?} is not an ISO 8601 date"))),
            }
        };
        let d = ExecutionDate {
            not_before: bound("not_before", false)?,
            not_after: bound("not_after", true)?,
        };
        match (d.not_before, d.not_after) {
            (None, None) => Err(f.error("needs not_before, not_after, or both")),
            (Some(a), Some(b)) if a > b => Err(f.error("not_before is after not_after")),
            _ => Ok(d),
        }
    }

    pub(super) fn evaluate(&self, p: &PaymentMandate, now: i64) -> Result<(), Failure> {
        let (start, end) = match &p.execution_date {
            None => (now, now),
            Some(s) => instant_range(s)
                .ok_or_else(|| violated(format!("execution_date {s:?} is not an ISO 8601 date")))?,
        };
        if self.not_before.is_some_and(|nb| start < nb) {
            return Err(violated("execution date is before the allowed window"));
        }
        if self.not_after.is_some_and(|na| end > na) {
            return Err(violated("execution date is after the allowed window"));
        }
        Ok(())
    }

    pub(super) fn covers(&self, child: &ExecutionDate) -> bool {
        let nb = match (self.not_before, child.not_before) {
            (None, _) => true,
            (Some(p), Some(c)) => c >= p,
            (Some(_), None) => false,
        };
        let na = match (self.not_after, child.not_after) {
            (None, _) => true,
            (Some(p), Some(c)) => c <= p,
            (Some(_), None) => false,
        };
        nb && na
    }
}

/// An RFC 3339 date-time is one instant; a bare `YYYY-MM-DD` date is the
/// whole UTC day, first to last second.
fn instant_range(s: &str) -> Option<(i64, i64)> {
    if let Ok(t) = DateTime::parse_from_rfc3339(s) {
        let t = t.timestamp();
        return Some((t, t));
    }
    let day = NaiveDate::parse_from_str(s, "%Y-%m-%d").ok()?;
    let start = day.and_hms_opt(0, 0, 0)?.and_utc().timestamp();
    Some((start, start + 86_399))
}

pub(super) fn allowed_merchants(allowed: &[Merchant], env: &EvalEnv<'_>) -> Result<(), Failure> {
    let checkout = env
        .checkout
        .ok_or_else(|| unresolved("no trusted checkout to read the merchant from"))?;
    let merchant = checkout
        .merchant
        .as_ref()
        .ok_or_else(|| violated("the checkout names no merchant"))?;
    if allowed.iter().any(|m| m.id == merchant.id) {
        Ok(())
    } else {
        Err(violated(format!(
            "merchant {:?} is not allowed",
            merchant.id
        )))
    }
}

pub(super) fn allowed_payees(allowed: &[Merchant], p: &PaymentMandate) -> Result<(), Failure> {
    if allowed.iter().any(|m| m.id == p.payee.id) {
        Ok(())
    } else {
        Err(violated(format!("payee {:?} is not allowed", p.payee.id)))
    }
}

pub(super) fn allowed_instruments(
    allowed: &[PaymentInstrument],
    p: &PaymentMandate,
) -> Result<(), Failure> {
    if allowed.iter().any(|i| i.id == p.payment_instrument.id) {
        Ok(())
    } else {
        Err(violated(format!(
            "payment instrument {:?} is not allowed",
            p.payment_instrument.id
        )))
    }
}

pub(super) fn allowed_pisps(allowed: &[Pisp], p: &PaymentMandate) -> Result<(), Failure> {
    match &p.pisp {
        Some(pisp) if allowed.contains(pisp) => Ok(()),
        Some(pisp) => Err(violated(format!(
            "PISP {:?} is not allowed",
            pisp.domain_name
        ))),
        None => Err(violated("the payment names no PISP")),
    }
}

pub(super) fn reference(id: &str, env: &EvalEnv<'_>) -> Result<(), Failure> {
    match &env.tx.open_checkout_hash {
        None => Err(unresolved(
            "payment.reference needs the open checkout mandate's hash",
        )),
        Some(h) if h == id => Ok(()),
        Some(h) => Err(violated(format!(
            "payment is for open checkout {h:?}, the mandate allows {id:?}"
        ))),
    }
}

/// Upper bound on requirements plus distinct cart items, so a hostile
/// mandate or checkout cannot make matching expensive.
const MAX_LINE_ITEM_NODES: usize = 512;

/// AP2's line-item rule as a max-flow problem: source → requirement
/// (capacity `quantity`), requirement → item (unbounded, if acceptable),
/// item → sink (cart quantity). Met iff the flow equals both totals.
pub(super) fn line_items(
    requirements: &[LineItemRequirement],
    env: &EvalEnv<'_>,
) -> Result<(), Failure> {
    let checkout = env
        .checkout
        .ok_or_else(|| unresolved("no trusted checkout to read line items from"))?;
    let cart = &checkout.line_items;
    if cart.is_empty() {
        return Err(violated("the checkout has no line items"));
    }
    if let Some((sku, _)) = cart
        .iter()
        .find(|(sku, _)| !requirements.iter().any(|r| r.acceptable.contains(sku)))
    {
        return Err(violated(format!(
            "item {sku:?} is not acceptable for any requirement"
        )));
    }
    let (r, s) = (requirements.len(), cart.len());
    if r + s > MAX_LINE_ITEM_NODES {
        return Err(unresolved("too many line items to evaluate"));
    }
    let wanted: u128 = requirements.iter().map(|x| u128::from(x.quantity)).sum();
    let present: u128 = cart.iter().map(|(_, q)| u128::from(*q)).sum();
    if wanted != present {
        return Err(violated(format!(
            "the checkout has {present} items, the mandate requires exactly {wanted}"
        )));
    }

    let n = r + s + 2;
    let (source, sink) = (0, n - 1);
    let mut cap = vec![vec![0u128; n]; n];
    for (i, req) in requirements.iter().enumerate() {
        cap[source][1 + i] = u128::from(req.quantity);
        for (j, (sku, _)) in cart.iter().enumerate() {
            if req.acceptable.contains(sku) {
                cap[1 + i][1 + r + j] = present;
            }
        }
    }
    for (j, (_, qty)) in cart.iter().enumerate() {
        cap[1 + r + j][sink] = u128::from(*qty);
    }
    if max_flow(&mut cap, source, sink) == wanted {
        Ok(())
    } else {
        Err(violated(
            "the checkout's items cannot be assigned to the required line items",
        ))
    }
}

/// Edmonds–Karp on a dense capacity matrix (consumed as the residual graph).
fn max_flow(cap: &mut [Vec<u128>], source: usize, sink: usize) -> u128 {
    let n = cap.len();
    let mut total = 0;
    loop {
        let mut parent = vec![usize::MAX; n];
        parent[source] = source;
        let mut queue = std::collections::VecDeque::from([source]);
        while let Some(u) = queue.pop_front() {
            for v in 0..n {
                if parent[v] == usize::MAX && cap[u][v] > 0 {
                    parent[v] = u;
                    queue.push_back(v);
                }
            }
        }
        if parent[sink] == usize::MAX {
            return total;
        }
        let mut bottleneck = u128::MAX;
        let mut v = sink;
        while v != source {
            let u = parent[v];
            bottleneck = bottleneck.min(cap[u][v]);
            v = u;
        }
        let mut v = sink;
        while v != source {
            let u = parent[v];
            cap[u][v] -= bottleneck;
            cap[v][u] += bottleneck;
            v = u;
        }
        total += bottleneck;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{Nonce, TransactionContext};
    use crate::mandate::Checkout;
    use serde_json::json;

    fn req(id: &str, acceptable: &[&str], quantity: u64) -> LineItemRequirement {
        LineItemRequirement::parse(&json!({
            "id": id,
            "quantity": quantity,
            "acceptable_items": acceptable.iter().map(|a| json!({"id": a, "title": a})).collect::<Vec<_>>(),
        }))
        .unwrap()
    }

    fn check(reqs: &[LineItemRequirement], cart: &[(&str, u64)]) -> Result<(), Failure> {
        let checkout = Checkout {
            merchant: None,
            line_items: cart.iter().map(|(s, q)| (s.to_string(), *q)).collect(),
        };
        let tx = TransactionContext::new(Nonce::Challenge("n".into()));
        let env = EvalEnv {
            now: 0,
            tx: &tx,
            ledger: None,
            checkout: Some(&checkout),
        };
        line_items(reqs, &env)
    }

    #[test]
    fn spec_example_shoes_and_socks() {
        // checkout_mandate.md, "Line Items" example.
        let reqs = [
            req("shoes", &["BAB1234", "FAF1234"], 1),
            req("socks", &["QRT1234"], 1),
        ];
        assert!(check(&reqs, &[("BAB1234", 1), ("QRT1234", 1)]).is_ok());
        assert!(check(&reqs, &[("FAF1234", 1), ("QRT1234", 1)]).is_ok());
        for bad in [
            vec![("BAB1234", 1), ("FAF1234", 1)],
            vec![("BAB1234", 1)],
            vec![("FAF1234", 1)],
            vec![("QRT1234", 1)],
            vec![("BAB1234", 1), ("QRT1234", 2)],
        ] {
            assert!(check(&reqs, &bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn matching_needs_augmenting_paths() {
        // Greedy would put "a" into r1 and get stuck; max flow reassigns.
        let reqs = [req("r1", &["a", "b"], 1), req("r2", &["a"], 1)];
        assert!(check(&reqs, &[("a", 1), ("b", 1)]).is_ok());
        assert!(check(&reqs, &[("b", 2)]).is_err());
    }

    #[test]
    fn empty_acceptable_items_match_nothing() {
        // The SDK reads an empty (all undisclosed) list as a wildcard.
        assert!(LineItemRequirement::parse(&json!({
            "id": "x", "quantity": 1, "acceptable_items": []
        }))
        .is_err());
    }

    #[test]
    fn calendar_frequencies() {
        let jan31 = chrono::NaiveDate::from_ymd_opt(2026, 1, 31)
            .unwrap()
            .and_hms_opt(12, 0, 0)
            .unwrap()
            .and_utc()
            .timestamp();
        let feb28 = jan31 + 28 * 86_400;
        assert_eq!(Frequency::Monthly.next_after(jan31), Some(feb28));
        assert_eq!(Frequency::OnDemand.next_after(jan31), Some(jan31));
    }

    #[test]
    fn execution_dates() {
        let d = ExecutionDate {
            not_before: instant_range("2026-03-31T00:00:00Z").map(|r| r.0),
            not_after: instant_range("2026-04-30").map(|r| r.1),
        };
        let pay = |date: Option<&str>| PaymentMandate {
            transaction_id: "t".into(),
            payee: Merchant {
                id: "m".into(),
                name: None,
                website: None,
            },
            pisp: None,
            payment_amount: crate::amount::Amount {
                minor: 1,
                currency: Currency::parse("USD").unwrap(),
            },
            payment_instrument: PaymentInstrument {
                id: "i".into(),
                kind: "card".into(),
            },
            execution_date: date.map(str::to_owned),
        };
        assert!(d.evaluate(&pay(Some("2026-04-30")), 0).is_ok());
        assert!(d.evaluate(&pay(Some("2026-04-30T23:59:59Z")), 0).is_ok());
        assert!(d.evaluate(&pay(Some("2026-05-01")), 0).is_err());
        assert!(d.evaluate(&pay(Some("2026-03-30T23:59:59Z")), 0).is_err());
        assert!(d.evaluate(&pay(Some("31.03.2026")), 0).is_err());
        // Absent: immediate execution at the verifier's clock.
        let april = instant_range("2026-04-10").unwrap().0;
        assert!(d.evaluate(&pay(None), april).is_ok());
        assert!(d.evaluate(&pay(None), april + 86_400 * 30).is_err());
    }
}
