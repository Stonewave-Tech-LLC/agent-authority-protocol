//! Every type name this crate knows: mandate types (`vct`), constraint
//! types, and the receipt `typ`.
//!
//! AAP's own names are built from one prefix, [`AAP_NAMESPACE`], through the
//! `aap!` macro. The final namespace is undecided (0001, 0004 open question
//! 1; candidates like `com.stonewavetech.aap`), so changing it is a one-line
//! edit here. AP2's names are AP2's and do not move.

/// Placeholder namespace for AAP type names. Not final.
pub const AAP_NAMESPACE: &str = "aap";

/// `aap!("actions")` is `"<AAP_NAMESPACE>.actions"`. A macro rather than a
/// function so the names stay `&'static str` constants usable in `match`.
macro_rules! aap {
    ($name:literal) => {
        concat!("aap", ".", $name)
    };
}

/// AAP mandate and constraint types (0004 "Mapping from v0", 0005).
pub mod aap {
    /// Open mandate for non-payment domains.
    pub const AUTHORITY_OPEN: &str = aap!("authority.open.1");
    /// Closed mandate: one concrete action.
    pub const ACTION: &str = aap!("action.1");

    pub const ACTIONS: &str = aap!("actions");
    pub const RESOURCES: &str = aap!("resources");
    pub const AMOUNT: &str = aap!("amount");
    pub const COUNTERPARTIES: &str = aap!("counterparties");
    pub const DATA_CATEGORIES: &str = aap!("data_categories");
    pub const TIME_WINDOWS: &str = aap!("time_windows");
    pub const DELEGATION: &str = aap!("delegation");

    /// Informational claims: rendered as "the agent says", never binding.
    pub const AGENT: &str = aap!("agent");
    pub const NOTE: &str = aap!("note");
}

/// AP2 v0.2 mandate and constraint types (AP2 SDK at e1ea56d,
/// `code/sdk/python/ap2/sdk/generated`).
pub mod ap2 {
    pub const CHECKOUT_OPEN: &str = "mandate.checkout.open.1";
    pub const CHECKOUT: &str = "mandate.checkout.1";
    pub const PAYMENT_OPEN: &str = "mandate.payment.open.1";
    pub const PAYMENT: &str = "mandate.payment.1";

    pub const ALLOWED_MERCHANTS: &str = "checkout.allowed_merchants";
    pub const LINE_ITEMS: &str = "checkout.line_items";

    pub const AMOUNT_RANGE: &str = "payment.amount_range";
    pub const ALLOWED_PAYEES: &str = "payment.allowed_payees";
    pub const ALLOWED_PAYMENT_INSTRUMENTS: &str = "payment.allowed_payment_instruments";
    pub const ALLOWED_PISPS: &str = "payment.allowed_pisps";
    pub const BUDGET: &str = "payment.budget";
    pub const AGENT_RECURRENCE: &str = "payment.agent_recurrence";
    pub const EXECUTION_DATE: &str = "payment.execution_date";
    pub const REFERENCE: &str = "payment.reference";
}

/// JOSE `typ` of a Mandate Receipt. AP2 defines none (its SDK signs receipts
/// as plain `JWT`); an explicit type keeps a receipt from being mistaken for
/// any other JWT (0004 "`typ` is checked per position").
pub const RECEIPT_TYP: &str = "mandate-receipt+jwt";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aap_names_use_the_namespace_constant() {
        // The macro cannot read the constant, so pin them together here.
        for name in [
            aap::AUTHORITY_OPEN,
            aap::ACTION,
            aap::ACTIONS,
            aap::DELEGATION,
        ] {
            assert!(name.starts_with(&format!("{AAP_NAMESPACE}.")), "{name}");
        }
    }
}
