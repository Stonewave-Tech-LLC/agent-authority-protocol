//! Money: integer minor units and an ISO 4217 alphabetic code (0004
//! "Amounts"). There is no float anywhere, so there is nothing to round, and
//! no sign, so a negative value cannot sit "under" a ceiling (v0 bug 2).

use std::fmt;

/// An ISO 4217 alphabetic code: exactly three ASCII capital letters.
///
/// Only the shape is checked, not membership in the ISO list: the list
/// changes, and a code nobody uses simply never matches a constraint's
/// currency. Comparison is exact, so `usd` is rejected rather than folded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Currency([u8; 3]);

impl Currency {
    pub fn parse(code: &str) -> Result<Self, String> {
        match <[u8; 3]>::try_from(code.as_bytes()) {
            Ok(bytes) if bytes.iter().all(u8::is_ascii_uppercase) => Ok(Currency(bytes)),
            _ => Err(format!(
                "{code:?} is not an ISO 4217 code (three capital letters)"
            )),
        }
    }

    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.0).expect("ASCII by construction")
    }
}

impl fmt::Display for Currency {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An amount in the currency's minor unit (cents for USD, yen for JPY).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Amount {
    pub minor: u64,
    pub currency: Currency,
}

impl fmt::Display for Amount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} (minor units)", self.minor, self.currency)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema;
    use serde_json::json;

    #[test]
    fn currency_codes_are_three_capitals() {
        assert_eq!(Currency::parse("EUR").unwrap().as_str(), "EUR");
        for bad in ["eur", "EU", "EURO", "E1R", "", "€UR"] {
            assert!(Currency::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn amounts_are_non_negative_integers() {
        let ok = schema::amount(&json!({"amount": 19900, "currency": "USD"}), "t").unwrap();
        assert_eq!(ok.minor, 19900);
        for bad in [
            json!({"amount": -1, "currency": "USD"}),
            json!({"amount": 199.0, "currency": "USD"}),
            json!({"amount": 1.5, "currency": "USD"}),
            json!({"amount": "100", "currency": "USD"}),
            json!({"amount": 100, "currency": "usd"}),
            json!({"amount": 100}),
            json!({"amount": 100, "currency": "USD", "value": 5}),
        ] {
            assert!(schema::amount(&bad, "t").is_err(), "{bad}");
        }
    }
}
