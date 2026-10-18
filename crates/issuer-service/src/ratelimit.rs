//! Per-IP fixed-window rate limiter, in memory. Deliberately simple: it
//! protects a loopback-bound service behind a future reverse proxy against
//! a single noisy client. It is per process; running several replicas would
//! need a shared limiter (not needed for R1).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const WINDOW: Duration = Duration::from_secs(60);
const MAX_TRACKED: usize = 50_000;

pub struct RateLimiter {
    limit: u32,
    state: Mutex<HashMap<IpAddr, (Instant, u32)>>,
}

/// IPv6 clients are keyed by their /64 so one host cannot dodge the limit by
/// rotating addresses inside its prefix.
fn key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => {
            let mut o = v6.octets();
            o[8..].fill(0);
            IpAddr::V6(o.into())
        }
    }
}

impl RateLimiter {
    pub fn new(limit_per_min: u32) -> Self {
        RateLimiter {
            limit: limit_per_min,
            state: Mutex::new(HashMap::new()),
        }
    }

    /// Returns true if the request is allowed.
    pub fn check(&self, ip: IpAddr) -> bool {
        self.check_at(ip, Instant::now())
    }

    pub fn check_at(&self, ip: IpAddr, now: Instant) -> bool {
        let mut map = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if map.len() >= MAX_TRACKED {
            map.retain(|_, (start, _)| now.duration_since(*start) < WINDOW);
            if map.len() >= MAX_TRACKED {
                // Table still full of live entries: fail closed.
                return false;
            }
        }
        let entry = map.entry(key(ip)).or_insert((now, 0));
        if now.duration_since(entry.0) >= WINDOW {
            *entry = (now, 0);
        }
        if entry.1 >= self.limit {
            return false;
        }
        entry.1 += 1;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_per_ip_and_resets_after_the_window() {
        let rl = RateLimiter::new(2);
        let a: IpAddr = "192.0.2.1".parse().unwrap();
        let b: IpAddr = "192.0.2.2".parse().unwrap();
        let t0 = Instant::now();
        assert!(rl.check_at(a, t0));
        assert!(rl.check_at(a, t0));
        assert!(!rl.check_at(a, t0));
        assert!(rl.check_at(b, t0), "other clients are unaffected");
        assert!(rl.check_at(a, t0 + WINDOW), "window resets");
    }

    #[test]
    fn ipv6_is_keyed_by_prefix() {
        let rl = RateLimiter::new(1);
        let t0 = Instant::now();
        assert!(rl.check_at("2001:db8::1".parse().unwrap(), t0));
        assert!(!rl.check_at("2001:db8::2".parse().unwrap(), t0));
        assert!(rl.check_at("2001:db8:0:1::1".parse().unwrap(), t0));
    }
}
