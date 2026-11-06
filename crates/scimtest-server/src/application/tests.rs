use super::*;
use std::time::Duration;

#[test]
fn token_bucket_enforces_burst_refills_and_idle_capacity() {
    let mut limiter = RateLimiter::new(60, 2);
    let now = limiter.last;
    assert!(limiter.allow_at(now));
    assert!(limiter.allow_at(now));
    assert!(!limiter.allow_at(now));
    assert!(!limiter.allow_at(now + Duration::from_millis(999)));
    assert!(limiter.allow_at(now + Duration::from_secs(1)));
    assert!(!limiter.allow_at(now + Duration::from_secs(1)));
    assert!(limiter.allow_at(now + Duration::from_secs(120)));
    assert!(limiter.allow_at(now + Duration::from_secs(120)));
    assert!(!limiter.allow_at(now + Duration::from_secs(120)));
}
