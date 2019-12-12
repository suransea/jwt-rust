//! Timestamp functions.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn now_unix() -> Duration {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
}

pub fn now_secs() -> u64 {
    now_unix().as_secs()
}

pub fn now_millis() -> u128 {
    now_unix().as_millis()
}

pub fn now_micros() -> u128 {
    now_unix().as_micros()
}

pub fn now_nanos() -> u128 {
    now_unix().as_nanos()
}
