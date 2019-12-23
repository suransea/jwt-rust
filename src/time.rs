//! Timestamp functions

use std::time;
use std::time::{Duration, SystemTime};

/// The duration since UNIX_EPOCH, or duration 0 if system time before UNIX_EPOCH.
fn now_unix() -> Duration {
    SystemTime::now()
        .duration_since(time::UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
}

/// System time since UNIX_EPOCH as seconds.
#[inline]
pub fn now_secs() -> u64 {
    now_unix().as_secs()
}
