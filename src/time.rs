//! Timestamp functions

use std::time;
use std::time::{Duration, SystemTime};

/// The duration since UNIX_EPOCH, or duration 0 if system time before UNIX_EPOCH.
fn now() -> Duration {
    SystemTime::now()
        .duration_since(time::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
}

/// System time since UNIX_EPOCH as seconds.
#[inline]
pub fn now_secs() -> u64 {
    now().as_secs()
}
