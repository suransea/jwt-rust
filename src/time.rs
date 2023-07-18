//! Timestamp functions

use std::time;
use std::time::{Duration, SystemTime};

#[inline]
pub fn since_unix_epoch_secs(time: SystemTime) -> u64 {
    time.duration_since(time::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

/// System time since UNIX_EPOCH as seconds.
#[inline]
pub fn now_secs() -> u64 {
    since_unix_epoch_secs(SystemTime::now())
}
