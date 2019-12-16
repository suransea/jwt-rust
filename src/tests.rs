//! Tests for mod jwt.

use crate::time;

#[test]
fn test_time() {
    println!("{}", time::now_secs());
}
