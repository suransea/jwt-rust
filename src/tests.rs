//! Tests for mod jwt.

use crate::time;

#[test]
fn test_time() {
    println!("{}", time::now_secs());
    println!("{}", time::now_millis());
    println!("{}", time::now_micros());
    println!("{}", time::now_nanos());
}
