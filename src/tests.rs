//! Tests for mod `jwts`.

use crate::time;

#[test]
fn test_time() {
    println!("{}", time::now_secs());
}
