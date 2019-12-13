//! Verify

use crate::error::{Error, ErrorKind};
use crate::jws::Alg;

pub fn check_sign(f2s: &str, sign: &[u8], alg: &Alg) -> bool {
    let real_sign = alg.sign(&f2s);
    real_sign.as_slice() == sign
}
