//! Verify

use crate::error::ErrorKind;
use crate::jws::Algorithm;
use crate::time;

pub fn verify_signature(f2s: &str, sign: &[u8], alg: &Algorithm) -> Result<(), ErrorKind> {
    let real_sign = alg.sign(&f2s);
    if real_sign.as_slice() == sign {
        Ok(())
    } else {
        Err(ErrorKind::InvalidSignature)
    }
}

pub fn verify_iat(iat: u64) -> Result<(), ErrorKind> {
    if time::now_secs() >= iat {
        Ok(())
    } else {
        Err(ErrorKind::BeforeIat)
    }
}

pub fn verify_nbf(nbf: u64) -> Result<(), ErrorKind> {
    if time::now_secs() >= nbf {
        Ok(())
    } else {
        Err(ErrorKind::BeforeNbf)
    }
}

pub fn verify_exp(exp: u64) -> Result<(), ErrorKind> {
    let now = time::now_secs();
    if now < exp {
        Ok(())
    } else {
        Err(ErrorKind::Expired(now - exp))
    }
}
