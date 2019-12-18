//! Verify

use ring::signature;
use ring::signature::{UnparsedPublicKey, VerificationAlgorithm};

use crate::error::{Error, ErrorKind};
use crate::jws::sign::{Algorithm, Key};
use crate::time;

pub fn verify_signature(msg: &str, sig: &[u8], key: &Key) -> Result<(), Error> {
    match key.alg {
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => verify_symmetric(msg, sig, key),
        Algorithm::RS256 => verify_asymmetric(msg, sig, key, &signature::RSA_PKCS1_2048_8192_SHA256),
        Algorithm::RS384 => verify_asymmetric(msg, sig, key, &signature::RSA_PKCS1_2048_8192_SHA384),
        Algorithm::RS512 => verify_asymmetric(msg, sig, key, &signature::RSA_PKCS1_2048_8192_SHA512),
        Algorithm::ES256 => verify_asymmetric(msg, sig, key, &signature::ECDSA_P256_SHA256_FIXED),
        Algorithm::ES384 => verify_asymmetric(msg, sig, key, &signature::ECDSA_P384_SHA384_FIXED),
        Algorithm::PS256 => verify_asymmetric(msg, sig, key, &signature::RSA_PSS_2048_8192_SHA256),
        Algorithm::PS384 => verify_asymmetric(msg, sig, key, &signature::RSA_PSS_2048_8192_SHA384),
        Algorithm::PS512 => verify_asymmetric(msg, sig, key, &signature::RSA_PSS_2048_8192_SHA512),
    }
}

pub fn verify_iat(iat: u64) -> Result<(), ErrorKind> {
    if time::now_secs() >= iat {
        Ok(())
    } else {
        Err(ErrorKind::InvalidIat)
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
        Err(ErrorKind::TokenExpired(now - exp))
    }
}

fn verify_symmetric(msg: &str, sig: &[u8], key: &Key) -> Result<(), Error> {
    let real_sign = key.sign(&msg)?;
    if real_sign.as_slice() != sig {
        return Err(Error(ErrorKind::SignatureInvalid));
    }
    Ok(())
}

fn verify_asymmetric(msg: &str, sig: &[u8], key: &Key, alg: &'static dyn VerificationAlgorithm) -> Result<(), Error> {
    let key = UnparsedPublicKey::new(alg, key.as_ref());
    key.verify(msg.as_ref(), sig)
        .map_err(|_| Error(ErrorKind::SignatureInvalid))
}
