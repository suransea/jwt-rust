//! Algorithm

use ring::hmac;
use ring::rand::SystemRandom;
use ring::signature;
use ring::signature::{EcdsaKeyPair, EcdsaSigningAlgorithm, Ed25519KeyPair, RsaEncoding, RsaKeyPair, UnparsedPublicKey, VerificationAlgorithm};

use crate::error::Error;

pub trait Algorithm {
    type SignKey: ?Sized;
    type VerifyKey: ?Sized;

    /// Name of the algorithm
    fn name() -> &'static str;

    /// Calculate the signature of the data with the key.
    fn sign(data: impl AsRef<[u8]>, key: &Self::SignKey) -> Result<Vec<u8>, Error>;

    /// Verify the signature with the key.
    fn verify(data: impl AsRef<[u8]>, sig: impl AsRef<[u8]>, key: &Self::VerifyKey) -> Result<(), Error>;
}

/// HMAC using SHA-256
pub struct HS256;

/// HMAC using SHA-384
pub struct HS384;

/// HMAC using SHA-512
pub struct HS512;

/// RSASSA-PKCS1-v1_5 using SHA-256
pub struct RS256;

/// RSASSA-PKCS1-v1_5 using SHA-384
pub struct RS384;

/// RSASSA-PKCS1-v1_5 using SHA-512
pub struct RS512;

/// ECDSA using P-256 and SHA-256
pub struct ES256;

/// ECDSA using P-384 and SHA-384
pub struct ES384;

/// RSASSA-PSS using SHA-256 and MGF1 with SHA-256
pub struct PS256;

/// RSASSA-PSS using SHA-384 and MGF1 with SHA-384
pub struct PS384;

/// RSASSA-PSS using SHA-512 and MGF1 with SHA-512
pub struct PS512;

/// Ed25519 using SHA-512
pub struct Ed25519;

impl Algorithm for HS256 {
    type SignKey = [u8];
    type VerifyKey = [u8];

    fn name() -> &'static str {
        "HS256"
    }

    fn sign(data: impl AsRef<[u8]>, key: &Self::SignKey) -> Result<Vec<u8>, Error> {
        sign_hmac(data, key, hmac::HMAC_SHA256)
    }

    fn verify(data: impl AsRef<[u8]>, sig: impl AsRef<[u8]>, key: &Self::VerifyKey) -> Result<(), Error> {
        verify_symmetric(sig, Self::sign(data, key)?)
    }
}

impl Algorithm for HS384 {
    type SignKey = [u8];
    type VerifyKey = [u8];

    fn name() -> &'static str {
        "HS384"
    }

    fn sign(data: impl AsRef<[u8]>, key: &Self::SignKey) -> Result<Vec<u8>, Error> {
        sign_hmac(data, key, hmac::HMAC_SHA384)
    }

    fn verify(data: impl AsRef<[u8]>, sig: impl AsRef<[u8]>, key: &Self::VerifyKey) -> Result<(), Error> {
        verify_symmetric(sig, Self::sign(data, key)?)
    }
}

impl Algorithm for HS512 {
    type SignKey = [u8];
    type VerifyKey = [u8];

    fn name() -> &'static str {
        "HS512"
    }

    fn sign(data: impl AsRef<[u8]>, key: &Self::SignKey) -> Result<Vec<u8>, Error> {
        sign_hmac(data, key, hmac::HMAC_SHA512)
    }

    fn verify(data: impl AsRef<[u8]>, sig: impl AsRef<[u8]>, key: &Self::VerifyKey) -> Result<(), Error> {
        verify_symmetric(sig, Self::sign(data, key)?)
    }
}

impl Algorithm for RS256 {
    type SignKey = RsaKeyPair;
    type VerifyKey = [u8];

    fn name() -> &'static str {
        "RS256"
    }

    fn sign(data: impl AsRef<[u8]>, key: &Self::SignKey) -> Result<Vec<u8>, Error> {
        sign_rsa(data, key, &signature::RSA_PKCS1_SHA256)
    }

    fn verify(data: impl AsRef<[u8]>, sig: impl AsRef<[u8]>, key: &Self::VerifyKey) -> Result<(), Error> {
        verify_asymmetric(data, sig, key, &signature::RSA_PKCS1_2048_8192_SHA256)
    }
}

impl Algorithm for RS384 {
    type SignKey = RsaKeyPair;
    type VerifyKey = [u8];

    fn name() -> &'static str {
        "RS384"
    }

    fn sign(data: impl AsRef<[u8]>, key: &Self::SignKey) -> Result<Vec<u8>, Error> {
        sign_rsa(data, key, &signature::RSA_PKCS1_SHA384)
    }

    fn verify(data: impl AsRef<[u8]>, sig: impl AsRef<[u8]>, key: &Self::VerifyKey) -> Result<(), Error> {
        verify_asymmetric(data, sig, key, &signature::RSA_PKCS1_2048_8192_SHA384)
    }
}

impl Algorithm for RS512 {
    type SignKey = RsaKeyPair;
    type VerifyKey = [u8];

    fn name() -> &'static str {
        "RS512"
    }

    fn sign(data: impl AsRef<[u8]>, key: &Self::SignKey) -> Result<Vec<u8>, Error> {
        sign_rsa(data, key, &signature::RSA_PKCS1_SHA512)
    }

    fn verify(data: impl AsRef<[u8]>, sig: impl AsRef<[u8]>, key: &Self::VerifyKey) -> Result<(), Error> {
        verify_asymmetric(data, sig, key, &signature::RSA_PKCS1_2048_8192_SHA512)
    }
}

impl Algorithm for ES256 {
    type SignKey = [u8];
    type VerifyKey = [u8];

    fn name() -> &'static str {
        "ES256"
    }

    fn sign(data: impl AsRef<[u8]>, key: &Self::SignKey) -> Result<Vec<u8>, Error> {
        sign_ecdsa(data, key, &signature::ECDSA_P256_SHA256_FIXED_SIGNING)
    }

    fn verify(data: impl AsRef<[u8]>, sig: impl AsRef<[u8]>, key: &Self::VerifyKey) -> Result<(), Error> {
        verify_asymmetric(data, sig, key, &signature::ECDSA_P256_SHA256_FIXED)
    }
}

impl Algorithm for ES384 {
    type SignKey = [u8];
    type VerifyKey = [u8];

    fn name() -> &'static str {
        "ES384"
    }

    fn sign(data: impl AsRef<[u8]>, key: &Self::SignKey) -> Result<Vec<u8>, Error> {
        sign_ecdsa(data, key, &signature::ECDSA_P384_SHA384_FIXED_SIGNING)
    }

    fn verify(data: impl AsRef<[u8]>, sig: impl AsRef<[u8]>, key: &Self::VerifyKey) -> Result<(), Error> {
        verify_asymmetric(data, sig, key, &signature::ECDSA_P384_SHA384_FIXED)
    }
}

impl Algorithm for PS256 {
    type SignKey = RsaKeyPair;
    type VerifyKey = [u8];

    fn name() -> &'static str {
        "PS256"
    }

    fn sign(data: impl AsRef<[u8]>, key: &Self::SignKey) -> Result<Vec<u8>, Error> {
        sign_rsa(data, key, &signature::RSA_PSS_SHA256)
    }

    fn verify(data: impl AsRef<[u8]>, sig: impl AsRef<[u8]>, key: &Self::VerifyKey) -> Result<(), Error> {
        verify_asymmetric(data, sig, key, &signature::RSA_PSS_2048_8192_SHA256)
    }
}

impl Algorithm for PS384 {
    type SignKey = RsaKeyPair;
    type VerifyKey = [u8];

    fn name() -> &'static str {
        "PS384"
    }

    fn sign(data: impl AsRef<[u8]>, key: &Self::SignKey) -> Result<Vec<u8>, Error> {
        sign_rsa(data, key, &signature::RSA_PSS_SHA384)
    }

    fn verify(data: impl AsRef<[u8]>, sig: impl AsRef<[u8]>, key: &Self::VerifyKey) -> Result<(), Error> {
        verify_asymmetric(data, sig, key, &signature::RSA_PSS_2048_8192_SHA384)
    }
}

impl Algorithm for PS512 {
    type SignKey = RsaKeyPair;
    type VerifyKey = [u8];

    fn name() -> &'static str {
        "PS512"
    }

    fn sign(data: impl AsRef<[u8]>, key: &Self::SignKey) -> Result<Vec<u8>, Error> {
        sign_rsa(data, key, &signature::RSA_PSS_SHA512)
    }

    fn verify(data: impl AsRef<[u8]>, sig: impl AsRef<[u8]>, key: &Self::VerifyKey) -> Result<(), Error> {
        verify_asymmetric(data, sig, key, &signature::RSA_PSS_2048_8192_SHA512)
    }
}

impl Algorithm for Ed25519 {
    type SignKey = Ed25519KeyPair;
    type VerifyKey = [u8];

    fn name() -> &'static str {
        "Ed25519"
    }

    fn sign(data: impl AsRef<[u8]>, key: &Self::SignKey) -> Result<Vec<u8>, Error> {
        sign_eddsa(data, key)
    }

    fn verify(data: impl AsRef<[u8]>, sig: impl AsRef<[u8]>, key: &Self::VerifyKey) -> Result<(), Error> {
        verify_asymmetric(data, sig, key, &signature::ED25519)
    }
}

fn sign_hmac(data: impl AsRef<[u8]>, key: impl AsRef<[u8]>, alg: hmac::Algorithm) -> Result<Vec<u8>, Error> {
    let key = hmac::Key::new(alg, key.as_ref());
    let tag = hmac::sign(&key, data.as_ref());
    Ok(tag.as_ref().to_owned())
}

fn sign_rsa(data: impl AsRef<[u8]>, key: &RsaKeyPair, alg: &'static impl RsaEncoding) -> Result<Vec<u8>, Error> {
    let rng = SystemRandom::new();
    let mut sig = vec![0; key.public_modulus_len()];
    key.sign(alg, &rng, data.as_ref(), &mut sig)?;
    Ok(sig)
}

fn sign_ecdsa(data: impl AsRef<[u8]>, key: impl AsRef<[u8]>, alg: &'static EcdsaSigningAlgorithm) -> Result<Vec<u8>, Error> {
    let key_pair = EcdsaKeyPair::from_pkcs8(alg, key.as_ref())?;
    let rng = SystemRandom::new();
    let sig = key_pair.sign(&rng, data.as_ref())?;
    Ok(sig.as_ref().to_owned())
}

#[inline]
fn sign_eddsa(data: impl AsRef<[u8]>, key: &Ed25519KeyPair) -> Result<Vec<u8>, Error> {
    Ok(key.sign(data.as_ref()).as_ref().to_owned())
}

#[inline]
fn verify_symmetric(sig: impl AsRef<[u8]>, expect: impl AsRef<[u8]>) -> Result<(), Error> {
    (sig.as_ref() == expect.as_ref()).then_some(()).ok_or(Error::InvalidSignature)
}

fn verify_asymmetric(msg: impl AsRef<[u8]>, sig: impl AsRef<[u8]>, key: impl AsRef<[u8]>, alg: &'static impl VerificationAlgorithm) -> Result<(), Error> {
    let key = UnparsedPublicKey::new(alg, key.as_ref());
    key.verify(msg.as_ref(), sig.as_ref())
        .map_err(|_| Error::InvalidSignature)
}
