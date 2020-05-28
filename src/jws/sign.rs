//! Sign

use ring::hmac;
use ring::rand::SystemRandom;
use ring::signature;
use ring::signature::{EcdsaKeyPair, EcdsaSigningAlgorithm, Ed25519KeyPair, RsaEncoding, RsaKeyPair, UnparsedPublicKey, VerificationAlgorithm};

use crate::error::{Error, ErrorKind};

/// Algorithms for signing and verifying.
#[derive(Clone, Copy)]
pub enum Algorithm {
    /// HMAC using SHA-256
    HS256,
    /// HMAC using SHA-384
    HS384,
    /// HMAC using SHA-512
    HS512,
    /// RSASSA-PKCS1-v1_5 using SHA-256
    RS256,
    /// RSASSA-PKCS1-v1_5 using SHA-384
    RS384,
    /// RSASSA-PKCS1-v1_5 using SHA-512
    RS512,
    /// ECDSA using P-256 and SHA-256
    ES256,
    /// ECDSA using P-384 and SHA-384
    ES384,
    /// RSASSA-PSS using SHA-256 and MGF1 with SHA-256
    PS256,
    /// RSASSA-PSS using SHA-384 and MGF1 with SHA-384
    PS384,
    /// RSASSA-PSS using SHA-512 and MGF1 with SHA-512
    PS512,
    /// EdDSA using SHA-512
    EdDSA,
}

impl ToString for Algorithm {
    fn to_string(&self) -> String {
        match self {
            Algorithm::HS256 => "HS256".to_owned(),
            Algorithm::HS384 => "HS384".to_owned(),
            Algorithm::HS512 => "HS512".to_owned(),
            Algorithm::RS256 => "RS256".to_owned(),
            Algorithm::RS384 => "RS384".to_owned(),
            Algorithm::RS512 => "RS512".to_owned(),
            Algorithm::ES256 => "ES256".to_owned(),
            Algorithm::ES384 => "ES384".to_owned(),
            Algorithm::PS256 => "PS256".to_owned(),
            Algorithm::PS384 => "PS384".to_owned(),
            Algorithm::PS512 => "PS512".to_owned(),
            Algorithm::EdDSA => "EdDSA".to_owned(),
        }
    }
}

/// A key to use for signing and verifying.
pub struct Key {
    val: Vec<u8>,
    pub alg: Algorithm,
}

impl AsRef<[u8]> for Key {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.val.as_ref()
    }
}

impl Key {
    /// Create a new `Key` with the specific bytes and algorithm.
    ///
    /// For RSA(RS*, PS*), use DER-encoded RSAPrivateKey-formatted private key and
    /// DER-encoded RSAPublicKey-formatted public key.
    ///
    /// For ECDSA(ES*), use PKCS#8 v1 format key.
    #[inline]
    pub fn new(key: impl AsRef<[u8]>, alg: Algorithm) -> Self {
        Key {
            val: key.as_ref().to_owned(),
            alg,
        }
    }

    /// Calculate the signature of the data.
    pub fn sign(&self, data: impl AsRef<[u8]>) -> Result<Vec<u8>, Error> {
        match self.alg {
            Algorithm::HS256 => sign_hmac(data, self, hmac::HMAC_SHA256),
            Algorithm::HS384 => sign_hmac(data, self, hmac::HMAC_SHA384),
            Algorithm::HS512 => sign_hmac(data, self, hmac::HMAC_SHA512),
            Algorithm::RS256 => sign_rsa(data, self, &signature::RSA_PKCS1_SHA256),
            Algorithm::RS384 => sign_rsa(data, self, &signature::RSA_PKCS1_SHA384),
            Algorithm::RS512 => sign_rsa(data, self, &signature::RSA_PKCS1_SHA512),
            Algorithm::ES256 => sign_ecdsa(data, self, &signature::ECDSA_P256_SHA256_FIXED_SIGNING),
            Algorithm::ES384 => sign_ecdsa(data, self, &signature::ECDSA_P384_SHA384_FIXED_SIGNING),
            Algorithm::PS256 => sign_rsa(data, self, &signature::RSA_PSS_SHA256),
            Algorithm::PS384 => sign_rsa(data, self, &signature::RSA_PSS_SHA384),
            Algorithm::PS512 => sign_rsa(data, self, &signature::RSA_PSS_SHA512),
            Algorithm::EdDSA => sign_eddsa(data, self)
        }
    }

    /// Verify the signature.
    pub fn verify(&self, data: impl AsRef<[u8]>, sig: impl AsRef<[u8]>) -> Result<(), Error> {
        match self.alg {
            Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => verify_symmetric(data, sig, self),
            Algorithm::RS256 => verify_asymmetric(data, sig, self, &signature::RSA_PKCS1_2048_8192_SHA256),
            Algorithm::RS384 => verify_asymmetric(data, sig, self, &signature::RSA_PKCS1_2048_8192_SHA384),
            Algorithm::RS512 => verify_asymmetric(data, sig, self, &signature::RSA_PKCS1_2048_8192_SHA512),
            Algorithm::ES256 => verify_asymmetric(data, sig, self, &signature::ECDSA_P256_SHA256_FIXED),
            Algorithm::ES384 => verify_asymmetric(data, sig, self, &signature::ECDSA_P384_SHA384_FIXED),
            Algorithm::PS256 => verify_asymmetric(data, sig, self, &signature::RSA_PSS_2048_8192_SHA256),
            Algorithm::PS384 => verify_asymmetric(data, sig, self, &signature::RSA_PSS_2048_8192_SHA384),
            Algorithm::PS512 => verify_asymmetric(data, sig, self, &signature::RSA_PSS_2048_8192_SHA512),
            Algorithm::EdDSA => verify_asymmetric(data, sig, self, &signature::ED25519),
        }
    }
}

fn sign_hmac(data: impl AsRef<[u8]>, key: impl AsRef<[u8]>, alg: hmac::Algorithm) -> Result<Vec<u8>, Error> {
    let key = hmac::Key::new(alg, key.as_ref());
    let tag = hmac::sign(&key, data.as_ref());
    Ok(tag.as_ref().to_owned())
}

fn sign_rsa(data: impl AsRef<[u8]>, key: impl AsRef<[u8]>, alg: &'static dyn RsaEncoding) -> Result<Vec<u8>, Error> {
    let key_pair = RsaKeyPair::from_der(key.as_ref())?;
    let rng = SystemRandom::new();
    let mut sig = vec![0; key_pair.public_modulus_len()];
    key_pair.sign(alg, &rng, data.as_ref(), &mut sig)?;
    Ok(sig)
}

fn sign_ecdsa(data: impl AsRef<[u8]>, key: impl AsRef<[u8]>, alg: &'static EcdsaSigningAlgorithm) -> Result<Vec<u8>, Error> {
    let key_pair = EcdsaKeyPair::from_pkcs8(alg, key.as_ref())?;
    let rng = SystemRandom::new();
    let sig = key_pair.sign(&rng, data.as_ref())?;
    Ok(sig.as_ref().to_owned())
}

fn sign_eddsa(data: impl AsRef<[u8]>, key: impl AsRef<[u8]>) -> Result<Vec<u8>, Error> {
    let key_pair = Ed25519KeyPair::from_pkcs8(key.as_ref())?;
    let sig = key_pair.sign(data.as_ref());
    Ok(sig.as_ref().to_owned())
}

fn verify_symmetric(msg: impl AsRef<[u8]>, sig: impl AsRef<[u8]>, key: &Key) -> Result<(), Error> {
    let real_sign = key.sign(msg)?;
    if real_sign.as_slice() != sig.as_ref() {
        return Err(Error::from(ErrorKind::InvalidSignature));
    }
    Ok(())
}

fn verify_asymmetric(msg: impl AsRef<[u8]>, sig: impl AsRef<[u8]>, key: &Key, alg: &'static dyn VerificationAlgorithm) -> Result<(), Error> {
    let key = UnparsedPublicKey::new(alg, key.as_ref());
    key.verify(msg.as_ref(), sig.as_ref())
        .map_err(|_| Error::from(ErrorKind::InvalidSignature))
}
