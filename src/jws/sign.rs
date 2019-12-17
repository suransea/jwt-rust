//! Signature

use ring::hmac;

pub enum Algorithm {
    HS256,
}

impl ToString for Algorithm {
    fn to_string(&self) -> String {
        match self {
            Algorithm::HS256 => "HS256".to_owned(),
        }
    }
}

pub struct Key {
    pub val: Vec<u8>,
    pub alg: Algorithm,
}

impl AsRef<[u8]> for Key {
    fn as_ref(&self) -> &[u8] {
        self.val.as_ref()
    }
}

impl Key {
    pub fn new(key: impl AsRef<[u8]>, alg: Algorithm) -> Self {
        Key {
            val: key.as_ref().to_owned(),
            alg,
        }
    }

    pub fn sign(&self, data: impl AsRef<[u8]>) -> Vec<u8> {
        match self.alg {
            Algorithm::HS256 => {
                let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, self.as_ref());
                let tag = hmac::sign(&hmac_key, data.as_ref());
                tag.as_ref().to_owned()
            }
        }
    }
}
