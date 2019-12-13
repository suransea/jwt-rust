//! Signature

use ring::hmac;

pub enum Alg {
    HS256(String),
}

impl Alg {
    pub fn sign<T: AsRef<[u8]>>(&self, data: &T) -> Vec<u8> {
        match self {
            Alg::HS256(key) => {
                let sign_key = hmac::Key::new(hmac::HMAC_SHA256, key.as_bytes());
                let tag = hmac::sign(&sign_key, data.as_ref());
                tag.as_ref().to_vec()
            }
        }
    }
}

impl ToString for Alg {
    fn to_string(&self) -> String {
        match self {
            Alg::HS256(_) => "HS256".to_owned(),
        }
    }
}
