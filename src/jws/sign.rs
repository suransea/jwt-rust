//! Signature

use ring::hmac;

pub struct Key(Vec<u8>);

impl Key {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<T: AsRef<[u8]>> From<T> for Key {
    fn from(key: T) -> Self {
        Key(key.as_ref().to_vec())
    }
}

pub enum Algorithm {
    HS256(Key),
}

impl Algorithm {
    pub fn sign<T: AsRef<[u8]>>(&self, data: &T) -> Vec<u8> {
        match self {
            Algorithm::HS256(key) => {
                let sign_key = hmac::Key::new(hmac::HMAC_SHA256, key.as_ref());
                let tag = hmac::sign(&sign_key, data.as_ref());
                tag.as_ref().to_vec()
            }
        }
    }
}

impl ToString for Algorithm {
    fn to_string(&self) -> String {
        match self {
            Algorithm::HS256(_) => "HS256".to_owned(),
        }
    }
}
