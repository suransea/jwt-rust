//! Encode

use serde::Serialize;
use serde_json as json;

use crate::{bs64, Error};
use crate::jws::{Algorithm, Header};

/// Encode and sign a token, return the signed token as `String`.
pub fn encode<A: Algorithm>(header: Header, payload: &impl Serialize, key: &A::SignKey) -> Result<String, Error> {
    let header = header.with_algorithm::<A>();
    let header = json::to_string(&header)
        .map(bs64::from_bytes)?;

    let payload = json::to_string(&payload)
        .map(bs64::from_bytes)?;

    let f2s = [header, payload].join(".");
    let signature = A::sign(&f2s, &key)?;

    let trd = bs64::from_bytes(signature);

    Ok([f2s, trd].join("."))
}
