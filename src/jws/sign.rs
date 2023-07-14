//! Sign

use serde::Serialize;
use serde_json as json;

use crate::{bs64, Error};
use crate::jws::{Algorithm, Header};

/// Sign the token, and return the signed token as `String`.
pub fn sign<A: Algorithm>(header: Header, payload: &impl Serialize, key: &A::SignKey) -> Result<String, Error> {
    let header = Header {
        alg: Some(A::name().to_owned()),
        ..header
    };
    let header = json::to_string(&header)
        .map(bs64::from_bytes)?;

    let payload = json::to_string(&payload)
        .map(bs64::from_bytes)?;

    let f2s = [header, payload].join(".");
    let signature = A::sign(&f2s, &key)?;

    let trd = bs64::from_bytes(signature);

    Ok([f2s, trd].join("."))
}
