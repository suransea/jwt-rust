//! Rust implementation of JSON Web Tokens, see https://tools.ietf.org/html/rfc7519
//!
//! # Examples
//!
//! ## Encode
//!
//! ```rust
//! use jwts::{Claims, jws};
//! use jwts::jws::Header;
//! use jwts::jws::alg::HS256;
//!
//! let claims = Claims {
//!     iss: Some("sea".to_owned()),
//!     ..Default::default()
//! };
//! jws::encode::<HS256>(Header::default(), &claims, b"secret").unwrap();
//! ```
//!
//! ## Decode
//!
//! ```rust
//! use jwts::{Claims, jws};
//! use jwts::jws::{Header, NoVerify, Token, VerifyWith};
//! use jwts::jws::alg::HS256;
//!
//! let claims = Claims::default();
//! let token = jws::encode::<HS256>(Header::default(), &claims, b"secret").unwrap();
//!
//! let Token {..} = jws::decode::<Claims>(&token, NoVerify).unwrap(); // no verify
//! let Token {..} = jws::decode::<Claims>(&token, VerifyWith::<HS256>(b"secret")).unwrap(); // verify with algorithm and key
//! ```
//!
//! ## Validate Claims
//!
//! ```rust
//! use std::collections::HashMap;
//! use std::time::{Duration, SystemTime};
//! use jwts::Claims;
//! use jwts::validate::{ExpectAud, ExpectIss, ExpectJti, ExpectSub, ExpiredTime, IssuedAtTime, NotBeforeTime, Validate};
//!
//! let claims = Claims {
//!     iss: Some("sea".to_owned()),
//!     sub: Some("subject".to_owned()),
//!     aud: Some("audience".to_owned()),
//!     jti: Some("id".to_owned()),
//!     ..Default::default()
//! };
//! let claims = claims
//!     .issued_now()
//!     .expired_in(Duration::from_secs(1))
//!     .not_before(SystemTime::now());
//!
//! claims.validate(IssuedAtTime).unwrap();
//! claims.validate(NotBeforeTime).unwrap();
//! claims.validate(ExpiredTime).unwrap();
//! claims.validate(ExpectIss("sea")).unwrap();
//! claims.validate(ExpectSub("subject")).unwrap();
//! claims.validate(ExpectAud("audience")).unwrap();
//! claims.validate(ExpectJti("id")).unwrap();
//!
//! // builtin validation works with any `Serialize` type:
//! let claims = HashMap::from([("iss", "sea")]);
//! claims.validate(ExpectIss("sea")).unwrap();
//! ```
//!
//! ## Custom Claims Type
//!
//! ```rust
//! use std::collections::HashMap;
//! use serde_derive::{Deserialize, Serialize};
//! use jwts::jws;
//! use jwts::jws::{Header, Token, VerifyWith};
//! use jwts::jws::alg::HS256;
//!
//! #[derive(Debug, Serialize, Deserialize)]
//! struct CustomClaims {
//!     iss: String,
//! }
//!
//! let claims = CustomClaims {
//!     iss: "sea".to_owned(),
//! };
//! let token = jws::encode::<HS256>(Header::default(), &claims, b"secret").unwrap();
//! let Token {..} = jws::decode::<CustomClaims>(&token, VerifyWith::<HS256>(b"secret")).unwrap();
//!
//! // Or use a map directly
//! let claims = HashMap::from([("iss", "sea")]);
//! let Token {..} = jws::decode::<HashMap<String, String>>(&token, VerifyWith::<HS256>(b"secret")).unwrap();
//! ```
//!
//! ## Custom Algorithm
//!
//! ```rust
//! use jwts::{Claims, Error, jws};
//! use jwts::jws::{Algorithm, Header, Token, VerifyWith};
//!
//! pub struct None;
//!
//! impl Algorithm for None {
//!     type SignKey = ();
//!     type VerifyKey = ();
//!
//!     fn name() -> &'static str {
//!         "None"
//!     }
//!
//!     fn sign(data: impl AsRef<[u8]>, key: &Self::SignKey) -> Result<Vec<u8>, Error> {
//!         Ok([].into())
//!     }
//!
//!     fn verify(data: impl AsRef<[u8]>, sig: impl AsRef<[u8]>, key: &Self::VerifyKey) -> Result<(), Error> {
//!         sig.as_ref().is_empty().then_some(()).ok_or(Error::InvalidSignature)
//!     }
//! }
//!
//! let claims = Claims::default();
//! let token = jws::encode::<None>(Header::default(), &claims, &()).unwrap();
//! let Token {..} = jws::decode::<Claims>(&token, VerifyWith::<None>(&())).unwrap();
//! ```
//!
//! ## Custom Verification
//!
//! ```rust
//! use jwts::{Claims, Error, jws};
//! use jwts::jws::{Algorithm, Header, Token, Verify};
//! use jwts::jws::alg::HS256;
//!
//! pub struct CustomVerify;
//!
//! impl Verify<Claims> for CustomVerify {
//!     fn verify(&self, f2s: &str, signature: &[u8], header: &Header, payload: &Claims) -> Result<(), Error> {
//!         HS256::verify(f2s, signature, b"secret")
//!     }
//! }
//!
//! let token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJzZWEifQ.L0DLtDjydcSK-c0gTyOYbmUQ_LUCZzqAGCINn2OLhFs";
//! let Token {..} = jws::decode::<Claims>(&token, CustomVerify).unwrap();
//! ```
//!
//! ## Custom Claims Validation
//!
//! ```rust
//! use jwts::Claims;
//! use jwts::validate::{Validate, Validation};
//!
//! pub struct CustomValidation;
//!
//! impl Validation<Claims> for CustomValidation {
//!     type Error = ();
//!
//!     fn validate(&self, claims: &Claims) -> Result<(), Self::Error> {
//!         claims.aud.is_some().then_some(()).ok_or(())
//!     }
//! }
//!
//! let claims = Claims {
//!     aud: Some("audience".to_owned()),
//!     ..Default::default()
//! };
//! claims.validate(CustomValidation).unwrap();
//! ```

pub use self::claims::Claims;
pub use self::error::Error;

pub mod jws;
pub mod validate;
mod error;
mod bs64;
mod time;
mod claims;
