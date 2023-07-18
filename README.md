# jwt-rust

[![jwts](https://img.shields.io/crates/v/jwts?style=flat-square)](https://crates.io/crates/jwts)
[![jwts](https://img.shields.io/github/languages/top/suransea/jwt-rust?style=flat-square)](https://github.com/suransea/jwt-rust)
[![jwts](https://img.shields.io/crates/d/jwts?style=flat-square)](https://crates.io/crates/jwts)
[![jwts](https://img.shields.io/crates/l/jwts?style=flat-square)](http://www.apache.org/licenses/LICENSE-2.0)

[![jwt](http://jwt.io/img/logo-asset.svg)](http://jwt.io)

A rust implementation of JSON Web Tokens.

## Examples

### Encode

```rust
use jwts::{Claims, jws};
use jwts::jws::Header;
use jwts::jws::alg::HS256;

let claims = Claims {
    iss: Some("sea".to_owned()),
    ..Default::default()
};
jws::encode::<HS256>(Header::default(), &claims, b"secret").unwrap();
```

### Decode

```rust
use jwts::{Claims, jws};
use jwts::jws::{Header, NoVerify, Token, VerifyWith};
use jwts::jws::alg::HS256;

let claims = Claims::default();
let token = jws::encode::<HS256>(Header::default(), &claims, b"secret").unwrap();

let Token {..} = jws::decode::<Claims>(&token, NoVerify).unwrap(); // no verify
let Token {..} = jws::decode::<Claims>(&token, VerifyWith::<HS256>(b"secret")).unwrap(); // verify with algorithm and key
```

### Validate Claims

```rust
use std::collections::HashMap;
use std::time::{Duration, SystemTime};
use jwts::Claims;
use jwts::validate::{ExpectAud, ExpectIss, ExpectJti, ExpectSub, ExpiredTime, IssuedAtTime, NotBeforeTime, Validate};

let claims = Claims {
    iss: Some("sea".to_owned()),
    sub: Some("subject".to_owned()),
    aud: Some("audience".to_owned()),
    jti: Some("id".to_owned()),
    ..Default::default()
};
let claims = claims
    .issued_now()
    .expired_in(Duration::from_secs(1))
    .not_before(SystemTime::now());

claims.validate(IssuedAtTime).unwrap();
claims.validate(NotBeforeTime).unwrap();
claims.validate(ExpiredTime).unwrap();
claims.validate(ExpectIss("sea")).unwrap();
claims.validate(ExpectSub("subject")).unwrap();
claims.validate(ExpectAud("audience")).unwrap();
claims.validate(ExpectJti("id")).unwrap();

// builtin validation works with any `Serialize` type:
let claims = HashMap::from([("iss", "sea")]);
claims.validate(ExpectIss("sea")).unwrap();
```

### Custom Claims Type

```rust
use std::collections::HashMap;
use serde_derive::{Deserialize, Serialize};
use jwts::jws;
use jwts::jws::{Header, Token, VerifyWith};
use jwts::jws::alg::HS256;

#[derive(Debug, Serialize, Deserialize)]
struct CustomClaims {
    iss: String,
}

let claims = CustomClaims {
    iss: "sea".to_owned(),
};
let token = jws::encode::<HS256>(Header::default(), &claims, b"secret").unwrap();
let Token {..} = jws::decode::<CustomClaims>(&token, VerifyWith::<HS256>(b"secret")).unwrap();

// Or use a map directly
let claims = HashMap::from([("iss", "sea")]);
let Token {..} = jws::decode::<HashMap<String, String>>(&token, VerifyWith::<HS256>(b"secret")).unwrap();
```

### Custom Algorithm

```rust
use jwts::{Claims, Error, jws};
use jwts::jws::{Algorithm, Header, Token, VerifyWith};

pub struct None;

impl Algorithm for None {
    type SignKey = ();
    type VerifyKey = ();

    fn name() -> &'static str {
        "None"
    }

    fn sign(data: impl AsRef<[u8]>, key: &Self::SignKey) -> Result<Vec<u8>, Error> {
        Ok([].into())
    }

    fn verify(data: impl AsRef<[u8]>, sig: impl AsRef<[u8]>, key: &Self::VerifyKey) -> Result<(), Error> {
        sig.as_ref().is_empty().then_some(()).ok_or(Error::InvalidSignature)
    }
}

let claims = Claims::default();
let token = jws::encode::<None>(Header::default(), &claims, &()).unwrap();
let Token {..} = jws::decode::<Claims>(&token, VerifyWith::<None>(&())).unwrap();
```

### Custom Verification

```rust
use jwts::{Claims, Error, jws};
use jwts::jws::{Algorithm, Header, Token, Verify};
use jwts::jws::alg::HS256;

pub struct CustomVerify;

impl Verify<Claims> for CustomVerify {
    fn verify(&self, f2s: &str, signature: &[u8], header: &Header, payload: &Claims) -> Result<(), Error> {
        HS256::verify(f2s, signature, b"secret")
    }
}

let token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJzZWEifQ.L0DLtDjydcSK-c0gTyOYbmUQ_LUCZzqAGCINn2OLhFs";
let Token {..} = jws::decode::<Claims>(&token, CustomVerify).unwrap();
```

### Custom Claims Validation

```rust
use jwts::Claims;
use jwts::validate::{Validate, Validation};

pub struct CustomValidation;

impl Validation<Claims> for CustomValidation {
    type Error = ();

    fn validate(&self, claims: &Claims) -> Result<(), Self::Error> {
        claims.aud.is_some().then_some(()).ok_or(())
    }
}

let claims = Claims {
    aud: Some("audience".to_owned()),
    ..Default::default()
};
claims.validate(CustomValidation).unwrap();
```

## Algorithms

Sign and verify use crate [ring](https://crates.io/crates/ring).

- [x] HS256 - HMAC using SHA-256
- [x] HS384 - HMAC using SHA-384
- [x] HS512 - HMAC using SHA-512
- [x] RS256 - RSASSA-PKCS1-v1_5 using SHA-256
- [x] RS384 - RSASSA-PKCS1-v1_5 using SHA-384
- [x] RS512 - RSASSA-PKCS1-v1_5 using SHA-512
- [x] ES256 - ECDSA using P-256 and SHA-256
- [x] ES384 - ECDSA using P-384 and SHA-384
- [ ] ES512 - ECDSA using P-521 and SHA-512
- [x] PS256 - RSASSA-PSS using SHA-256 and MGF1 with SHA-256
- [x] PS384 - RSASSA-PSS using SHA-384 and MGF1 with SHA-384
- [x] PS512 - RSASSA-PSS using SHA-512 and MGF1 with SHA-512

## Migrate from 0.2

| <= 0.2                            | >= 0.4                           |
|-----------------------------------|----------------------------------|
| `Token::sign`                     | `jws::encode`                    |
| `Token::decode`                   | `jws::decode` with NoVerify      |
| `Token::verify_with_key`          | `jws::decode` with WerifyWith    |
| `Token::verify_with_key_resolver` | `jws::decode` with custom verify |
| `Token::validate_claims`          | `Validate::validate`             |


## More

[RFC 7519](https://tools.ietf.org/html/rfc7519) JSON Web Token (JWT)

[RFC 7515](https://tools.ietf.org/html/rfc7515) JSON Web Signature (JWS)

[RFC 7518](https://tools.ietf.org/html/rfc7518) JSON Web Algorithms (JWA)

## License

[Apache 2.0 License](http://www.apache.org/licenses/LICENSE-2.0)
