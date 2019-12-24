# jwt-rust

[![jwts](https://img.shields.io/crates/v/jwts?style=flat-square)](https://crates.io/crates/jwts)
[![jwts](https://img.shields.io/github/languages/top/suransea/jwt-rust?style=flat-square)](https://github.com/suransea/jwt-rust)
[![jwts](https://img.shields.io/crates/d/jwts?style=flat-square)](https://crates.io/crates/jwts)
[![jwts](https://img.shields.io/crates/l/jwts?style=flat-square)](http://www.apache.org/licenses/LICENSE-2.0)

[![jwt](http://jwt.io/img/logo-asset.svg)](http://jwt.io)

A rust implementation of JSON Web Tokens.

## Examples

### Sign

```rust
use jwts::Claims;
use jwts::jws::{Algorithm, Key, Token};

let mut claims = Claims::new();
claims.iss = Some("sea".to_owned());

let mut token = Token::with_payload(claims);

// custom the header like:
// token.header.cty = Some("application/example".to_owned());

let key = Key::new(b"secret", Algorithm::HS256);
let token = token.sign(&key).unwrap();

assert_eq!(token, "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJzZWEifQ.L0DLtDjydcSK-c0gTyOYbmUQ_LUCZzqAGCINn2OLhFs");
```

### Verify

```rust
use jwts::{Claims, ValidationConfig};
use jwts::jws::{Algorithm, Key, Token};

let token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJzZWEiLCJleHAiOjEwNTc3MDkxMDU2LCJuYmYiOjE1NzcwOTEwNTYsImlhdCI6MTU3NzA5MTA1Nn0.4HwFlFB3LMhVc2xpsGBGSO3ut1KmnFdF8JrsL589ytw";

let key = Key::new(b"secret", Algorithm::HS256);
let verified: Token<Claims> = Token::verify_with_key(token, &key).unwrap();

// use key resolver like:
// let verified: Token<Claims> = Token::verify_with_key_resolver(token, |header, payload| {
//     // return a Key here
// }).unwrap();

println!("{:?}", verified);

// validate claims
let config = ValidationConfig {
    iat_validation: true,
    nbf_validation: true,
    exp_validation: true,
    expected_iss: Some("sea".to_owned()),
    expected_sub: None,
    expected_aud: None,
    expected_jti: None,
};
verified.validate_claims(&config).unwrap();
```

### Custom Claims

```rust
use jwts::jws::{Algorithm, Key, Token};

#[macro_use]
extern crate serde_derive;

#[derive(Debug, Serialize, Deserialize)]
struct CustomClaims {
    iss: String,
}

let claims = CustomClaims {
    iss: "sea".to_owned(),
};

let mut token = Token::with_payload(claims);
let key = Key::new(b"secret", Algorithm::HS256);
let token = token.sign(&key).unwrap();
let token: Token<CustomClaims> = Token::decode(&token).unwrap(); // here decode without verification for demonstration
println!("{:?}", token);
```

## Algorithms

Sign and verify use crate [ring](https://crates.io/crates/ring).

-   [x] HS256 - HMAC using SHA-256
-   [x] HS384 - HMAC using SHA-384
-   [x] HS512 - HMAC using SHA-512
-   [x] RS256 - RSASSA-PKCS1-v1_5 using SHA-256
-   [x] RS384 - RSASSA-PKCS1-v1_5 using SHA-384
-   [x] RS512 - RSASSA-PKCS1-v1_5 using SHA-512
-   [x] ES256 - ECDSA using P-256 and SHA-256
-   [x] ES384 - ECDSA using P-384 and SHA-384
-   [ ] ES512 - ECDSA using P-521 and SHA-512
-   [x] PS256 - RSASSA-PSS using SHA-256 and MGF1 with SHA-256
-   [x] PS384 - RSASSA-PSS using SHA-384 and MGF1 with SHA-384
-   [x] PS512 - RSASSA-PSS using SHA-512 and MGF1 with SHA-512

## More

[RFC 7519](https://tools.ietf.org/html/rfc7519) JSON Web Token (JWT)

[RFC 7515](https://tools.ietf.org/html/rfc7515) JSON Web Signature (JWS)

[RFC 7518](https://tools.ietf.org/html/rfc7518) JSON Web Algorithms (JWA)

## License

[Apache 2.0 License](http://www.apache.org/licenses/LICENSE-2.0)
