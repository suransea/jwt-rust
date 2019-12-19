# jwt-rust

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
let token = token.sign(&key).unwrap_or_default();

assert_eq!(token, "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJzZWEifQ.L0DLtDjydcSK-c0gTyOYbmUQ_LUCZzqAGCINn2OLhFs");
```

### Parse and Verify

```rust
use jwts::{Claims, jws};
use jwts::jws::{Algorithm, Config, Key, SignatureValidation, Token};

let key = Key::new(b"secret", Algorithm::HS256);
let signature_validation = SignatureValidation::Key(key);

// use key resolver like:
// let signature_validation = SignatureValidation::KeyResolver(|header, payload| {
//     // return a Key here
// });

let config = Config {
    signature_validation,
    iat_validation: true,
    nbf_validation: true,
    exp_validation: true,
    expected_iss: Some("sea".to_owned()),
    expected_sub: None,
    expected_aud: None,
    expected_jti: None,
};

let token = "a jwt token";

let token: Option<Token<Claims>> = jws::parse(token, &config)
    .map(Option::Some)
    .unwrap_or_else(|err| {
        println!("{:?}", err.kind());
        None
    });
println!("{:?}", token);
```

### Custom Claims

```rust
use jwts::{Claims, jws};
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
let token = token.sign(&key).unwrap_or_default();
let token: Token<CustomClaims> = jws::parse_validate_none(&token).unwrap();
println!("{:?}", token);
```

## Algorithms

Sign and verify use crate [ring](https://crates.io/crates/ring).

- [x] HS256 - HMAC using SHA-256
- [x] HS384 - HMAC using SHA-384
- [x] HS512 - HMAC using SHA-512
- [x] RS256 - PKCS#1 1.5 padding using SHA-256 for RSA signatures
- [x] RS384 - PKCS#1 1.5 padding using SHA-384 for RSA signatures
- [x] RS512 - PKCS#1 1.5 padding using SHA-512 for RSA signatures
- [x] ES256 - ECDSA signatures using the P-256 curve and SHA-256
- [x] ES384 - ECDSA signatures using the P-384 curve and SHA-384
- [ ] ES512 - ECDSA signatures using the P-512 curve and SHA-512
- [x] PS256 - RSA PSS padding using SHA-256 for RSA signatures
- [x] PS384 - RSA PSS padding using SHA-384 for RSA signatures
- [x] PS512 - RSA PSS padding using SHA-512 for RSA signatures

## More

[RFC 7519](https://tools.ietf.org/html/rfc7519) JSON Web Token (JWT)

[RFC 7515](https://tools.ietf.org/html/rfc7515) JSON Web Signature (JWS)

## License

[Apache 2.0 License](http://www.apache.org/licenses/LICENSE-2.0)
