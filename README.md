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
 use jwts::{Claims, jws};
 use jwts::jws::Header;
 use jwts::jws::alg::HS256;

 let claims = Claims {
     iss: Some("sea".to_owned()),
     ..Default::default()
 };
 assert_eq!(
     jws::sign::<HS256>(Header::default(), &claims, b"secret"),
     Ok("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJzZWEifQ.L0DLtDjydcSK-c0gTyOYbmUQ_LUCZzqAGCINn2OLhFs".to_owned()),
 );
 ```

 ### Verify

 ```rust
 use jwts::{Claims, jws};
 use jwts::jws::{Header, Token};
 use jwts::jws::alg::HS256;

 let claims = Claims {
     iss: Some("sea".to_owned()),
     ..Default::default()
 };
 let token = jws::sign::<HS256>(Header::default(), &claims, b"secret").unwrap();

 let result = Token::<Claims>::verify_with_key::<HS256>(&token, b"secret");
 assert!(result.is_ok());
 ```

 ### Validate Claims

 ```rust
 use std::time;
 use std::time::{Duration, SystemTime};
 use jwts::Claims;
 use jwts::validate::{ExpectAud, ExpectIss, ExpectJti, ExpectSub, Expired, Iat, NotBefore, Validate};

 fn now_secs() -> u64 {
     SystemTime::now()
         .duration_since(time::UNIX_EPOCH)
         .unwrap_or(Duration::ZERO)
         .as_secs()
 }

 let claims = Claims {
     iss: Some("sea".to_owned()),
     sub: Some("subject".to_owned()),
     aud: Some("audience".to_owned()),
     jti: Some("id".to_owned()),
     iat: Some(now_secs()),
     nbf: Some(now_secs()),
     exp: Some(now_secs() + 1),
 };
 assert_eq!(claims.validate(IssuedAtTime), Ok(()));
 assert_eq!(claims.validate(NotBeforeTime), Ok(()));
 assert_eq!(claims.validate(ExpiredTime), Ok(()));
 assert_eq!(claims.validate(ExpectIss("sea")), Ok(()));
 assert_eq!(claims.validate(ExpectSub("subject")), Ok(()));
 assert_eq!(claims.validate(ExpectAud("audience")), Ok(()));
 assert_eq!(claims.validate(ExpectJti("id")), Ok(()));
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

## More

[RFC 7519](https://tools.ietf.org/html/rfc7519) JSON Web Token (JWT)

[RFC 7515](https://tools.ietf.org/html/rfc7515) JSON Web Signature (JWS)

[RFC 7518](https://tools.ietf.org/html/rfc7518) JSON Web Algorithms (JWA)

## License

[Apache 2.0 License](http://www.apache.org/licenses/LICENSE-2.0)
