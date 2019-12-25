//! Integration tests.

use std::collections::HashMap;
use std::time;
use std::time::{Duration, SystemTime};

use serde_derive::{Deserialize, Serialize};
use serde_json::{Map, Value};

use jwts::{Claims, ValidationConfig};
use jwts::jws::{Algorithm, Header, Key, Token};

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(time::UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs()
}

#[derive(Debug, Serialize, Deserialize)]
struct CustomClaims {
    iss: String,
}

#[test]
fn test_sign() {
    let mut c1 = Claims::new();
    c1.iss = Some("sea".to_owned());

    let mut c2 = HashMap::new();
    c2.insert("iss", "sea");

    let c3 = CustomClaims {
        iss: "sea".to_owned(),
    };

    let mut t1 = Token::with_payload(c1);
    let mut t2 = Token::with_payload(c2);
    let mut t3 = Token::with_payload(c3);

    let key = Key::new(b"secret", Algorithm::HS256);
    let t1 = t1.sign(&key).unwrap();
    let t2 = t2.sign(&key).unwrap();
    let t3 = t3.sign(&key).unwrap();

    println!("{}\n{}\n{}", t1, t2, t3);
}

#[test]
fn test_sign_custom_header() {
    let mut c = Claims::new();
    c.iss = Some("sea".to_owned());

    let mut h = Header::new();
    h.cty = Some("application/example".to_owned());

    let mut t = Token::with_header_and_payload(h, c);
    let t = t.sign(&Key::new("secret", Algorithm::HS256)).unwrap_or_default();

    println!("{}", t);
}

#[test]
fn test_decode() {
    let tok = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJzZWEifQ.L0DLtDjydcSK-c0gTyOYbmUQ_LUCZzqAGCINn2OLhFs";

    // decode the payload to standard jwt::Claims
    let t1: Token<Claims> = Token::decode(tok).unwrap();

    // decode the payload to custom claims
    let t2: Token<CustomClaims> = Token::decode(tok).unwrap();

    // decode the payload to serde_json::Map
    let t3: Token<Map<String, Value>> = Token::decode(tok).unwrap();

    println!("{:?}\n{:?}\n{:?}", t1, t2, t3);
}

#[test]
fn test_verify() {
    // generate
    let mut c = Claims::new();
    c.iss = Some("sea".to_owned());
    c.iat = Some(now_unix_secs());
    c.nbf = Some(now_unix_secs());
    c.exp = Some(now_unix_secs() + 100);

    let mut t = Token::with_payload(c);
    let t = t.sign(&Key::new("secret", Algorithm::HS256)).unwrap();
    println!("{}", t);


    // verify
    let t: Token<Claims> = Token::verify_with_key_resolver(&t, |_header, _payload| {
        Key::new(b"secret", Algorithm::HS256)
    }).unwrap();

    // validate claims
    let conf = ValidationConfig {
        iat_validation: true,
        nbf_validation: true,
        exp_validation: true,
        expected_iss: Some("sea".to_owned()),
        expected_sub: None,
        expected_aud: None,
        expected_jti: None,
    };
    t.validate_claims(&conf).unwrap();
    println!("{:?}", t);
}
