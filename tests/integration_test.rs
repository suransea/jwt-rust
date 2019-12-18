//! Integration tests.

#[macro_use]
extern crate serde_derive;

use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value};

use jwts::{Claims, jws};
use jwts::jws::{Algorithm, Config, Header, Key, SignatureValidation, Token};

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
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

    let mut t1 = Token::with_claims(c1);
    let mut t2 = Token::with_claims(c2);
    let mut t3 = Token::with_claims(c3);

    let key = Key::new("secret", Algorithm::HS256);
    t1.sign(&key);
    t2.sign(&key);
    t3.sign(&key);

    println!("{}\n{}\n{}", t1.to_string(), t2.to_string(), t3.to_string());
}

#[test]
fn test_sign_custom_header() {
    let mut c = Claims::new();
    c.iss = Some("sea".to_owned());

    let mut h = Header::new();
    h.cty = Some("application/example".to_owned());

    let mut t = Token::with_header_and_claims(h, c);
    t.sign(&Key::new("secret", Algorithm::HS256));

    println!("{}", t.to_string());
}

#[test]
fn test_parse() {
    let tok = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJzZWEifQ.L0DLtDjydcSK-c0gTyOYbmUQ_LUCZzqAGCINn2OLhFs";

    // parse claims to standard jwt::Claims
    let t1: Token<Claims> = jws::parse_verify_none(tok).unwrap();

    // parse claims to custom claims
    let t2: Token<CustomClaims> = jws::parse_verify_none(tok).unwrap();

    // parse claims to serde_json::Map
    let t3: Token<Map<String, Value>> = jws::parse_verify_none(tok).unwrap();

    println!("{:?}\n{:?}\n{:?}", t1, t2, t3);
}

#[test]
fn test_parse_error() {
    // generate
    let mut c = Claims::new();
    c.iss = Some("sea".to_owned());
    c.iat = Some(now_unix_secs());
    c.nbf = Some(now_unix_secs());
    c.exp = Some(now_unix_secs() + 100);

    let mut h = Header::new();
    h.cty = Some("application/example".to_owned());

    let mut t = Token::with_header_and_claims(h, c);
    t.sign(&Key::new("secret", Algorithm::HS256));
    let t = t.to_string();
    println!("{}", t);


    // parse
    let signature_validation = SignatureValidation::KeyResolver(|h, c| {
        Key::new("secret", Algorithm::HS256)
    });

    let conf = Config {
        signature_validation,
        iat_validation: true,
        nbf_validation: true,
        exp_validation: true,
    };

    let t: Option<Token<Claims>> = jws::parse(&t, &conf)
        .map(Option::Some)
        .unwrap_or_else(|err| {
            println!("{}", err.kind());
            None
        });
    println!("{:?}", t);
}
