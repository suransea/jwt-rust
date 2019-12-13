//! Integration tests.

#[macro_use]
extern crate serde_derive;

use std::collections::HashMap;

use serde_json::{Map, Value};

use jwt::{Claims, jws};
use jwt::jws::{Alg, Header, Token};

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

    let algorithm = Alg::HS256("secret".to_owned());
    t1.sign(&algorithm);
    t2.sign(&algorithm);
    t3.sign(&algorithm);

    println!("{}\n{}\n{}", t1.to_string(), t2.to_string(), t3.to_string());
}

#[test]
fn test_sign_custom_header() {
    let mut c = Claims::new();
    c.iss = Some("sea".to_owned());

    let mut h = Header::new();
    h.cty = Some("application/example".to_owned());

    let mut t = Token::with_header_and_claims(h, c);
    t.sign(&Alg::HS256("secret".to_owned()));

    println!("{}", t.to_string());
}

#[test]
fn test_parse() {
    let tok = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJzZWEifQ.L0DLtDjydcSK-c0gTyOYbmUQ_LUCZzqAGCINn2OLhFs";
    let algorithm = Alg::HS256("secret".to_owned());

    // parse claims to standard jwt::Claims
    let t1: Token<Claims> = jws::parse(tok, &algorithm).unwrap();

    // parse claims to custom claims
    let t2: Token<CustomClaims> = jws::parse(tok, &algorithm).unwrap();

    // parse claims to serde_json::Map
    let t3: Token<Map<String, Value>> = jws::parse(tok, &algorithm).unwrap();

    println!("{:?}\n{:?}\n{:?}", t1, t2, t3);
}

#[test]
fn test_parse_error() {
    let tok = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJzZWEifQ.L0DLtDjydcSK-c0gTyOYbmUQ_LUCZzqAGCINn2OLhFs";
    let algorithm = Alg::HS256("secret".to_owned());

    let t: Option<Token<Claims>> = jws::parse(tok, &algorithm)
        .map(Option::Some)
        .unwrap_or_else(|err| {
            match err.kind {
                jwt::ErrorKind::InvalidFormat(_) => println!("invalid token."),
                jwt::ErrorKind::InvalidSignature => println!("invalid signature."),
            }
            None
        });
    println!("{:?}", t);
}
