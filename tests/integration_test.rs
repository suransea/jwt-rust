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
fn test_sign_rsa() {
    let mut claims = Claims::new();
    claims.iss = Some("sea".to_owned());

    let mut token = Token::with_payload(claims);

    let key = include_bytes!("rsa-pri.der").to_vec();
    let algorithms = [
        Algorithm::RS256,
        Algorithm::RS384,
        Algorithm::RS512,
        Algorithm::PS256,
        Algorithm::PS384,
        Algorithm::PS512,
    ];
    for &algorithm in algorithms.iter() {
        let key = Key::new(&key, algorithm);
        let token = token.sign(&key).unwrap();

        println!("{}", token);
    }
}

#[test]
fn test_sign_ecdsa() {
    let mut claims = Claims::new();
    claims.iss = Some("sea".to_owned());

    let mut token = Token::with_payload(claims);

    let key256 = include_bytes!("ecdsa-pri.pk8").to_vec();
    let key256 = Key::new(&key256, Algorithm::ES256);
    let token256 = token.sign(&key256).unwrap();

    println!("{}", token256);

    let key384 = include_bytes!("ecdsa-pri384.pk8").to_vec();
    let key384 = Key::new(&key384, Algorithm::ES384);
    let token384 = token.sign(&key384).unwrap();

    println!("{}", token384);
}

#[test]
fn test_sign_eddsa() {
    let mut claims = Claims::new();
    claims.iss = Some("sea".to_owned());

    let mut token = Token::with_payload(claims);

    let key = include_bytes!("eddsa-pri.pk8").to_vec();
    let key = Key::new(&key, Algorithm::EdDSA);
    let token = token.sign(&key).unwrap();

    println!("{}", token);
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
fn test_decode_error() {
    let token = "eyJ0eXAiOiUzI1NiJ9.eyJpc3MizZWEifQ.L0c0gTyOYbmUQ_LUCn2OLhFs";

    // decode the payload to standard jwt::Claims
    let result = Token::<Claims>::decode(token);

    match result {
        Ok(token) => println!("{:?}", token),
        Err(err) => println!("{:?}", err)
    }
}

#[test]
fn test_validate() {
    // generate a token for validating claims
    let mut c = Claims::new();
    c.iss = Some("sea".to_owned());
    c.iat = Some(now_unix_secs());
    c.nbf = Some(now_unix_secs());
    c.exp = Some(now_unix_secs() + 100);

    let mut t = Token::with_payload(c);
    let t = t.sign(&Key::new(b"secret", Algorithm::HS256)).unwrap();
    println!("{}", t);

    let t: Token<Claims> = Token::decode(&t).unwrap();

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
    let result = t.validate_claims(&conf);
    match result {
        Ok(()) => println!("valid claims."),
        Err(err) => println!("{:?}", err)
    }
}

#[test]
fn test_verify() {
    let mut c = Claims::new();
    c.iss = Some("sea".to_owned());

    let mut t = Token::with_payload(c);
    let t = t.sign(&Key::new(b"secret", Algorithm::HS256)).unwrap();
    println!("{}", t);

    // verify
    let _verified: Token<Claims> = Token::verify_with_key_resolver(&t, |_header, _payload| {
        Key::new(b"secret", Algorithm::HS256)
    }).unwrap();
}

#[test]
fn test_verify_rsa() {
    let mut claims = Claims::new();
    claims.iss = Some("sea".to_owned());

    let mut token = Token::with_payload(claims);

    let key = include_bytes!("rsa-pri.der").to_vec();
    let algorithms = [
        Algorithm::RS256,
        Algorithm::RS384,
        Algorithm::RS512,
        Algorithm::PS256,
        Algorithm::PS384,
        Algorithm::PS512,
    ];
    for &algorithm in algorithms.iter() {
        let key = Key::new(&key, algorithm);
        let token = token.sign(&key).unwrap();

        println!("{}", token);
        let key = include_bytes!("rsa-pub.der").to_vec();
        let key = Key::new(key, algorithm);
        let result = Token::<Claims>::verify_with_key(&token, &key);
        match result {
            Ok(_token) => println!("signature verified."),
            Err(err) => println!("{:?}", err)
        }
    }
}

#[test]
fn test_verify_eddsa() {
    let mut claims = Claims::new();
    claims.iss = Some("sea".to_owned());

    let mut token = Token::with_payload(claims);

    let key = include_bytes!("eddsa-pri.pk8").to_vec();
    let key = Key::new(&key, Algorithm::EdDSA);
    let token = token.sign(&key).unwrap();
    println!("{}", token);

    let key = include_bytes!("eddsa-pub.der").to_vec();
    let key = Key::new(key, Algorithm::EdDSA);
    let result = Token::<Claims>::verify_with_key(&token, &key);
    match result {
        Ok(_token) => println!("signature verified."),
        Err(err) => println!("{:?}", err)
    }
}
