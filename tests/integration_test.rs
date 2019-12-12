//! Integration tests.

#[macro_use]
extern crate serde_derive;

use std::collections::HashMap;

use serde_json::json;

use jwt::{Claims, jws};
use jwt::jws::{Alg, Header, Token};

#[derive(Serialize, Deserialize)]
struct CustomClaims {
    iss: String,
}

#[test]
fn test_sign() {
    let mut c1 = Claims::new();
    c1.iss = Some("sea".to_owned());

    let mut c2 = HashMap::new();
    c2.insert("iss", "sea");

    let mut c3 = CustomClaims {
        iss: "sea".to_owned(),
    };

    let mut t1 = Token::new(c1);
    let mut t2 = Token::new(c2);
    let mut t3 = Token::new(c3);

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

    let mut t = Token::with_header(h, c);
    t.sign(&Alg::HS256("secret".to_owned()));

    println!("{}", t.to_string());
}
