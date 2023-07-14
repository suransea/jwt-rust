//! Integration tests.

use std::collections::HashMap;
use std::time;
use std::time::{Duration, SystemTime};

use ring::signature::{Ed25519KeyPair, RsaKeyPair};
use serde_derive::{Deserialize, Serialize};

use jwts::{Claims, Error, jws};
use jwts::jws::{Algorithm, Header, Token};
use jwts::jws::alg::{Ed25519, ES256, ES384, HS256, HS384, HS512, PS256, PS384, PS512, RS256, RS384, RS512};
use jwts::validate::{ExpectAud, ExpectIss, ExpectJti, ExpectSub, ExpiredTime, IssuedAtTime, NotBeforeTime, Validate};

#[derive(Debug, Serialize, Deserialize)]
struct CustomClaims {
    iss: String,
}

#[test]
fn test_sign() {
    let c1 = Claims {
        iss: Some("sea".to_owned()),
        ..Default::default()
    };
    assert_eq!(
        jws::sign::<HS256>(Header::default(), &c1, b"secret"),
        Ok("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJzZWEifQ.L0DLtDjydcSK-c0gTyOYbmUQ_LUCZzqAGCINn2OLhFs".to_owned()),
    );

    let c2 = HashMap::from([("iss", "sea")]);
    assert_eq!(
        jws::sign::<HS384>(Header::default(), &c2, b"secret"),
        Ok("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzM4NCJ9.eyJpc3MiOiJzZWEifQ.8vpSRdUJBMEHhSV9HxwrVuK6f4isin5tjt-z27wwLcaypUmjypVjYusdYpmZZDPA".to_owned()),
    );

    let c3 = CustomClaims {
        iss: "sea".to_owned(),
    };
    assert_eq!(
        jws::sign::<HS512>(Header::default(), &c3, b"secret"),
        Ok("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJpc3MiOiJzZWEifQ.POLzcNhDxbm3VwWpjv8vRsqbkfOSqn00XZ3QTw_qITJglET3cOwlv6pqbXalZ6JQCTt9IJHKvovl66W6izp5VA".to_owned()),
    );
}

#[test]
fn test_sign_rsa() {
    let claims = Claims {
        iss: Some("sea".to_owned()),
        ..Default::default()
    };
    let key = RsaKeyPair::from_der(include_bytes!("rsa-pri.der")).unwrap();
    assert_eq!(
        jws::sign::<RS256>(Header::default(), &claims, &key),
        Ok("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJzZWEifQ.q20CYxjQ54NCYEQXYK5WyshkQMZtIdBRe0o458OaEgMWyuNMDYvopwL84-ABzeb_6VQKRY1e7F1j9ipoHuAtWr_gjkn05BDW3f_wwXZXRB1_8RZ32p1ZqXInwFRXDwEzUDRFAURzz6mrznS2Ia-_cpYtO5nB8LalupnvF03PcUAcLZapJLVVyGHooVp7HM4iQBYKwZoy1mhWsYJnwMNFcftPiXtytFxt6F2c_6huPCYooDTj-ce3avJf68idf5AxuWOoiIJYEIlwK4zYPPAna8U99Lfp5bCLJjgOx5WFqzREv5fW6rbuwmWo9K_ooxuPmbtRo-nd0LJIUIY7eosI7w".to_owned()),
    );
    assert_eq!(
        jws::sign::<RS384>(Header::default(), &claims, &key),
        Ok("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzM4NCJ9.eyJpc3MiOiJzZWEifQ.VA2FzDhbmRzhXg-XuITI0rdJsIuc_bjrhXbIhCbcPQLqwK_9RvpU3w9zbevK93BnsShsTv0t7SgHr4heIGmodTvjUVPhlOZbnd8zzufMfOYnJPHcucitB84a3oLsBmRm1gDz5gLghv7GV1MnJRUw2UpTtfTbY0ebzLIvNOr-avZKRYJq1uhguIPvQVwGWTDIBh51EFK-p_UoIB_rMr4gxJ0ANIlCt2VvUZA1ORrE7Gg7B4zyTopDxXUZKJqtuoWQmDCfCbhM3FnbikGPvyWaW9G4-8mhPZ2kRxlTUoTn0ExzUFiwaCBrnFmPVXzM8LloCn3f98I6qEIvVOuOcR9CBA".to_owned()),
    );
    assert_eq!(
        jws::sign::<RS512>(Header::default(), &claims, &key),
        Ok("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzUxMiJ9.eyJpc3MiOiJzZWEifQ.KW5qjSj6i_72IPrzfbo4Vty3h4MihAURtCtRU7KEnJPcaCLE1obx3Owj3PYdjFw_ih0hTDcCggzGIJy3lZbJqT4enCPYCCNOxoLUKYr7FCc5PveQ5xt2svLB_27YzSXYrMVJxjnapkPM-xwy5-0bJBRnnkUgf10AVZhf9YzIKITpnBSnHO9E4VFZL2OvStoIN3jqsJXjv0S8am4T9A5RKTOmaZ7Y2vUySAbAZN5GNDhEK71EkULu248KImiKPAHAtcsVUThC0-aiUB-_cEbSSTFkWIjKpjq-B3KPrKfqWKpK5AHIa5cYU18358CMGtTxCZHufUK7BD-v0taEmyzzuQ".to_owned()),
    );
    println!("{}", jws::sign::<PS256>(Header::default(), &claims, &key).unwrap());
    println!("{}", jws::sign::<PS384>(Header::default(), &claims, &key).unwrap());
    println!("{}", jws::sign::<PS512>(Header::default(), &claims, &key).unwrap());
}

#[test]
fn test_sign_ecdsa() {
    let claims = Claims {
        iss: Some("sea".to_owned()),
        ..Default::default()
    };

    let key256 = include_bytes!("ecdsa-pri.pk8");
    println!("{}", jws::sign::<ES256>(Header::default(), &claims, key256).unwrap());

    let key384 = include_bytes!("ecdsa-pri384.pk8");
    println!("{}", jws::sign::<ES384>(Header::default(), &claims, key384).unwrap());
}

#[test]
fn test_sign_eddsa() {
    let claims = Claims {
        iss: Some("sea".to_owned()),
        ..Default::default()
    };
    let key = Ed25519KeyPair::from_pkcs8(include_bytes!("eddsa-pri.pk8")).unwrap();
    println!("{}", jws::sign::<Ed25519>(Header::default(), &claims, &key).unwrap());
}

#[test]
fn test_sign_custom_header() {
    let header = Header {
        cty: Some("application/json".to_owned()),
        ..Default::default()
    };
    let claims = Claims {
        iss: Some("sea".to_owned()),
        ..Default::default()
    };
    assert_eq!(
        jws::sign::<HS256>(header, &claims, b"secret"),
        Ok("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImN0eSI6ImFwcGxpY2F0aW9uL2pzb24ifQ.eyJpc3MiOiJzZWEifQ.2tAOI3HXR1CJC4M4YdRRFAcZCsa3mBdx7qFW6lgqjVM".to_owned()),
    );
}

#[test]
fn test_decode() {
    let tok = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJzZWEifQ.L0DLtDjydcSK-c0gTyOYbmUQ_LUCZzqAGCINn2OLhFs";

    // decode the payload to standard jwt::Claims
    let t1: Token<Claims> = Token::decode(tok).unwrap();

    // decode the payload to custom claims
    let t2: Token<CustomClaims> = Token::decode(tok).unwrap();

    // decode the payload to HashMap
    let t3: Token<HashMap<String, String>> = Token::decode(tok).unwrap();

    println!("{:?}\n{:?}\n{:?}", t1, t2, t3);
}

#[test]
fn test_decode_error() {
    let token = "eyJ0eXAiOiUzI1NiJ9.eyJpc3MizZWEifQ.L0c0gTyOYbmUQ_LUCn2OLhFs";
    let result = Token::<Claims>::decode(token);
    assert_eq!(result, Err(Error::Malformed));
}

#[test]
fn test_verify() {
    let claims = Claims {
        iss: Some("sea".to_owned()),
        ..Default::default()
    };
    let token = jws::sign::<HS256>(Header::default(), &claims, b"secret").unwrap();

    let result = Token::<Claims>::verify_with_key_resolver::<HS256, _>(&token, |_header, _payload| {
        b"secret".to_owned()
    });
    assert!(result.is_ok());
}

#[test]
fn test_verify_rsa() {
    fn test_verify<A>() where A: Algorithm<SignKey=RsaKeyPair, VerifyKey=[u8]> {
        let claims = Claims {
            iss: Some("sea".to_owned()),
            ..Default::default()
        };
        let sign_key = RsaKeyPair::from_der(include_bytes!("rsa-pri.der")).unwrap();
        let token = jws::sign::<A>(Header::default(), &claims, &sign_key).unwrap();

        let verify_key = include_bytes!("rsa-pub.der");
        let result = Token::<Claims>::verify_with_key::<A>(&token, verify_key);
        assert!(result.is_ok());
    }
    test_verify::<RS256>();
    test_verify::<RS384>();
    test_verify::<RS512>();
    test_verify::<PS256>();
    test_verify::<PS384>();
    test_verify::<PS512>();
}

#[test]
fn test_verify_eddsa() {
    let claims = Claims {
        iss: Some("sea".to_owned()),
        ..Default::default()
    };
    let sign_key = Ed25519KeyPair::from_pkcs8(include_bytes!("eddsa-pri.pk8")).unwrap();
    let token = jws::sign::<Ed25519>(Header::default(), &claims, &sign_key).unwrap();

    let verify_key = include_bytes!("eddsa-pub.der");
    let result = Token::<Claims>::verify_with_key::<Ed25519>(&token, verify_key);
    assert!(result.is_ok());
}

#[test]
fn test_validate_claims() {
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
}
