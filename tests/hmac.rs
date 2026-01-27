#![allow(deprecated)]
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use time::OffsetDateTime;
use wasm_bindgen_test::wasm_bindgen_test;

use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, HeaderValue, Validation,
    crypto::{sign, verify},
    decode, decode_header, encode,
};

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct Claims {
    sub: String,
    company: String,
    exp: i64,
}

#[test]
#[wasm_bindgen_test]
fn sign_hs256() {
    let result =
        sign(b"hello world", &EncodingKey::from_secret(b"secret"), Algorithm::HS256).unwrap();
    let expected = "c0zGLzKEFWj0VxWuufTXiRMk5tlI5MbGDAYhzaxIYjo";
    assert_eq!(result, expected);
}

#[test]
#[wasm_bindgen_test]
fn verify_hs256() {
    let sig = "c0zGLzKEFWj0VxWuufTXiRMk5tlI5MbGDAYhzaxIYjo";
    let valid = verify(sig, b"hello world", &DecodingKey::from_secret(b"secret"), Algorithm::HS256)
        .unwrap();
    assert!(valid);
}

#[test]
#[wasm_bindgen_test]
fn encode_with_custom_header() {
    let my_claims = Claims {
        sub: "b@b.com".to_string(),
        company: "ACME".to_string(),
        exp: OffsetDateTime::now_utc().unix_timestamp() + 10000,
    };
    let header = Header { kid: Some("kid".to_string()), ..Default::default() };
    let token = encode(&header, &my_claims, &EncodingKey::from_secret(b"secret")).unwrap();

    let token_data = decode::<Claims>(
        &token,
        &DecodingKey::from_secret(b"secret"),
        &Validation::new(Algorithm::HS256),
    )
    .unwrap();
    assert_eq!(my_claims, token_data.claims);
    assert_eq!("kid", token_data.header.kid.unwrap());
    assert!(token_data.header.extras.is_empty());
}

#[test]
#[wasm_bindgen_test]
fn encode_with_extra_custom_header() {
    let my_claims = Claims {
        sub: "b@b.com".to_string(),
        company: "ACME".to_string(),
        exp: OffsetDateTime::now_utc().unix_timestamp() + 10000,
    };
    let mut extras = HashMap::with_capacity(1);
    extras.insert("custom".to_string(), HeaderValue::String("header".to_string()));
    let header = Header { kid: Some("kid".to_string()), extras, ..Default::default() };
    let token = encode(&header, &my_claims, &EncodingKey::from_secret(b"secret")).unwrap();
    let token_data = decode::<Claims>(
        &token,
        &DecodingKey::from_secret(b"secret"),
        &Validation::new(Algorithm::HS256),
    )
    .unwrap();
    assert_eq!(my_claims, token_data.claims);
    assert_eq!("kid", token_data.header.kid.unwrap());
    match token_data.header.extras.get("custom").unwrap() {
        HeaderValue::String(s) => assert_eq!("header", s),
        _ => panic!("Expected string value"),
    }
}

#[test]
#[wasm_bindgen_test]
fn encode_with_multiple_extra_custom_headers() {
    let my_claims = Claims {
        sub: "b@b.com".to_string(),
        company: "ACME".to_string(),
        exp: OffsetDateTime::now_utc().unix_timestamp() + 10000,
    };
    let mut extras = HashMap::with_capacity(2);
    extras.insert("custom1".to_string(), HeaderValue::String("header1".to_string()));
    extras.insert("custom2".to_string(), HeaderValue::String("header2".to_string()));
    let header = Header { kid: Some("kid".to_string()), extras, ..Default::default() };
    let token = encode(&header, &my_claims, &EncodingKey::from_secret(b"secret")).unwrap();
    let token_data = decode::<Claims>(
        &token,
        &DecodingKey::from_secret(b"secret"),
        &Validation::new(Algorithm::HS256),
    )
    .unwrap();
    assert_eq!(my_claims, token_data.claims);
    assert_eq!("kid", token_data.header.kid.unwrap());
    let extras = token_data.header.extras;
    match extras.get("custom1").unwrap() {
        HeaderValue::String(s) => assert_eq!("header1", s),
        _ => panic!("Expected string value"),
    }
    match extras.get("custom2").unwrap() {
        HeaderValue::String(s) => assert_eq!("header2", s),
        _ => panic!("Expected string value"),
    }
}

#[test]
#[wasm_bindgen_test]
fn encode_with_numeric_header() {
    let my_claims = Claims {
        sub: "b@b.com".to_string(),
        company: "ACME".to_string(),
        exp: OffsetDateTime::now_utc().unix_timestamp() + 10000,
    };
    let mut extras = HashMap::with_capacity(2);
    extras.insert("version".to_string(), HeaderValue::Number(42));
    extras.insert("build".to_string(), HeaderValue::Number(1234567890));
    let header = Header { kid: Some("kid".to_string()), extras, ..Default::default() };
    let token = encode(&header, &my_claims, &EncodingKey::from_secret(b"secret")).unwrap();
    let token_data = decode::<Claims>(
        &token,
        &DecodingKey::from_secret(b"secret"),
        &Validation::new(Algorithm::HS256),
    )
    .unwrap();
    assert_eq!(my_claims, token_data.claims);
    assert_eq!("kid", token_data.header.kid.unwrap());
    
    // Verify numeric values
    match token_data.header.extras.get("version").unwrap() {
        HeaderValue::Number(n) => assert_eq!(42, *n),
        _ => panic!("Expected numeric value"),
    }
    match token_data.header.extras.get("build").unwrap() {
        HeaderValue::Number(n) => assert_eq!(1234567890, *n),
        _ => panic!("Expected numeric value"),
    }
}

#[test]
#[wasm_bindgen_test]
fn encode_with_mixed_header_types() {
    let my_claims = Claims {
        sub: "b@b.com".to_string(),
        company: "ACME".to_string(),
        exp: OffsetDateTime::now_utc().unix_timestamp() + 10000,
    };
    let mut extras = HashMap::with_capacity(3);
    extras.insert("debug".to_string(), HeaderValue::Boolean(true));
    extras.insert("production".to_string(), HeaderValue::Boolean(false));
    extras.insert("version".to_string(), HeaderValue::Number(2));
    extras.insert("app_name".to_string(), HeaderValue::String("my_app".to_string()));
    
    let header = Header { kid: Some("kid".to_string()), extras, ..Default::default() };
    let token = encode(&header, &my_claims, &EncodingKey::from_secret(b"secret")).unwrap();
    let token_data = decode::<Claims>(
        &token,
        &DecodingKey::from_secret(b"secret"),
        &Validation::new(Algorithm::HS256),
    )
    .unwrap();
    assert_eq!(my_claims, token_data.claims);
    
    // Verify mixed types
    match token_data.header.extras.get("debug").unwrap() {
        HeaderValue::Boolean(b) => assert_eq!(true, *b),
        _ => panic!("Expected boolean value"),
    }
    match token_data.header.extras.get("production").unwrap() {
        HeaderValue::Boolean(b) => assert_eq!(false, *b),
        _ => panic!("Expected boolean value"),
    }
    match token_data.header.extras.get("version").unwrap() {
        HeaderValue::Number(n) => assert_eq!(2, *n),
        _ => panic!("Expected numeric value"),
    }
    match token_data.header.extras.get("app_name").unwrap() {
        HeaderValue::String(s) => assert_eq!("my_app", s),
        _ => panic!("Expected string value"),
    }
}

#[test]
#[wasm_bindgen_test]
fn round_trip_claim() {
    let my_claims = Claims {
        sub: "b@b.com".to_string(),
        company: "ACME".to_string(),
        exp: OffsetDateTime::now_utc().unix_timestamp() + 10000,
    };
    let token =
        encode(&Header::default(), &my_claims, &EncodingKey::from_secret(b"secret")).unwrap();
    let token_data = decode::<Claims>(
        &token,
        &DecodingKey::from_secret(b"secret"),
        &Validation::new(Algorithm::HS256),
    )
    .unwrap();
    assert_eq!(my_claims, token_data.claims);
    assert!(token_data.header.kid.is_none());
}

#[test]
#[wasm_bindgen_test]
fn decode_token() {
    let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUiLCJleHAiOjI1MzI1MjQ4OTF9.9r56oF7ZliOBlOAyiOFperTGxBtPykRQiWNFxhDCW98";
    let claims = decode::<Claims>(
        token,
        &DecodingKey::from_secret(b"secret"),
        &Validation::new(Algorithm::HS256),
    );
    println!("{:?}", claims);
    claims.unwrap();
}

#[test]
#[wasm_bindgen_test]
fn decode_token_custom_headers() {
    let token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6ImtpZCIsImN1c3RvbTEiOiJoZWFkZXIxIiwiY3VzdG9tMiI6ImhlYWRlcjIifQ.eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUiLCJleHAiOjI1MzI1MjQ4OTF9.FtOHsoKcNH3SriK3tnR-uWJg4UV4FkOzvq_JCfLngfU";
    let claims = decode::<Claims>(
        token,
        &DecodingKey::from_secret(b"secret"),
        &Validation::new(Algorithm::HS256),
    )
    .unwrap();
    let my_claims =
        Claims { sub: "b@b.com".to_string(), company: "ACME".to_string(), exp: 2532524891 };
    assert_eq!(my_claims, claims.claims);
    assert_eq!("kid", claims.header.kid.unwrap());
    let extras = claims.header.extras;
    match extras.get("custom1").unwrap() {
        HeaderValue::String(s) => assert_eq!("header1", s),
        _ => panic!("Expected string value"),
    }
    match extras.get("custom2").unwrap() {
        HeaderValue::String(s) => assert_eq!("header2", s),
        _ => panic!("Expected string value"),
    }
}

#[test]
#[wasm_bindgen_test]
#[should_panic(expected = "InvalidToken")]
fn decode_token_missing_parts() {
    let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
    let claims = decode::<Claims>(
        token,
        &DecodingKey::from_secret(b"secret"),
        &Validation::new(Algorithm::HS256),
    );
    claims.unwrap();
}

#[test]
#[wasm_bindgen_test]
fn decode_token_invalid_signature() {
    let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUifQ.Hm0yvKH25TavFPz7J_coST9lZFYH1hQo0tvhvImmaks";
    let claims = decode::<Claims>(
        token,
        &DecodingKey::from_secret(b"secret"),
        &Validation::new(Algorithm::HS256),
    );
    assert_eq!(claims.unwrap_err().into_kind(), ErrorKind::InvalidSignature);
}

#[test]
#[wasm_bindgen_test]
fn decode_token_wrong_algorithm() {
    let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUifQ.I1BvFoHe94AFf09O6tDbcSB8-jp8w6xZqmyHIwPeSdY";
    let claims = decode::<Claims>(
        token,
        &DecodingKey::from_secret(b"secret"),
        &Validation::new(Algorithm::RS512),
    );
    assert_eq!(claims.unwrap_err().into_kind(), ErrorKind::InvalidAlgorithm);
}

#[test]
#[wasm_bindgen_test]
fn encode_wrong_alg_family() {
    let my_claims = Claims {
        sub: "b@b.com".to_string(),
        company: "ACME".to_string(),
        exp: OffsetDateTime::now_utc().unix_timestamp() + 10000,
    };
    let claims = encode(&Header::default(), &my_claims, &EncodingKey::from_rsa_der(b"secret"));
    assert_eq!(claims.unwrap_err().into_kind(), ErrorKind::InvalidAlgorithm);
}

#[test]
#[wasm_bindgen_test]
fn decode_token_with_bytes_secret() {
    let token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUiLCJleHAiOjI1MzI1MjQ4OTF9.Hm0yvKH25TavFPz7J_coST9lZFYH1hQo0tvhvImmaks";
    let claims = decode::<Claims>(
        token,
        &DecodingKey::from_secret(b"\x01\x02\x03"),
        &Validation::new(Algorithm::HS256),
    );
    assert!(claims.is_ok());
}

#[test]
#[wasm_bindgen_test]
fn decode_header_only() {
    let token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJjb21wYW55IjoiMTIzNDU2Nzg5MCIsInN1YiI6IkpvaG4gRG9lIn0.S";
    let header = decode_header(token).unwrap();
    assert_eq!(header.alg, Algorithm::HS256);
    assert_eq!(header.typ, Some("JWT".to_string()));
}

#[test]
#[wasm_bindgen_test]
fn dangerous_insecure_decode_valid_token() {
    let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUiLCJleHAiOjI1MzI1MjQ4OTF9.9r56oF7ZliOBlOAyiOFperTGxBtPykRQiWNFxhDCW98";
    let mut validation = Validation::new(Algorithm::HS256);
    validation.insecure_disable_signature_validation();
    let claims = decode::<Claims>(token, &DecodingKey::from_secret(&[]), &validation);
    claims.unwrap();
}

#[test]
#[wasm_bindgen_test]
fn dangerous_insecure_decode_token_invalid_signature() {
    let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUiLCJleHAiOjI1MzI1MjQ4OTF9.wrong";
    let mut validation = Validation::new(Algorithm::HS256);
    validation.insecure_disable_signature_validation();
    let claims = decode::<Claims>(token, &DecodingKey::from_secret(&[]), &validation);
    claims.unwrap();
}

#[test]
#[wasm_bindgen_test]
fn dangerous_insecure_decode_token_wrong_algorithm() {
    let token = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUiLCJleHAiOjI1MzI1MjQ4OTF9.fLxey-hxAKX5rNHHIx1_Ch0KmrbiuoakDVbsJjLWrx8fbjKjrPuWMYEJzTU3SBnYgnZokC-wqSdqckXUOunC-g";
    let mut validation = Validation::new(Algorithm::HS256);
    validation.insecure_disable_signature_validation();
    let claims = decode::<Claims>(token, &DecodingKey::from_secret(&[]), &validation);
    claims.unwrap();
}

#[test]
#[wasm_bindgen_test]
fn dangerous_insecure_decode_token_with_validation_wrong_algorithm() {
    let token = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUiLCJleHAiOjk1MzI1MjQ4OX0.ONtEUTtP1QmyksYH9ijtPCaXoHjZVHcHKZGX1DuJyPiSyKlT93Y-oKgrp_OSkHSu4huxCcVObLzwsdwF-xwiAQ";
    let mut validation = Validation::new(Algorithm::HS256);
    validation.insecure_disable_signature_validation();
    let claims = decode::<Claims>(token, &DecodingKey::from_secret(&[]), &validation);
    let err = claims.unwrap_err();
    assert_eq!(err.kind(), &ErrorKind::ExpiredSignature);
}

#[test]
#[wasm_bindgen_test]
fn verify_hs256_rfc7517_appendix_a1() {
    #[derive(Debug, PartialEq, Eq, Clone, Deserialize)]
    struct C {
        iss: String,
    }
    let token = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let jwk = r#"{"kty":"oct",
                  "k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"
                 }"#;
    let jwk: Jwk = serde_json::from_str(jwk).unwrap();
    let key = DecodingKey::from_jwk(&jwk).unwrap();
    let mut validation = Validation::new(Algorithm::HS256);
    // The RFC example signed jwt has expired
    validation.validate_exp = false;
    let c = decode::<C>(token, &key, &validation).unwrap();
    assert_eq!(c.claims.iss, "joe");
}

// Regression tests for type confusion vulnerability where malformed claims
// (eg nbf or exp as strings) were silently treated as "not present" when not required
#[derive(Debug, Serialize)]
struct ClaimsWithStringNbf {
    sub: String,
    nbf: String, // should be a number
}

#[derive(Debug, Serialize)]
struct ClaimsWithStringExp {
    sub: String,
    exp: String, // should be a number
}

#[test]
#[wasm_bindgen_test]
fn test_string_nbf_rejected_when_validate_nbf_enabled() {
    // Create token with nbf as string (malformed)
    let claims = ClaimsWithStringNbf {
        sub: "test".to_string(),
        nbf: "99999999999".to_string(), // Far future as string
    };
    let token = encode(&Header::default(), &claims, &EncodingKey::from_secret(b"secret")).unwrap();

    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_nbf = true;
    validation.required_spec_claims = std::collections::HashSet::new();

    let result =
        decode::<serde_json::Value>(&token, &DecodingKey::from_secret(b"secret"), &validation);

    assert!(result.is_err());
    assert_eq!(result.unwrap_err().into_kind(), ErrorKind::InvalidClaimFormat("nbf".to_string()));
}

#[test]
#[wasm_bindgen_test]
fn test_string_exp_rejected_when_validate_exp_enabled() {
    // Create token with exp as string (malformed)
    let claims = ClaimsWithStringExp {
        sub: "test".to_string(),
        exp: "99999999999".to_string(), // Far future as string
    };
    let token = encode(&Header::default(), &claims, &EncodingKey::from_secret(b"secret")).unwrap();

    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;
    validation.required_spec_claims = std::collections::HashSet::new();

    let result =
        decode::<serde_json::Value>(&token, &DecodingKey::from_secret(b"secret"), &validation);

    assert!(result.is_err());
    assert_eq!(result.unwrap_err().into_kind(), ErrorKind::InvalidClaimFormat("exp".to_string()));
}
