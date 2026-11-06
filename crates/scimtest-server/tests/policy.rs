mod support;

use base64::{Engine, engine::general_purpose::STANDARD};
use scimtest_server::application::{
    parse_instance_key, parse_public_key, parse_routes, request_allowed, valid_application_id,
    valid_instance_id,
};
use serde_json::json;
use support::{GoFixture, public_key};

#[test]
fn route_rules_and_identity_keys_match_the_actual_go_service() {
    let mut cases = Vec::new();
    for raw in [
        "GET,POST /oidc/{slug}/authorize\nPOST /oidc/{slug}/token",
        "* /saml/{slug}/sso",
        "\n get,GET,post /\r\n",
        "",
        "/oidc/{slug}/jwks",
        "GET /oidc/user-{slug}",
        "GET /oidc/*",
        "GET, /oidc",
        "GET relative",
        "GET /oidc/",
        "GET //oidc",
        "GET /oidc\\token",
        "GET /oidc/..",
        "GET /oidc/{9slug}",
        "GET /oidc/{slug_2}",
        "GET /oidc/{ſlug}",
        "ß /",
        "ſ /",
        "GE\u{7f}T /",
        "GET /{\u{7f}}",
    ] {
        cases.push(json!({"kind":"routes","routes":raw}));
    }
    cases.push(json!({"kind":"routes", "routes":"GET /oidc\n".repeat(101)}));
    for ch in (0..=0x10ffff)
        .filter_map(char::from_u32)
        .filter(|ch| ch.to_uppercase().count() > 1)
    {
        cases.push(json!({"kind":"routes","routes":format!("{ch} /")}));
    }
    let routes =
        "GET /oidc/{slug}/jwks\nGET,POST /saml/{slug}/sso\n* /\nGET /%2f\nGET /目录/{name}";
    for (method, path) in [
        ("GET", "/greendale/oidc/troy/jwks"),
        ("GET", "/greendale/oidc/troy/jwks?use=signing"),
        ("GET", "/greendale/oidc/green%2Fdale/jwks"),
        ("GET", "/greendale/oidc/green%5cdale/jwks"),
        ("GET", "/greendale/oidc/%2e%2e/jwks"),
        ("GET", "/greendale/oidc/%2e/jwks"),
        ("GET", "/greendale/oidc//jwks"),
        ("GET", "/greendale/oidc/troy/jwks/"),
        ("GET", "/greendale/oidc/%ff/jwks"),
        ("GET", "/greendale/oidc/🦀/jwks"),
        ("GET", "/greendale/%252f"),
        ("GET", "/greendale/%E7%9B%AE%E5%BD%95/%E8%9F%B9"),
        ("POST", "/greendale/oidc/troy/jwks"),
        ("HEAD", "/greendale/oidc/troy/jwks"),
        ("POST", "/greendale/saml/troy/sso"),
        ("GET", "/greendalehouse/oidc/troy/jwks"),
        ("GET", "/abed/oidc/troy/jwks"),
        ("DELETE", "/greendale"),
        ("DELETE", "/greendale/"),
    ] {
        cases.push(json!({"kind":"request","routes":routes,"method":method,"path":path,"root":"/greendale"}));
    }
    // Single-byte escapes exercise decoded segment matching without URL normalization.
    for byte in 0..=255 {
        cases.push(json!({"kind":"request","routes":routes,"method":"GET","path":format!("/greendale/oidc/%{byte:02x}/jwks"),"root":"/greendale"}));
    }
    let ssh = public_key(42);
    for key in [
        ssh.clone(),
        format!("{ssh} Troy Barnes at Greendale"),
        "ssh-rsa AAAA".into(),
        "ssh-ed25519 !".into(),
        "ssh-ed25519 AAAA".into(),
        format!("ssh-ed25519 {}", STANDARD.encode([0_u8; 32])),
        "ssh-ed25519".into(),
        "".into(),
    ] {
        cases.push(json!({"kind":"public_key","key":key}));
    }
    let instance = STANDARD.encode(
        ed25519_dalek::SigningKey::from_bytes(&[42; 32])
            .verifying_key()
            .as_bytes(),
    );
    for key in [
        instance.clone(),
        format!("{}\r\n{}", &instance[..16], &instance[16..]),
        instance.trim_end_matches('=').into(),
        "!".into(),
        "".into(),
        STANDARD.encode([0_u8; 31]),
        STANDARD.encode([255_u8; 32]),
    ] {
        cases.push(json!({"kind":"instance_key","key":key}));
    }
    for value in [
        "0123456789abcdef0123456789abcdef".to_owned(),
        "0123456789ABCDEF0123456789ABCDEF".into(),
        "troy-barnes_42".into(),
        "abed".repeat(32),
        "abed".repeat(33),
        "".into(),
        "🦀".into(),
        "x/y".into(),
    ] {
        cases.push(json!({"kind":"ids","value":value}));
    }
    let reference = GoFixture::new().run(json!({"kind":"policy","policies":cases}));
    println!(
        "Compared {} route, request-path, key and identity cases with Go",
        cases.len()
    );
    for (case, want) in cases.iter().zip(reference.as_array().unwrap()) {
        let got = match case["kind"].as_str().unwrap() {
            "routes" => match parse_routes(case["routes"].as_str().unwrap()) {
                Ok(routes) => json!({"routes":routes,"error":""}),
                Err(error) => json!({"routes":null,"error":error.to_string()}),
            },
            "request" => {
                let routes = parse_routes(case["routes"].as_str().unwrap()).unwrap();
                let path = case["path"].as_str().unwrap().split('?').next().unwrap();
                json!(request_allowed(
                    &routes,
                    case["root"].as_str().unwrap(),
                    case["method"].as_str().unwrap(),
                    path
                ))
            }
            "public_key" => match parse_public_key(case["key"].as_str().unwrap()) {
                Ok(key) => {
                    json!({"canonical":key.canonical,"bytes":STANDARD.encode(key.bytes),"fingerprint":key.fingerprint,"error":""})
                }
                Err(error) => {
                    json!({"canonical":"","bytes":null,"fingerprint":"","error":error.to_string()})
                }
            },
            "instance_key" => match parse_instance_key(case["key"].as_str().unwrap()) {
                Ok((bytes, id)) => json!({"bytes":STANDARD.encode(bytes),"id":id,"error":""}),
                Err(error) => json!({"bytes":null,"id":"","error":error.to_string()}),
            },
            "ids" => {
                json!({"application":valid_application_id(case["value"].as_str().unwrap()),"instance":valid_instance_id(case["value"].as_str().unwrap())})
            }
            _ => unreachable!(),
        };
        assert_eq!(got, *want, "case: {case}");
    }
}
