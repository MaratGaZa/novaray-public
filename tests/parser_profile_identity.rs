use novaray_core::config::{AppConfig, ServerProfile};
use novaray_core::parser::VlessParser;
use std::collections::HashSet;

const REALITY_KEY_A: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
const REALITY_KEY_B: &str = "AQECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";

#[test]
fn public_vless_canonical_normalization_handles_case_and_formatting() {
    let lower_uri = format!(
        "vless://00000000-0000-4000-8000-00000000000a@edge.example.com:443?security=reality&sni=sni.example.com&fp=chrome&sid=0a1b&pbk={REALITY_KEY_A}#test-node"
    );
    let upper_uri = format!(
        "vless://00000000-0000-4000-8000-00000000000A@EDGE.EXAMPLE.COM:443?security=reality&sni=SNI.EXAMPLE.COM&fp=CHROME&sid=0A1B&pbk={REALITY_KEY_A}#test-node"
    );

    let lower_profile = VlessParser::parse_uri(&lower_uri).expect("lower-case URI parses");
    let upper_profile = VlessParser::parse_uri(&upper_uri).expect("upper-case URI parses");

    assert_eq!(lower_profile.uuid, "00000000-0000-4000-8000-00000000000a");
    assert_eq!(upper_profile.uuid, "00000000-0000-4000-8000-00000000000a");
    assert_eq!(lower_profile.server, "edge.example.com");
    assert_eq!(upper_profile.server, "edge.example.com");

    let lower_tls = lower_profile.tls.as_ref().unwrap();
    let upper_tls = upper_profile.tls.as_ref().unwrap();
    assert_eq!(lower_tls.server_name, "sni.example.com");
    assert_eq!(upper_tls.server_name, "sni.example.com");
    assert_eq!(lower_tls.fingerprint.as_deref(), Some("chrome"));
    assert_eq!(upper_tls.fingerprint.as_deref(), Some("chrome"));
    assert_eq!(lower_tls.short_id.as_deref(), Some("0a1b"));
    assert_eq!(upper_tls.short_id.as_deref(), Some("0a1b"));

    assert_eq!(lower_profile.id, upper_profile.id);
    assert_eq!(lower_profile, upper_profile);
}

#[test]
fn public_vless_deterministic_profile_id_avoids_collisions_on_same_endpoint() {
    let host = "edge.example.com";
    let port = 443;
    let uuid_1 = "00000000-0000-4000-8000-000000000001";
    let uuid_2 = "00000000-0000-4000-8000-000000000002";

    let test_uris = [
        // 1. Base TCP without security
        format!("vless://{uuid_1}@{host}:{port}?security=none"),
        // 2. TCP with TLS default SNI
        format!("vless://{uuid_1}@{host}:{port}?security=tls"),
        // 3. TCP with TLS custom SNI
        format!("vless://{uuid_1}@{host}:{port}?security=tls&sni=custom.example.com"),
        // 4. TCP with Reality (key A)
        format!("vless://{uuid_1}@{host}:{port}?security=reality&sni=cdn.example.com&pbk={REALITY_KEY_A}"),
        // 5. TCP with Reality (key B)
        format!("vless://{uuid_1}@{host}:{port}?security=reality&sni=cdn.example.com&pbk={REALITY_KEY_B}"),
        // 6. TCP with Reality (key A, short_id)
        format!("vless://{uuid_1}@{host}:{port}?security=reality&sni=cdn.example.com&pbk={REALITY_KEY_A}&sid=0a1b"),
        // 7. TCP with XTLS Vision flow
        format!("vless://{uuid_1}@{host}:{port}?security=tls&flow=xtls-rprx-vision"),
        // 8. WebSocket transport (/ws1)
        format!("vless://{uuid_1}@{host}:{port}?type=ws&path=%2Fws1"),
        // 9. WebSocket transport (/ws2)
        format!("vless://{uuid_1}@{host}:{port}?type=ws&path=%2Fws2"),
        // 10. gRPC transport (svc1)
        format!("vless://{uuid_1}@{host}:{port}?type=grpc&serviceName=svc1"),
        // 11. Different UUID on TCP without security
        format!("vless://{uuid_2}@{host}:{port}?security=none"),
    ];

    let mut profiles: Vec<ServerProfile> = Vec::new();
    let mut seen_ids: HashSet<String> = HashSet::new();

    for uri in &test_uris {
        let profile = VlessParser::parse_uri(uri).expect("URI must parse successfully");
        assert_eq!(profile.server, host);
        assert_eq!(profile.port, port);

        // Verify ID format: vless-{safe_host}-{port}-{hash16}
        assert!(profile
            .id
            .starts_with(&format!("vless-edge-example-com-{port}-")));
        let hash_part = profile
            .id
            .strip_prefix(&format!("vless-edge-example-com-{port}-"))
            .unwrap();
        assert_eq!(hash_part.len(), 16, "hash component must be 16 hex chars");
        assert!(
            hash_part.chars().all(|c| c.is_ascii_hexdigit()),
            "hash must be hexadecimal"
        );

        assert!(
            seen_ids.insert(profile.id.clone()),
            "Duplicate profile ID detected for distinct configuration: {}",
            profile.id
        );
        profiles.push(profile);
    }

    assert_eq!(profiles.len(), 11);
    assert_eq!(seen_ids.len(), 11);

    // Verify all 11 profiles can coexist in an AppConfig and pass validation
    let app_config = AppConfig {
        schema: None,
        version: 1,
        active_profile_id: profiles[0].id.clone(),
        profiles,
    };

    assert!(
        app_config.validate().is_ok(),
        "AppConfig must validate without duplicate ID errors for all 11 endpoints"
    );
}

#[test]
fn public_vless_profile_id_disambiguates_hyphen_colliding_hosts() {
    let uuid = "00000000-0000-4000-8000-000000000001";
    let uri_dot = format!("vless://{uuid}@a.b.example.com:443?security=none");
    let uri_hyphen = format!("vless://{uuid}@a-b.example.com:443?security=none");

    let profile_dot = VlessParser::parse_uri(&uri_dot).expect("valid URI");
    let profile_hyphen = VlessParser::parse_uri(&uri_hyphen).expect("valid URI");

    // Both hosts have the slug "a-b-example-com"
    assert!(profile_dot.id.starts_with("vless-a-b-example-com-443-"));
    assert!(profile_hyphen.id.starts_with("vless-a-b-example-com-443-"));

    // But because of canonical server hashing, their IDs must differ!
    assert_ne!(
        profile_dot.id, profile_hyphen.id,
        "Distinct domain names that share the same hyphen slug must produce distinct profile IDs"
    );
}

#[test]
fn public_vless_profile_id_format_is_stable_and_deterministic() {
    let uri = format!(
        "vless://00000000-0000-4000-8000-000000000001@edge.example.com:8443?security=reality&sni=cdn.example.com&pbk={REALITY_KEY_A}&sid=0a1b&fp=chrome"
    );

    let baseline = VlessParser::parse_uri(&uri).unwrap();
    assert_eq!(baseline.id, "vless-edge-example-com-8443-80fde350f02fa7de");

    // 1. Repeated parsing yields identical ID
    for _ in 0..50 {
        let p = VlessParser::parse_uri(&uri).unwrap();
        assert_eq!(p.id, baseline.id);
    }

    // 2. Query parameter permutations yield identical profile and ID
    let permuted = format!(
        "vless://00000000-0000-4000-8000-000000000001@edge.example.com:8443?fp=chrome&sid=0a1b&pbk={REALITY_KEY_A}&sni=cdn.example.com&security=reality"
    );
    let p_permuted = VlessParser::parse_uri(&permuted).unwrap();
    assert_eq!(p_permuted.id, baseline.id);
    assert_eq!(p_permuted, baseline);

    // 3. User display fragment does not alter connection identity ID
    let with_frag1 = format!("{uri}#Node-Alpha");
    let with_frag2 = format!("{uri}#Node-Beta");
    let p_frag1 = VlessParser::parse_uri(&with_frag1).unwrap();
    let p_frag2 = VlessParser::parse_uri(&with_frag2).unwrap();

    assert_eq!(p_frag1.name, "Node-Alpha");
    assert_eq!(p_frag2.name, "Node-Beta");
    assert_eq!(p_frag1.id, baseline.id);
    assert_eq!(p_frag2.id, baseline.id);
}

#[test]
fn public_vless_field_framing_prevents_boundary_shifting_collisions() {
    let uuid = "00000000-0000-4000-8000-000000000001";
    // Candidate collision: boundary shift across authority and serviceName with delimiter '|'
    let uri_a = format!(
        "vless://{uuid}@edge.example.com:443?type=grpc&mode=gun&authority=a%7Cb&serviceName=c"
    );
    let uri_b = format!(
        "vless://{uuid}@edge.example.com:443?type=grpc&mode=gun&authority=a&serviceName=b%7Cc"
    );

    let profile_a = VlessParser::parse_uri(&uri_a).expect("URI A parses");
    let profile_b = VlessParser::parse_uri(&uri_b).expect("URI B parses");

    assert_eq!(profile_a.host.as_deref(), Some("a|b"));
    assert_eq!(profile_a.path.as_deref(), Some("c"));
    assert_eq!(profile_b.host.as_deref(), Some("a"));
    assert_eq!(profile_b.path.as_deref(), Some("b|c"));

    assert_ne!(
        profile_a.id, profile_b.id,
        "Length-prefixed field framing must prevent boundary shifting collisions"
    );
}

#[test]
fn public_vless_preserves_custom_string_user_id_case_while_normalizing_standard_uuids() {
    // 1. Standard RFC 4122 UUID is case-insensitively normalized to lowercase
    let standard_upper =
        "vless://A1B2C3D4-E5F6-47A8-89B0-C1D2E3F4A5B6@edge.example.com:443?security=none";
    let standard_lower =
        "vless://a1b2c3d4-e5f6-47a8-89b0-c1d2e3f4a5b6@edge.example.com:443?security=none";
    let p_std_u = VlessParser::parse_uri(standard_upper).expect("upper UUID parses");
    let p_std_l = VlessParser::parse_uri(standard_lower).expect("lower UUID parses");

    assert_eq!(p_std_u.uuid, "a1b2c3d4-e5f6-47a8-89b0-c1d2e3f4a5b6");
    assert_eq!(p_std_l.uuid, "a1b2c3d4-e5f6-47a8-89b0-c1d2e3f4a5b6");
    assert_eq!(p_std_u.id, p_std_l.id);

    // 2. Custom non-standard user string (Xray short ID) preserves case
    let custom_upper = "vless://ReviewUser@edge.example.com:443?security=none";
    let custom_lower = "vless://reviewuser@edge.example.com:443?security=none";
    let p_cust_u = VlessParser::parse_uri(custom_upper).expect("custom upper parses");
    let p_cust_l = VlessParser::parse_uri(custom_lower).expect("custom lower parses");

    assert_eq!(p_cust_u.uuid, "ReviewUser");
    assert_eq!(p_cust_l.uuid, "reviewuser");
    assert_ne!(
        p_cust_u.id, p_cust_l.id,
        "Custom non-UUID strings must preserve case and distinct identities"
    );

    // 3. 32-character hex string without hyphens is treated as arbitrary user string (preserves case)
    let hex32_upper = "vless://A1B2C3D4E5F647A889B0C1D2E3F4A5B6@edge.example.com:443?security=none";
    let hex32_lower = "vless://a1b2c3d4e5f647a889b0c1d2e3f4a5b6@edge.example.com:443?security=none";
    let p_hex_u = VlessParser::parse_uri(hex32_upper).expect("32-hex upper parses");
    let p_hex_l = VlessParser::parse_uri(hex32_lower).expect("32-hex lower parses");

    assert_eq!(p_hex_u.uuid, "A1B2C3D4E5F647A889B0C1D2E3F4A5B6");
    assert_eq!(p_hex_l.uuid, "a1b2c3d4e5f647a889b0c1d2e3f4a5b6");
    assert_ne!(
        p_hex_u.id, p_hex_l.id,
        "32-hex strings without hyphens must preserve case"
    );
}
