use novaray_core::config::{ClientSettings, SplitTunnelMode, SplitTunnelingSettings, UserSettings};
use novaray_core::config_generator::EngineConfigStrategy;
use novaray_core::parser::VlessParser;
use std::net::Ipv6Addr;

const USER: &str = "00000000-0000-4000-8000-000000000001";
const REALITY_KEY: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";

fn settings() -> UserSettings {
    UserSettings {
        schema: None,
        version: 1,
        client: ClientSettings {
            auto_connect_on_launch: false,
            kill_switch: false,
            system_notifications: false,
            dns_servers: vec![],
            local_socks_port: 10808,
            local_http_port: 10809,
        },
        split_tunneling: SplitTunnelingSettings {
            enabled: false,
            mode: SplitTunnelMode::ProxyAll,
            direct_domains: vec![],
            direct_ips: vec![],
            direct_apps: vec![],
        },
    }
}

#[test]
fn public_ipv6_server_is_canonical_in_both_generator_formats() {
    for (host, expected) in [
        ("2001:db8::1", "2001:db8::1"),
        ("2001:0DB8:0000:0000:0000:0000:0000:0001", "2001:db8::1"),
        ("2001:db8:1:2:3:4:5:6", "2001:db8:1:2:3:4:5:6"),
        ("::", "::"),
        ("::1", "::1"),
        ("::ffff:192.0.2.10", "::ffff:192.0.2.10"),
        ("::FFFF:c000:020a", "::ffff:192.0.2.10"),
    ] {
        let profile = VlessParser::parse_uri(&format!("vless://{USER}@[{host}]:8443"))
            .expect("valid bracketed IPv6 imports");
        assert_eq!(profile.server, expected);
        assert_eq!(
            profile.server.parse::<Ipv6Addr>().unwrap().to_string(),
            expected
        );
        assert_eq!(profile.port, 8443);
        let settings = settings();
        let xray = EngineConfigStrategy::Xray.generate(&profile, &settings);
        let sing_box = EngineConfigStrategy::SingBox.generate(&profile, &settings);
        assert_eq!(
            xray["outbounds"][0]["settings"]["vnext"][0]["address"],
            expected
        );
        assert_eq!(xray["outbounds"][0]["settings"]["vnext"][0]["port"], 8443);
        assert_eq!(sing_box["outbounds"][0]["server"], expected);
        assert_eq!(sing_box["outbounds"][0]["server_port"], 8443);
    }
}

#[test]
fn public_ipv6_preserves_legacy_identity_and_display_name() {
    for host in ["2001:db8::1", "2001:0DB8:0:0:0:0:0:1"] {
        let uri = format!("vless://{USER}@[{host}]:443");
        let profile = VlessParser::parse_uri(&uri).unwrap();
        assert_eq!(profile.server, "2001:db8::1");
        assert_eq!(profile.id, "vless-2001-db8--1-443-20e1f44a4ef7b986");
        assert_eq!(profile.name, "[2001:db8::1]:443");
        let named = VlessParser::parse_uri(&format!("{uri}#IPv6%20node")).unwrap();
        assert_eq!(named.name, "IPv6 node");
        assert_eq!(named.id, profile.id);
    }
}

#[test]
fn public_ipv6_sni_and_reality_policy_are_preserved() {
    let base = format!("vless://{USER}@[2001:db8::1]:443");
    let tls = VlessParser::parse_uri(&format!("{base}?security=tls")).unwrap();
    assert_eq!(tls.tls.unwrap().server_name, "");
    for security in ["tls", "reality"] {
        let profile = VlessParser::parse_uri(&format!(
            "{base}?security={security}&sni=identity.example&pbk={REALITY_KEY}"
        ))
        .unwrap();
        assert_eq!(profile.server, "2001:db8::1");
        assert_eq!(profile.tls.unwrap().server_name, "identity.example");
    }
    let error =
        VlessParser::parse_uri(&format!("{base}?security=reality&pbk={REALITY_KEY}")).unwrap_err();
    assert_eq!(error.to_string(), "Ошибка валидации профиля VLESS");
    assert!(error.source().is_none());
}

#[test]
fn public_invalid_ipv6_hosts_fail_without_echo_or_source() {
    for host in [
        "[2001:db8::PRIVATE-HOST]",
        "[2001:db8:::1]",
        "[2001:db8::1",
        "2001:db8::1",
        "[fe80::1%PRIVATE-ZONE]",
        "[fe80::1%25PRIVATE-ZONE]",
        "[%32%30%30%31:db8::1]",
    ] {
        let uri = format!("vless://PRIVATE-USER@{host}:443#PRIVATE-NAME");
        let error = VlessParser::parse_uri(&uri).unwrap_err();
        assert_eq!(error.to_string(), "Некорректный формат URI");
        assert!(error.source().is_none());
        for text in [
            error.to_string(),
            format!("{error:#}"),
            format!("{error:?}"),
        ] {
            for marker in ["PRIVATE-", "private-", host, &uri] {
                assert!(!text.contains(marker));
            }
        }
    }
}

#[test]
fn public_ipv4_and_domain_representation_remain_unchanged() {
    for (host, id_prefix, sni) in [
        ("192.0.2.10", "vless-192-0-2-10-443-", ""),
        ("edge.example", "vless-edge-example-443-", "edge.example"),
    ] {
        let profile =
            VlessParser::parse_uri(&format!("vless://{USER}@{host}:443?security=tls")).unwrap();
        assert_eq!(profile.server, host);
        assert!(profile.id.starts_with(id_prefix));
        assert_eq!(profile.name, format!("{host}:443"));
        assert_eq!(profile.tls.unwrap().server_name, sni);
    }
}

#[test]
fn public_ipv6_transport_aliases_keep_explicit_identity() {
    for query in [
        "type=ws&path=%2Fws&host=front.example",
        "type=grpc&serviceName=svc&authority=front.example",
    ] {
        let profile = VlessParser::parse_uri(&format!(
            "vless://{USER}@[2001:db8::1]:443?security=tls&sni=identity.example&{query}"
        ))
        .unwrap();
        assert_eq!(profile.server, "2001:db8::1");
        assert_eq!(profile.host.as_deref(), Some("front.example"));
        assert_eq!(profile.tls.unwrap().server_name, "identity.example");
    }
}

fn assert_transport_json(
    profile: &novaray_core::config::ServerProfile,
    transport: &str,
    expected_host: &str,
) {
    let settings = settings();
    let xray = EngineConfigStrategy::Xray.generate(profile, &settings);
    let sing_box = EngineConfigStrategy::SingBox.generate(profile, &settings);
    assert_eq!(
        xray["outbounds"][0]["settings"]["vnext"][0]["address"],
        profile.server
    );
    assert_eq!(sing_box["outbounds"][0]["server"], profile.server);
    assert_eq!(xray["outbounds"][0]["settings"]["vnext"][0]["port"], 8443);
    assert_eq!(sing_box["outbounds"][0]["server_port"], 8443);
    let xray_transport = &xray["outbounds"][0]["streamSettings"];
    let sing_box_transport = &sing_box["outbounds"][0]["transport"];
    match transport {
        "ws" => {
            assert_eq!(
                xray_transport["wsSettings"]["headers"]["Host"],
                expected_host
            );
            assert_eq!(sing_box_transport["headers"]["Host"], expected_host);
            assert_eq!(xray_transport["wsSettings"]["path"], "/ws");
            assert_eq!(sing_box_transport["path"], "/ws");
        }
        "grpc" => {
            assert_eq!(xray_transport["grpcSettings"]["authority"], expected_host);
            assert_eq!(sing_box_transport["authority"], expected_host);
            assert_eq!(xray_transport["grpcSettings"]["serviceName"], "svc");
            assert_eq!(sing_box_transport["service_name"], "svc");
        }
        _ => panic!("unexpected test transport"),
    }
}

#[test]
fn public_ipv6_http_fallback_is_bracketed_in_both_generator_formats() {
    for (host, canonical) in [
        ("2001:0DB8:0:0:0:0:0:1", "2001:db8::1"),
        ("::1", "::1"),
        ("::FFFF:c000:020a", "::ffff:192.0.2.10"),
    ] {
        for (transport, path) in [("ws", "path=%2Fws"), ("grpc", "serviceName=svc")] {
            for security in ["", "&security=none", "&security=tls"] {
                let profile = VlessParser::parse_uri(&format!(
                    "vless://{USER}@[{host}]:8443?type={transport}&{path}{security}"
                ))
                .unwrap();
                assert_eq!(profile.server, canonical);
                assert!(profile.host.is_none());
                if let Some(tls) = &profile.tls {
                    assert!(tls.server_name.is_empty());
                }
                assert_transport_json(&profile, transport, &format!("[{canonical}]"));
            }
        }
    }
}

#[test]
fn public_http_fallback_preserves_identity_precedence_and_legacy_hosts() {
    for (transport, path, alias) in [
        ("ws", "path=%2Fws", "host"),
        ("grpc", "serviceName=svc", "authority"),
    ] {
        for (extra, expected) in [
            (
                "&security=tls&sni=identity.example".to_string(),
                "identity.example",
            ),
            (
                format!("&security=tls&sni=identity.example&{alias}=front.example"),
                "front.example",
            ),
            (format!("&{alias}=%5B2001%3Adb8%3A%3A2%5D"), "[2001:db8::2]"),
        ] {
            let profile = VlessParser::parse_uri(&format!(
                "vless://{USER}@[2001:db8::1]:8443?type={transport}&{path}{extra}"
            ))
            .unwrap();
            assert_transport_json(&profile, transport, expected);
        }
        for host in ["192.0.2.10", "edge.example"] {
            let profile = VlessParser::parse_uri(&format!(
                "vless://{USER}@{host}:8443?type={transport}&{path}"
            ))
            .unwrap();
            assert_transport_json(&profile, transport, host);
        }
        // Existing bracketed profiles are not migrated or double-bracketed.
        let mut legacy = VlessParser::parse_uri(&format!(
            "vless://{USER}@[2001:db8::1]:8443?type={transport}&{path}"
        ))
        .unwrap();
        legacy.server = "[2001:db8::1]".to_string();
        assert_transport_json(&legacy, transport, "[2001:db8::1]");
    }
}
