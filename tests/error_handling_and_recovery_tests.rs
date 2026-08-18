//! Интеграционные тесты обработки ошибок и граничных состояний (Error Handling & Edge Cases)
use novaray_core::config::{AppConfig, UserSettings};
use novaray_core::matcher::{RoutingDecision, SplitTunnelMatcher};
use novaray_core::parser::VlessParser;

#[test]
fn test_corrupted_json_config_deserialization_fails_safely() {
    // 1. Поврежденный синтаксис JSON
    let invalid_json = "{ version: 1, profiles: [ }";
    let res: Result<AppConfig, _> = serde_json::from_str(invalid_json);
    assert!(
        res.is_err(),
        "Невалидный JSON должен приводить к ошибке десериализации"
    );

    // 2. Отсутствие обязательного поля `active_profile_id`
    let missing_field_json = r#"{
        "version": 1,
        "profiles": []
    }"#;
    let res2: Result<AppConfig, _> = serde_json::from_str(missing_field_json);
    assert!(
        res2.is_err(),
        "Отсутствие обязательного поля должно вызывать ошибку"
    );
}

#[test]
fn test_corrupted_settings_json_deserialization_fails_safely() {
    // Ошибочный тип данных: port в виде строки вместо числа
    let invalid_type_json = r#"{
        "version": 1,
        "client": {
            "auto_connect_on_launch": false,
            "kill_switch": true,
            "system_notifications": true,
            "dns_servers": ["192.0.2.53"],
            "local_socks_port": "one_thousand",
            "local_http_port": 10809
        },
        "split_tunneling": {
            "enabled": true,
            "mode": "bypass_selected",
            "direct_domains": [],
            "direct_ips": [],
            "direct_apps": []
        }
    }"#;

    let res: Result<UserSettings, _> = serde_json::from_str(invalid_type_json);
    assert!(
        res.is_err(),
        "Строковый порт вместо числа должен быть отклонен парсером Serde"
    );
}

#[test]
fn test_invalid_enum_values_fail_safely() {
    // Невалидный protocol
    let invalid_proto_json = r#"{
        "version": 1,
        "active_profile_id": "p1",
        "profiles": [{
            "id": "p1",
            "name": "Invalid Protocol",
            "protocol": "shadowsocks_unsupported",
            "server": "192.0.2.53",
            "port": 443,
            "uuid": "u1"
        }]
    }"#;
    let res_proto: Result<AppConfig, _> = serde_json::from_str(invalid_proto_json);
    assert!(res_proto.is_err());

    // Невалидный split tunneling mode
    let invalid_mode_json = r#"{
        "version": 1,
        "client": {
            "auto_connect_on_launch": false,
            "kill_switch": false,
            "system_notifications": false,
            "dns_servers": [],
            "local_socks_port": 10808,
            "local_http_port": 10809
        },
        "split_tunneling": {
            "enabled": true,
            "mode": "unsupported_legacy_mode",
            "direct_domains": [],
            "direct_ips": [],
            "direct_apps": []
        }
    }"#;
    let res_mode: Result<UserSettings, _> = serde_json::from_str(invalid_mode_json);
    assert!(res_mode.is_err());
}

#[test]
fn test_malformed_vless_uris_rejected() {
    let test_cases = vec![
        ("", "Пустая строка"),
        ("not_a_url", "Не ссылка"),
        ("ftp://user:pass@host:21", "Неподдерживаемый протокол FTP"),
        ("vless://", "Отсутствуют хост и порт"),
        ("vless://uuid@", "Отсутствует хост"),
        ("vless://uuid@host:notaport", "Нечисловой порт"),
        (
            "vless://uuid@host:443?security=relity",
            "Опечатка в security (fail-closed)",
        ),
        ("vless://uuid@host:443?flow=bogus_flow", "Неизвестный flow"),
        (
            "vless://uuid@host:443?type=grpc",
            "gRPC transport без обязательного path",
        ),
        (
            "vless://uuid@host:443?type=httpupgrade",
            "HTTP Upgrade transport пока не поддерживается",
        ),
        (
            "vless://uuid@host:443?type=future-transport",
            "Неизвестный transport",
        ),
        (
            "vless://uuid@host:443?type=tcp&headerType=http&host=cdn.example.com&path=%2F",
            "Неподдерживаемая TCP HTTP obfuscation",
        ),
        (
            "vless://uuid@host:443?Type=ws",
            "Некорректный регистр критичного query key",
        ),
        (
            "vless://uuid@host:443?security=reality",
            "Reality без обязательного public_key",
        ),
    ];

    for (uri, description) in test_cases {
        let result = VlessParser::parse_uri(uri);
        assert!(
            result.is_err(),
            "Кейс '{}' ({}) должен завершаться ошибкой",
            uri,
            description
        );
    }
}

#[test]
fn test_split_tunneling_complex_rule_evaluation() {
    let settings_json = r#"{
        "version": 1,
        "client": {
            "auto_connect_on_launch": false,
            "kill_switch": false,
            "system_notifications": false,
            "dns_servers": ["192.0.2.53"],
            "local_socks_port": 10808,
            "local_http_port": 10809
        },
        "split_tunneling": {
            "enabled": true,
            "mode": "bypass_selected",
            "direct_domains": [
                "geosite:category-ru",
                "domain:ya.ru",
                "sberbank.ru"
            ],
            "direct_ips": ["geoip:private"],
            "direct_apps": ["Telegram", "com.apple.Music"]
        }
    }"#;

    let settings: UserSettings = serde_json::from_str(settings_json).unwrap();
    let matcher = SplitTunnelMatcher::new(&settings.split_tunneling);

    // Домены из зоны .ru -> Direct
    assert_eq!(matcher.match_domain("api.ya.ru"), RoutingDecision::Direct);
    assert_eq!(
        matcher.match_domain("online.sberbank.ru"),
        RoutingDecision::Direct
    );
    assert_eq!(
        matcher.match_domain("custom.domain.ru"),
        RoutingDecision::Direct
    );

    // Иностранные сервисы -> Proxy
    assert_eq!(matcher.match_domain("chatgpt.com"), RoutingDecision::Proxy);
    assert_eq!(matcher.match_domain("github.com"), RoutingDecision::Proxy);
    assert_eq!(matcher.match_domain("bbc.co.uk"), RoutingDecision::Proxy);

    // Приложения
    assert_eq!(matcher.match_app("TELEGRAM"), RoutingDecision::Direct);
    assert_eq!(
        matcher.match_app("com.apple.Music"),
        RoutingDecision::Direct
    );
    assert_eq!(matcher.match_app("Firefox"), RoutingDecision::Proxy);
}

#[test]
fn test_tls_and_reality_validation_errors() {
    let raw_bad_sni = r#"{
        "version": 1,
        "active_profile_id": "p1",
        "profiles": [{
            "id": "p1",
            "name": "Bad SNI",
            "protocol": "vless",
            "server": "192.0.2.53",
            "port": 443,
            "uuid": "u1",
            "tls": {
                "enabled": true,
                "security": "tls",
                "server_name": "invalid host/with/slash"
            }
        }]
    }"#;
    let config_bad_sni: AppConfig = serde_json::from_str(raw_bad_sni).unwrap();
    assert!(config_bad_sni.validate().is_err());

    // IP literal in SNI
    let raw_ip_sni = r#"{
        "version": 1,
        "active_profile_id": "p1",
        "profiles": [{
            "id": "p1",
            "name": "IP SNI",
            "protocol": "vless",
            "server": "192.0.2.53",
            "port": 443,
            "uuid": "u1",
            "tls": {
                "enabled": true,
                "security": "tls",
                "server_name": "203.0.113.30"
            }
        }]
    }"#;
    let config_ip_sni: AppConfig = serde_json::from_str(raw_ip_sni).unwrap();
    assert!(config_ip_sni.validate().is_err());

    let raw_bad_pk = r#"{
        "version": 1,
        "active_profile_id": "p1",
        "profiles": [{
            "id": "p1",
            "name": "Bad PK",
            "protocol": "vless",
            "server": "192.0.2.53",
            "port": 443,
            "uuid": "u1",
            "tls": {
                "enabled": true,
                "security": "reality",
                "server_name": "example.com",
                "public_key": "bad base64 with spaces & invalid *&^%"
            }
        }]
    }"#;
    let config_bad_pk: AppConfig = serde_json::from_str(raw_bad_pk).unwrap();
    assert!(config_bad_pk.validate().is_err());

    // Public key valid base64 but not 32 bytes (e.g. 3 bytes or 16 bytes)
    let raw_short_pk = r#"{
        "version": 1,
        "active_profile_id": "p1",
        "profiles": [{
            "id": "p1",
            "name": "Short PK",
            "protocol": "vless",
            "server": "192.0.2.53",
            "port": 443,
            "uuid": "u1",
            "tls": {
                "enabled": true,
                "security": "reality",
                "server_name": "example.com",
                "public_key": "AAAA"
            }
        }]
    }"#;
    let config_short_pk: AppConfig = serde_json::from_str(raw_short_pk).unwrap();
    assert!(config_short_pk.validate().is_err());

    let raw_bad_sid = r#"{
        "version": 1,
        "active_profile_id": "p1",
        "profiles": [{
            "id": "p1",
            "name": "Bad Short ID",
            "protocol": "vless",
            "server": "192.0.2.53",
            "port": 443,
            "uuid": "u1",
            "tls": {
                "enabled": true,
                "security": "reality",
                "server_name": "example.com",
                "public_key": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
                "short_id": "1234567890abcdef1234567890"
            }
        }]
    }"#;
    let config_bad_sid: AppConfig = serde_json::from_str(raw_bad_sid).unwrap();
    assert!(config_bad_sid.validate().is_err());

    // Odd length short_id
    let raw_odd_sid = r#"{
        "version": 1,
        "active_profile_id": "p1",
        "profiles": [{
            "id": "p1",
            "name": "Odd Short ID",
            "protocol": "vless",
            "server": "192.0.2.53",
            "port": 443,
            "uuid": "u1",
            "tls": {
                "enabled": true,
                "security": "reality",
                "server_name": "example.com",
                "public_key": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
                "short_id": "abc"
            }
        }]
    }"#;
    let config_odd_sid: AppConfig = serde_json::from_str(raw_odd_sid).unwrap();
    assert!(config_odd_sid.validate().is_err());
}
