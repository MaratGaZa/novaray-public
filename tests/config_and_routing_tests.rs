//! Интеграционные тесты для NovaRay Core
use novaray_core::config::{
    AppConfig, ClientSettings, SplitTunnelMode, SplitTunnelingSettings, UserSettings,
};
use novaray_core::matcher::{RoutingDecision, SplitTunnelMatcher};
use novaray_core::parser::VlessParser;
use novaray_core::xray_generator::XrayConfigGenerator;

#[test]
fn test_end_to_end_vless_to_xray_pipeline() {
    // 1. Парсинг ссылки VLESS Reality
    let link = "vless://00000000-0000-4000-8000-000000000003@198.51.100.20:443?security=reality&encryption=none&pbk=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8&fp=chrome&type=tcp&flow=xtls-rprx-vision&sni=dl.google.com&sid=01234567#Test%20Reality%20Profile%20C";
    let profile = VlessParser::parse_uri(link).expect("URI парсинг должен пройти успешно");

    assert_eq!(profile.name, "Test Reality Profile C");
    assert_eq!(profile.server, "198.51.100.20");

    // 2. Чтение настроек по умолчанию
    let settings_json_str = r#"{
        "version": 1,
        "client": {
            "auto_connect_on_launch": false,
            "kill_switch": true,
            "system_notifications": true,
            "dns_servers": ["192.0.2.53", "198.51.100.53"],
            "local_socks_port": 10808,
            "local_http_port": 10809
        },
        "split_tunneling": {
            "enabled": true,
            "mode": "bypass_selected",
            "direct_domains": ["gosuslugi.ru", "yandex.ru"],
            "direct_ips": ["geoip:private", "198.51.100.1"],
            "direct_apps": ["Telegram", "com.yandex.desktop.music"]
        }
    }"#;

    let settings: UserSettings =
        serde_json::from_str(settings_json_str).expect("JSON настроек валиден");
    assert!(settings.validate().is_ok());

    // 3. Проверка правил раздельного туннелирования
    let matcher = SplitTunnelMatcher::new(&settings.split_tunneling);
    assert_eq!(
        matcher.match_domain("gosuslugi.ru"),
        RoutingDecision::Direct
    );
    assert_eq!(
        matcher.match_domain("sub.yandex.ru"),
        RoutingDecision::Direct
    );
    assert_eq!(matcher.match_domain("twitter.com"), RoutingDecision::Proxy);
    assert_eq!(matcher.match_app("Telegram"), RoutingDecision::Direct);
    assert_eq!(matcher.match_app("Chrome"), RoutingDecision::Proxy);
    assert_eq!(matcher.match_ip("192.168.1.50"), RoutingDecision::Direct);

    // 4. Генерация Xray-core конфигурации
    let xray_config = XrayConfigGenerator::generate(&profile, &settings);
    assert!(xray_config["inbounds"].is_array());
    assert_eq!(
        xray_config["outbounds"][0]["streamSettings"]["realitySettings"]["password"],
        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
    );
}

#[test]
fn test_standard_tls_pipeline_and_xray_generation() {
    let raw_uri = "vless://00000000-0000-4000-8000-000000000004@tls.example.com:443?security=tls&sni=tls.example.com&fp=firefox&type=tcp#TLS-Profile";
    let profile = VlessParser::parse_uri(raw_uri).expect("Standard TLS URI должен парситься");
    assert!(profile.validate().is_ok());

    let settings = UserSettings {
        schema: None,
        version: 1,
        client: ClientSettings {
            auto_connect_on_launch: false,
            kill_switch: true,
            system_notifications: false,
            dns_servers: vec!["198.51.100.53".to_string()],
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
    };

    let xray_config = XrayConfigGenerator::generate(&profile, &settings);
    let proxy_outbound = &xray_config["outbounds"][0];

    assert_eq!(proxy_outbound["protocol"], "vless");
    assert_eq!(proxy_outbound["streamSettings"]["security"], "tls");
    assert_eq!(
        proxy_outbound["streamSettings"]["tlsSettings"]["serverName"],
        "tls.example.com"
    );
    assert_eq!(
        proxy_outbound["streamSettings"]["tlsSettings"]["allowInsecure"],
        false
    );
    assert_eq!(
        proxy_outbound["streamSettings"]["tlsSettings"]["fingerprint"],
        "firefox"
    );
}

#[test]
fn test_config_example_file_integrity() {
    let example_config_str = include_str!("../config.example.json");
    let config: AppConfig = serde_json::from_str(example_config_str)
        .expect("config.example.json должен успешно десериализоваться");

    assert!(config.validate().is_ok());
    assert!(!config.profiles.is_empty());
}

#[test]
fn test_settings_example_file_integrity() {
    let example_settings_str = include_str!("../settings.example.json");
    let settings: UserSettings = serde_json::from_str(example_settings_str)
        .expect("settings.example.json должен успешно десериализоваться");

    assert!(settings.validate().is_ok());
    assert!(settings.split_tunneling.enabled);
}

#[test]
fn test_json_schemas_compile_and_validate_examples_and_reject_invalid_instances() {
    let config_schema_str = include_str!("../schema/config.schema.json");
    let config_schema_json: serde_json::Value = serde_json::from_str(config_schema_str)
        .expect("config.schema.json должен быть валидным JSON");
    let config_validator = jsonschema::validator_for(&config_schema_json)
        .expect("Схема config.schema.json должна успешно компилироваться");

    // 1. Валидация config.example.json против схемы
    let example_config_str = include_str!("../config.example.json");
    let example_config_json: serde_json::Value = serde_json::from_str(example_config_str).unwrap();
    assert!(
        config_validator.is_valid(&example_config_json),
        "config.example.json обязан быть валидным по JSON Schema"
    );

    // Negative tests для config.schema.json:
    // a) Неизвестное поле (additionalProperties: false)
    let bad_prop = serde_json::json!({
        "version": 1,
        "active_profile_id": "p1",
        "unknown_extra_prop": 123,
        "profiles": []
    });
    assert!(!config_validator.is_valid(&bad_prop));

    // b) Невалидный порт (порт 0)
    let bad_port = serde_json::json!({
        "version": 1,
        "active_profile_id": "p1",
        "profiles": [{
            "id": "p1",
            "name": "Node",
            "protocol": "vless",
            "server": "192.0.2.53",
            "port": 0,
            "uuid": "u1"
        }]
    });
    assert!(!config_validator.is_valid(&bad_port));

    // c) Reality без public_key (условная валидация if/then)
    let bad_reality = serde_json::json!({
        "version": 1,
        "active_profile_id": "p1",
        "profiles": [{
            "id": "p1",
            "name": "Node",
            "protocol": "vless",
            "server": "192.0.2.53",
            "port": 443,
            "uuid": "u1",
            "tls": {
                "enabled": true,
                "security": "reality",
                "server_name": "reality-test.example"
            }
        }]
    });
    assert!(!config_validator.is_valid(&bad_reality));

    // d) Reality с пустым server_name
    let bad_reality_sni = serde_json::json!({
        "version": 1,
        "active_profile_id": "p1",
        "profiles": [{
            "id": "p1",
            "name": "Node",
            "protocol": "vless",
            "server": "192.0.2.53",
            "port": 443,
            "uuid": "u1",
            "tls": {
                "enabled": true,
                "security": "reality",
                "server_name": "",
                "public_key": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
            }
        }]
    });
    assert!(!config_validator.is_valid(&bad_reality_sni));

    // e) ws/grpc требуют абсолютный path; валидный WebSocket профиль принимается
    let valid_ws = serde_json::json!({
        "version": 1,
        "active_profile_id": "p1",
        "profiles": [{
            "id": "p1",
            "name": "WebSocket Node",
            "protocol": "vless",
            "server": "edge.example",
            "port": 443,
            "uuid": "u1",
            "transport": "ws",
            "path": "/vless",
            "tls": {
                "enabled": true,
                "security": "tls",
                "server_name": "origin.example"
            }
        }]
    });
    assert!(config_validator.is_valid(&valid_ws));

    for invalid_path in [serde_json::Value::Null, serde_json::json!("relative")] {
        let mut invalid_transport = valid_ws.clone();
        let profile = &mut invalid_transport["profiles"][0];
        if invalid_path.is_null() {
            profile.as_object_mut().unwrap().remove("path");
        } else {
            profile["path"] = invalid_path;
        }
        assert!(!config_validator.is_valid(&invalid_transport));
    }

    let mut valid_grpc = valid_ws.clone();
    valid_grpc["profiles"][0]["transport"] = serde_json::json!("grpc");
    valid_grpc["profiles"][0]["path"] = serde_json::json!("service-name");
    assert!(config_validator.is_valid(&valid_grpc));
    valid_grpc["profiles"][0]
        .as_object_mut()
        .unwrap()
        .remove("path");
    assert!(!config_validator.is_valid(&valid_grpc));

    let mut invalid_grpc_custom_path = valid_ws.clone();
    invalid_grpc_custom_path["profiles"][0]["transport"] = serde_json::json!("grpc");
    invalid_grpc_custom_path["profiles"][0]["path"] = serde_json::json!("/svc");
    assert!(!config_validator.is_valid(&invalid_grpc_custom_path));

    // f) TCP (явный или default) не принимает поля host/path.
    for transport in [Some("tcp"), None] {
        let mut invalid_tcp = serde_json::json!({
            "version": 1,
            "active_profile_id": "p1",
            "profiles": [{
                "id": "p1",
                "name": "TCP Node",
                "protocol": "vless",
                "server": "edge.example",
                "port": 443,
                "uuid": "u1",
                "host": "cdn.example"
            }]
        });
        if let Some(value) = transport {
            invalid_tcp["profiles"][0]["transport"] = serde_json::json!(value);
        }
        assert!(!config_validator.is_valid(&invalid_tcp));
    }

    // g) Reality нельзя комбинировать с WebSocket; gRPC остаётся допустимым.
    let mut reality_ws = serde_json::json!({
        "version": 1,
        "active_profile_id": "p1",
        "profiles": [{
            "id": "p1",
            "name": "Reality WS",
            "protocol": "vless",
            "server": "edge.example",
            "port": 443,
            "uuid": "u1",
            "transport": "ws",
            "path": "/vless",
            "tls": {
                "enabled": true,
                "security": "reality",
                "server_name": "origin.example",
                "public_key": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
            }
        }]
    });
    assert!(!config_validator.is_valid(&reality_ws));
    reality_ws["profiles"][0]["transport"] = serde_json::json!("grpc");
    reality_ws["profiles"][0]["path"] = serde_json::json!("svc");
    assert!(config_validator.is_valid(&reality_ws));

    // h) XTLS Vision разрешён только поверх TCP
    let mut invalid_ws_flow = valid_ws;
    invalid_ws_flow["profiles"][0]["flow"] = serde_json::json!("xtls-rprx-vision");
    assert!(!config_validator.is_valid(&invalid_ws_flow));

    // 2. Валидация settings.schema.json
    let settings_schema_str = include_str!("../schema/settings.schema.json");
    let settings_schema_json: serde_json::Value = serde_json::from_str(settings_schema_str)
        .expect("settings.schema.json должен быть валидным JSON");
    let settings_validator = jsonschema::validator_for(&settings_schema_json)
        .expect("Схема settings.schema.json должна успешно компилироваться");

    // Валидация settings.example.json против схемы
    let example_settings_str = include_str!("../settings.example.json");
    let example_settings_json: serde_json::Value =
        serde_json::from_str(example_settings_str).unwrap();
    assert!(
        settings_validator.is_valid(&example_settings_json),
        "settings.example.json обязан быть валидным по JSON Schema"
    );

    // Negative tests для settings.schema.json:
    // a) Невалидный mode
    let bad_mode = serde_json::json!({
        "version": 1,
        "client": {
            "auto_connect_on_launch": false,
            "kill_switch": true,
            "system_notifications": true,
            "dns_servers": [],
            "local_socks_port": 10808,
            "local_http_port": 10809
        },
        "split_tunneling": {
            "enabled": true,
            "mode": "invalid_mode_name",
            "direct_domains": [],
            "direct_ips": [],
            "direct_apps": []
        }
    });
    assert!(!settings_validator.is_valid(&bad_mode));

    // b) Дополнительные неизвестные поля
    let bad_settings_extra = serde_json::json!({
        "version": 1,
        "client": {
            "auto_connect_on_launch": false,
            "kill_switch": true,
            "system_notifications": true,
            "dns_servers": [],
            "local_socks_port": 10808,
            "local_http_port": 10809
        },
        "split_tunneling": {
            "enabled": true,
            "mode": "proxy_all",
            "direct_domains": [],
            "direct_ips": [],
            "direct_apps": []
        },
        "unexpected_root_key": true
    });
    assert!(!settings_validator.is_valid(&bad_settings_extra));

    // c) Неподдерживаемый GeoIP (например geoip:us)
    let bad_settings_geoip = serde_json::json!({
        "version": 1,
        "client": {
            "auto_connect_on_launch": false,
            "kill_switch": true,
            "system_notifications": true,
            "dns_servers": [],
            "local_socks_port": 10808,
            "local_http_port": 10809
        },
        "split_tunneling": {
            "enabled": true,
            "mode": "proxy_all",
            "direct_domains": [],
            "direct_ips": ["geoip:us"],
            "direct_apps": []
        }
    });
    assert!(!settings_validator.is_valid(&bad_settings_geoip));

    // d) CIDR подсеть (CIDR отложен до Milestone 2)
    let bad_settings_cidr = serde_json::json!({
        "version": 1,
        "client": {
            "auto_connect_on_launch": false,
            "kill_switch": true,
            "system_notifications": true,
            "dns_servers": [],
            "local_socks_port": 10808,
            "local_http_port": 10809
        },
        "split_tunneling": {
            "enabled": true,
            "mode": "proxy_all",
            "direct_domains": [],
            "direct_ips": ["192.168.1.0/24"],
            "direct_apps": []
        }
    });
    assert!(!settings_validator.is_valid(&bad_settings_cidr));

    // e) Неподдерживаемый geosite (например geosite:netflix)
    let bad_settings_geosite = serde_json::json!({
        "version": 1,
        "client": {
            "auto_connect_on_launch": false,
            "kill_switch": true,
            "system_notifications": true,
            "dns_servers": [],
            "local_socks_port": 10808,
            "local_http_port": 10809
        },
        "split_tunneling": {
            "enabled": true,
            "mode": "proxy_all",
            "direct_domains": ["geosite:netflix"],
            "direct_ips": [],
            "direct_apps": []
        }
    });
    assert!(!settings_validator.is_valid(&bad_settings_geosite));
}

#[test]
fn test_multi_profile_switching_and_active_profile_resolution() {
    let config_json = r#"{
        "version": 1,
        "active_profile_id": "nl-node",
        "profiles": [
            {
                "id": "de-node",
                "name": "Germany Node",
                "protocol": "vless",
                "server": "192.0.2.53",
                "port": 443,
                "uuid": "uuid-1"
            },
            {
                "id": "nl-node",
                "name": "Test Node B",
                "protocol": "vless",
                "server": "192.0.2.22",
                "port": 8443,
                "uuid": "uuid-2"
            }
        ]
    }"#;

    let mut config: AppConfig =
        serde_json::from_str(config_json).expect("Конфиг с несколькими профилями валиден");
    assert!(config.validate().is_ok());

    // Проверяем начальный активный профиль
    let active = config
        .find_active_profile()
        .expect("Активный профиль найден");
    assert_eq!(active.id, "nl-node");
    assert_eq!(active.server, "192.0.2.22");

    // Переключаем профиль на de-node
    config.active_profile_id = "de-node".to_string();
    assert!(config.validate().is_ok());
    assert_eq!(config.find_active_profile().unwrap().server, "192.0.2.53");

    // Переключаем на несуществующий
    config.active_profile_id = "us-node".to_string();
    assert!(config.validate().is_err());
}

#[tokio::test]
async fn test_route_manager_and_process_supervisor_initialization() {
    use novaray_core::core::ProcessSupervisor;
    use novaray_core::routing::RouteManager;

    let route_mgr = RouteManager::new();
    let apply_res = route_mgr
        .apply_vpn_routes("203.0.113.30", "192.168.1.1")
        .await;
    assert!(apply_res.is_ok());

    let restore_res = route_mgr.restore_default_routes().await;
    assert!(restore_res.is_ok());

    let mut supervisor = ProcessSupervisor::new();
    let stop_res = supervisor.stop().await;
    assert!(stop_res.is_ok());
}
