//! Генератор конфигурационного JSON для ячеек Xray-core
use crate::config::{SecurityType, ServerProfile, TransportType, UserSettings};
use serde_json::{json, Value};

pub struct XrayConfigGenerator;

impl XrayConfigGenerator {
    /// Формирует полный конфигурационный JSON для процесса xray-core
    pub fn generate(profile: &ServerProfile, settings: &UserSettings) -> Value {
        let mut stream_settings = json!({
            "network": "tcp",
            "security": "none"
        });

        if let Some(ref tls) = profile.tls {
            if tls.enabled {
                match tls.security {
                    SecurityType::Reality => {
                        let password = tls
                            .public_key
                            .as_deref()
                            .and_then(crate::config::to_raw_url_safe_reality_public_key)
                            .unwrap_or_else(|| tls.public_key.as_deref().unwrap_or("").to_string());

                        stream_settings = json!({
                            "network": "tcp",
                            "security": "reality",
                            "realitySettings": {
                                "show": false,
                                "serverName": tls.server_name,
                                "fingerprint": tls.fingerprint.as_deref().unwrap_or("chrome"),
                                "password": password,
                                "shortId": tls.short_id.as_deref().unwrap_or(""),
                                "spiderX": "/"
                            }
                        });
                    }
                    SecurityType::Tls => {
                        let mut tls_settings = json!({
                            "allowInsecure": false,
                            "fingerprint": tls.fingerprint.as_deref().unwrap_or("chrome")
                        });
                        if !tls.server_name.trim().is_empty() {
                            tls_settings["serverName"] = json!(tls.server_name.trim());
                        }
                        stream_settings = json!({
                            "network": "tcp",
                            "security": "tls",
                            "tlsSettings": tls_settings
                        });
                    }
                    SecurityType::None => {
                        stream_settings = json!({
                            "network": "tcp",
                            "security": "none"
                        });
                    }
                }
            }
        }

        match profile.transport {
            TransportType::Tcp => {}
            TransportType::Ws => {
                let host = profile.effective_transport_host();
                let path = profile.path.as_deref().map(str::trim).unwrap_or("/");
                stream_settings["network"] = json!("ws");
                stream_settings["wsSettings"] = json!({
                    "path": path,
                    "headers": {
                        "Host": host
                    }
                });
            }
            TransportType::Grpc => {
                let host = profile.effective_transport_host();
                let service_name = profile.path.as_deref().map(str::trim).unwrap_or("");
                stream_settings["network"] = json!("grpc");
                stream_settings["grpcSettings"] = json!({
                    "authority": host,
                    "serviceName": service_name,
                    "multiMode": false
                });
            }
        }

        let user_obj = if let Some(ref flow) = profile.flow {
            json!({
                "id": profile.uuid,
                "encryption": "none",
                "flow": flow.to_string()
            })
        } else {
            json!({
                "id": profile.uuid,
                "encryption": "none"
            })
        };

        json!({
            "log": {
                "loglevel": "warning"
            },
            "inbounds": [
                {
                    "tag": "socks-in",
                    "port": settings.client.local_socks_port,
                    "listen": "127.0.0.1",
                    "protocol": "socks",
                    "settings": {
                        "auth": "noauth",
                        "udp": true
                    },
                    "sniffing": {
                        "enabled": true,
                        "destOverride": ["http", "tls", "quic"]
                    }
                },
                {
                    "tag": "http-in",
                    "port": settings.client.local_http_port,
                    "listen": "127.0.0.1",
                    "protocol": "http"
                }
            ],
            "outbounds": [
                {
                    "tag": "proxy",
                    "protocol": profile.protocol.to_string(),
                    "settings": {
                        "vnext": [
                            {
                                "address": profile.server,
                                "port": profile.port,
                                "users": [user_obj]
                            }
                        ]
                    },
                    "streamSettings": stream_settings
                },
                {
                    "tag": "direct",
                    "protocol": "freedom"
                },
                {
                    "tag": "block",
                    "protocol": "blackhole"
                }
            ]
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        ClientSettings, FlowType, ProtocolType, SplitTunnelMode, SplitTunnelingSettings, TlsConfig,
        TransportType,
    };

    #[test]
    fn test_xray_config_generation_structure() {
        let profile = ServerProfile {
            id: "p1".to_string(),
            name: "Test Reality Profile A".to_string(),
            protocol: ProtocolType::Vless,
            server: "203.0.113.30".to_string(),
            port: 443,
            uuid: "test-uuid-999".to_string(),
            transport: TransportType::Tcp,
            host: None,
            path: None,
            flow: Some(FlowType::XtlsRprxVision),
            tls: Some(TlsConfig {
                enabled: true,
                security: SecurityType::Reality,
                server_name: "gateway.icloud.com".to_string(),
                public_key: Some("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=".to_string()),
                short_id: Some("1234abcd".to_string()),
                fingerprint: Some("chrome".to_string()),
            }),
        };

        let settings = UserSettings {
            schema: None,
            version: 1,
            client: ClientSettings {
                auto_connect_on_launch: false,
                kill_switch: true,
                system_notifications: true,
                dns_servers: vec!["192.0.2.53".to_string()],
                local_socks_port: 10808,
                local_http_port: 10809,
            },
            split_tunneling: SplitTunnelingSettings {
                enabled: true,
                mode: SplitTunnelMode::BypassSelected,
                direct_domains: vec![],
                direct_ips: vec![],
                direct_apps: vec![],
            },
        };

        let config_json = XrayConfigGenerator::generate(&profile, &settings);

        // Проверяем входящие порты
        let inbounds = config_json["inbounds"].as_array().unwrap();
        assert_eq!(inbounds.len(), 2);
        assert_eq!(inbounds[0]["port"], 10808);
        assert_eq!(inbounds[1]["port"], 10809);

        // Проверяем outbound proxy
        let outbounds = config_json["outbounds"].as_array().unwrap();
        let proxy_outbound = outbounds
            .iter()
            .find(|o| o["tag"] == "proxy")
            .expect("Proxy outbound должен быть сформирован");

        assert_eq!(proxy_outbound["protocol"], "vless");
        assert_eq!(proxy_outbound["streamSettings"]["security"], "reality");
        assert_eq!(
            proxy_outbound["streamSettings"]["realitySettings"]["serverName"],
            "gateway.icloud.com"
        );
        assert_eq!(
            proxy_outbound["streamSettings"]["realitySettings"]["password"],
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
        );
        assert_eq!(
            proxy_outbound["streamSettings"]["realitySettings"]["shortId"],
            "1234abcd"
        );
        assert_eq!(
            proxy_outbound["streamSettings"]["realitySettings"]["fingerprint"],
            "chrome"
        );

        let user = &proxy_outbound["settings"]["vnext"][0]["users"][0];
        assert_eq!(user["id"], "test-uuid-999");
        assert_eq!(user["flow"], "xtls-rprx-vision");
    }

    #[test]
    fn test_xray_config_generation_standard_tls() {
        let profile = ServerProfile {
            id: "p-tls".to_string(),
            name: "Standard TLS Node".to_string(),
            protocol: ProtocolType::Vless,
            server: "tls.example.com".to_string(),
            port: 443,
            uuid: "uuid-tls-user".to_string(),
            transport: TransportType::Tcp,
            host: None,
            path: None,
            flow: Some(FlowType::XtlsRprxVision),
            tls: Some(TlsConfig {
                enabled: true,
                security: SecurityType::Tls,
                server_name: "tls.example.com".to_string(),
                public_key: None,
                short_id: None,
                fingerprint: Some("firefox".to_string()),
            }),
        };

        let settings = UserSettings {
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
        };

        let config_json = XrayConfigGenerator::generate(&profile, &settings);
        let proxy_outbound = &config_json["outbounds"][0];

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
    fn test_xray_config_generation_standard_tls_without_sni() {
        let profile = ServerProfile {
            id: "p-tls-ip".to_string(),
            name: "TLS Node on IP".to_string(),
            protocol: ProtocolType::Vless,
            server: "203.0.113.30".to_string(),
            port: 443,
            uuid: "uuid-tls-ip".to_string(),
            transport: TransportType::Tcp,
            host: None,
            path: None,
            flow: None,
            tls: Some(TlsConfig {
                enabled: true,
                security: SecurityType::Tls,
                server_name: "".to_string(),
                public_key: None,
                short_id: None,
                fingerprint: Some("chrome".to_string()),
            }),
        };

        let settings = UserSettings {
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
        };

        let config_json = XrayConfigGenerator::generate(&profile, &settings);
        let proxy_outbound = &config_json["outbounds"][0];

        assert_eq!(proxy_outbound["streamSettings"]["security"], "tls");
        assert!(proxy_outbound["streamSettings"]["tlsSettings"]
            .get("serverName")
            .is_none());
        assert_eq!(
            proxy_outbound["streamSettings"]["tlsSettings"]["allowInsecure"],
            false
        );
    }

    #[test]
    fn test_xray_config_generation_reality_defaults_for_optional_fields() {
        let profile = ServerProfile {
            id: "p-reality-min".to_string(),
            name: "Reality Minimal".to_string(),
            protocol: ProtocolType::Vless,
            server: "192.0.2.53".to_string(),
            port: 443,
            uuid: "uuid-min".to_string(),
            transport: TransportType::Tcp,
            host: None,
            path: None,
            flow: None,
            tls: Some(TlsConfig {
                enabled: true,
                security: SecurityType::Reality,
                server_name: "dl.google.com".to_string(),
                public_key: Some("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=".to_string()),
                short_id: None,
                fingerprint: None,
            }),
        };

        let settings = UserSettings {
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
        };

        let config_json = XrayConfigGenerator::generate(&profile, &settings);
        let proxy_outbound = &config_json["outbounds"][0];

        assert_eq!(proxy_outbound["streamSettings"]["security"], "reality");
        assert_eq!(
            proxy_outbound["streamSettings"]["realitySettings"]["serverName"],
            "dl.google.com"
        );
        assert_eq!(
            proxy_outbound["streamSettings"]["realitySettings"]["password"],
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
        );
        assert_eq!(
            proxy_outbound["streamSettings"]["realitySettings"]["shortId"],
            ""
        );
        assert_eq!(
            proxy_outbound["streamSettings"]["realitySettings"]["fingerprint"],
            "chrome"
        );
    }

    #[test]
    fn test_xray_config_generation_plain_tcp_no_tls_no_flow() {
        let profile = ServerProfile {
            id: "p2".to_string(),
            name: "Plain Node".to_string(),
            protocol: ProtocolType::Vless,
            server: "198.51.100.78".to_string(),
            port: 80,
            uuid: "uuid-plain".to_string(),
            transport: TransportType::Tcp,
            host: None,
            path: None,
            flow: None,
            tls: None,
        };

        let settings = UserSettings {
            schema: None,
            version: 1,
            client: ClientSettings {
                auto_connect_on_launch: false,
                kill_switch: false,
                system_notifications: false,
                dns_servers: vec![],
                local_socks_port: 1080,
                local_http_port: 8080,
            },
            split_tunneling: SplitTunnelingSettings {
                enabled: false,
                mode: SplitTunnelMode::ProxyAll,
                direct_domains: vec![],
                direct_ips: vec![],
                direct_apps: vec![],
            },
        };

        let config_json = XrayConfigGenerator::generate(&profile, &settings);
        let proxy_outbound = &config_json["outbounds"][0];

        assert_eq!(proxy_outbound["streamSettings"]["security"], "none");
        let user = &proxy_outbound["settings"]["vnext"][0]["users"][0];
        assert_eq!(user["id"], "uuid-plain");
        assert!(user.get("flow").is_none());
    }

    #[test]
    fn test_xray_config_generation_normalizes_padded_reality_public_key_to_raw_url_safe() {
        // Profile with standard padded Base64 key (44 chars ending in =)
        let profile = ServerProfile {
            id: "p-padded".to_string(),
            name: "Padded Key Node".to_string(),
            protocol: ProtocolType::Vless,
            server: "203.0.113.30".to_string(),
            port: 443,
            uuid: "uuid-padded".to_string(),
            transport: TransportType::Tcp,
            host: None,
            path: None,
            flow: Some(FlowType::XtlsRprxVision),
            tls: Some(TlsConfig {
                enabled: true,
                security: SecurityType::Reality,
                server_name: "dl.google.com".to_string(),
                public_key: Some("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=".to_string()),
                short_id: Some("1234abcd".to_string()),
                fingerprint: Some("chrome".to_string()),
            }),
        };

        let settings = UserSettings {
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
        };

        let config_json = XrayConfigGenerator::generate(&profile, &settings);
        let password = config_json["outbounds"][0]["streamSettings"]["realitySettings"]["password"]
            .as_str()
            .unwrap();

        // Must be exactly 43 characters, raw URL-safe Base64, without padding '='
        assert_eq!(password, "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8");
        assert_eq!(password.len(), 43);
        assert!(!password.contains('='));
        assert!(!password.contains('+'));
        assert!(!password.contains('/'));
    }

    #[test]
    fn test_xray_config_generation_websocket_settings() {
        let mut profile = transport_profile(TransportType::Ws, "cdn.example", "/vless");
        profile.host = None;
        let config_json = XrayConfigGenerator::generate(&profile, &transport_test_settings());
        let stream = &config_json["outbounds"][0]["streamSettings"];

        assert_eq!(stream["network"], "ws");
        assert_eq!(stream["wsSettings"]["path"], "/vless");
        assert_eq!(stream["wsSettings"]["headers"]["Host"], "origin.example");
        assert!(stream.get("grpcSettings").is_none());
    }

    #[test]
    fn test_xray_config_generation_grpc_settings() {
        let profile = transport_profile(TransportType::Grpc, "grpc.example", "svc");
        let config_json = XrayConfigGenerator::generate(&profile, &transport_test_settings());
        let stream = &config_json["outbounds"][0]["streamSettings"];

        assert_eq!(stream["network"], "grpc");
        assert_eq!(stream["grpcSettings"]["authority"], "grpc.example");
        assert_eq!(stream["grpcSettings"]["serviceName"], "svc");
        assert_eq!(stream["grpcSettings"]["multiMode"], false);
        assert!(stream.get("wsSettings").is_none());
    }

    #[test]
    fn test_transport_generation_trims_path_and_falls_back_to_server_host() {
        let mut ws = transport_profile(TransportType::Ws, "cdn.example", " /vless ");
        ws.host = None;
        ws.tls = None;
        ws.server = "203.0.113.10".to_string();
        let ws_config = XrayConfigGenerator::generate(&ws, &transport_test_settings());
        let ws_stream = &ws_config["outbounds"][0]["streamSettings"];
        assert_eq!(ws_stream["wsSettings"]["path"], "/vless");
        assert_eq!(ws_stream["wsSettings"]["headers"]["Host"], "203.0.113.10");

        let mut grpc = transport_profile(TransportType::Grpc, "cdn.example", " svc ");
        grpc.host = None;
        grpc.tls = None;
        grpc.server = "203.0.113.10".to_string();
        let grpc_config = XrayConfigGenerator::generate(&grpc, &transport_test_settings());
        let grpc_stream = &grpc_config["outbounds"][0]["streamSettings"];
        assert_eq!(grpc_stream["grpcSettings"]["serviceName"], "svc");
        assert_eq!(grpc_stream["grpcSettings"]["authority"], "203.0.113.10");
    }

    fn transport_profile(transport: TransportType, host: &str, path: &str) -> ServerProfile {
        ServerProfile {
            id: format!("p-{transport}"),
            name: format!("{transport} node"),
            protocol: ProtocolType::Vless,
            server: "edge.example".to_string(),
            port: 443,
            uuid: "00000000-0000-4000-8000-000000000001".to_string(),
            transport,
            host: Some(host.to_string()),
            path: Some(path.to_string()),
            flow: None,
            tls: Some(TlsConfig {
                enabled: true,
                security: SecurityType::Tls,
                server_name: "origin.example".to_string(),
                public_key: None,
                short_id: None,
                fingerprint: Some("chrome".to_string()),
            }),
        }
    }

    fn transport_test_settings() -> UserSettings {
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
}
