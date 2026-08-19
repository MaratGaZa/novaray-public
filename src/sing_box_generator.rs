//! Генератор конфигурационного JSON для sing-box.
//!
//! Покрывает текущий NovaRay M2 local-proxy contract: VLESS outbound, локальные
//! SOCKS/HTTP inbounds, TCP/RAW, WebSocket и gRPC transport metadata, TLS/Reality.
//! TUN/DNS/routing policy остаются вне этой задачи и не выдаются за реализованные.
use crate::config::{SecurityType, ServerProfile, TransportType, UserSettings};
use serde_json::{json, Map, Value};

pub struct SingBoxConfigGenerator;

impl SingBoxConfigGenerator {
    /// Формирует полный конфигурационный JSON для процесса sing-box.
    pub fn generate(profile: &ServerProfile, settings: &UserSettings) -> Value {
        let mut proxy_outbound = Map::new();
        proxy_outbound.insert("type".to_string(), json!(profile.protocol.to_string()));
        proxy_outbound.insert("tag".to_string(), json!("proxy"));
        proxy_outbound.insert("server".to_string(), json!(profile.server.trim()));
        proxy_outbound.insert("server_port".to_string(), json!(profile.port));
        proxy_outbound.insert("uuid".to_string(), json!(profile.uuid.trim()));
        proxy_outbound.insert("network".to_string(), json!("tcp"));

        if let Some(ref flow) = profile.flow {
            proxy_outbound.insert("flow".to_string(), json!(flow.to_string()));
        }

        if let Some(tls) = build_tls(profile) {
            proxy_outbound.insert("tls".to_string(), tls);
        }

        if let Some(transport) = build_transport(profile) {
            proxy_outbound.insert("transport".to_string(), transport);
        }

        json!({
            "log": {
                "level": "warn"
            },
            "inbounds": [
                {
                    "type": "socks",
                    "tag": "socks-in",
                    "listen": "127.0.0.1",
                    "listen_port": settings.client.local_socks_port
                },
                {
                    "type": "http",
                    "tag": "http-in",
                    "listen": "127.0.0.1",
                    "listen_port": settings.client.local_http_port
                }
            ],
            "outbounds": [
                Value::Object(proxy_outbound),
                {
                    "type": "direct",
                    "tag": "direct"
                },
                {
                    "type": "block",
                    "tag": "block"
                }
            ],
            "route": {
                "final": "proxy"
            }
        })
    }
}

fn build_tls(profile: &ServerProfile) -> Option<Value> {
    let tls = profile.tls.as_ref()?;
    if !tls.enabled {
        return None;
    }

    match tls.security {
        SecurityType::None => None,
        SecurityType::Tls => {
            let mut tls_json = json!({
                "enabled": true,
                "insecure": false
            });
            if !tls.server_name.trim().is_empty() {
                tls_json["server_name"] = json!(tls.server_name.trim());
            }
            if let Some(fingerprint) = tls
                .fingerprint
                .as_deref()
                .map(str::trim)
                .filter(|v| !v.is_empty())
            {
                tls_json["utls"] = json!({
                    "enabled": true,
                    "fingerprint": fingerprint
                });
            }
            Some(tls_json)
        }
        SecurityType::Reality => {
            let public_key = tls
                .public_key
                .as_deref()
                .and_then(crate::config::to_raw_url_safe_reality_public_key)
                .unwrap_or_else(|| tls.public_key.as_deref().unwrap_or("").trim().to_string());

            Some(json!({
                "enabled": true,
                "server_name": tls.server_name.trim(),
                "insecure": false,
                "utls": {
                    "enabled": true,
                    "fingerprint": tls.fingerprint.as_deref().map(str::trim).filter(|v| !v.is_empty()).unwrap_or("chrome")
                },
                "reality": {
                    "enabled": true,
                    "public_key": public_key,
                    "short_id": tls.short_id.as_deref().map(str::trim).unwrap_or("")
                }
            }))
        }
    }
}

fn build_transport(profile: &ServerProfile) -> Option<Value> {
    match profile.transport {
        TransportType::Tcp => None,
        TransportType::Ws => {
            let path = profile.path.as_deref().map(str::trim).unwrap_or("/");
            Some(json!({
                "type": "ws",
                "path": path,
                "headers": {
                    "Host": profile.effective_transport_host()
                }
            }))
        }
        TransportType::Grpc => {
            let service_name = profile.path.as_deref().map(str::trim).unwrap_or("");
            Some(json!({
                "type": "grpc",
                "service_name": service_name
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        ClientSettings, FlowType, ProtocolType, SplitTunnelMode, SplitTunnelingSettings, TlsConfig,
    };

    #[test]
    fn generates_reality_tcp_local_proxy_config() {
        let profile = reality_profile(TransportType::Tcp, None, None);
        let config_json = SingBoxConfigGenerator::generate(&profile, &settings());

        assert_eq!(config_json["log"]["level"], "warn");
        assert_eq!(config_json["inbounds"][0]["type"], "socks");
        assert_eq!(config_json["inbounds"][0]["listen_port"], 10808);
        assert_eq!(config_json["inbounds"][1]["type"], "http");
        assert_eq!(config_json["inbounds"][1]["listen_port"], 10809);

        let proxy = &config_json["outbounds"][0];
        assert_eq!(proxy["type"], "vless");
        assert_eq!(proxy["tag"], "proxy");
        assert_eq!(proxy["server"], "edge.example");
        assert_eq!(proxy["server_port"], 443);
        assert_eq!(proxy["uuid"], "00000000-0000-4000-8000-000000000001");
        assert_eq!(proxy["network"], "tcp");
        assert_eq!(proxy["flow"], "xtls-rprx-vision");
        assert_eq!(proxy["tls"]["enabled"], true);
        assert_eq!(proxy["tls"]["server_name"], "gateway.example");
        assert_eq!(proxy["tls"]["insecure"], false);
        assert_eq!(proxy["tls"]["utls"]["fingerprint"], "chrome");
        assert_eq!(proxy["tls"]["reality"]["enabled"], true);
        assert_eq!(
            proxy["tls"]["reality"]["public_key"],
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
        );
        assert_eq!(proxy["tls"]["reality"]["short_id"], "1234abcd");
        assert!(proxy.get("transport").is_none());
    }

    #[test]
    fn generates_standard_tls_websocket_transport() {
        let profile = tls_profile(TransportType::Ws, Some("cdn.example"), Some(" /vless "));
        let config_json = SingBoxConfigGenerator::generate(&profile, &settings());
        let proxy = &config_json["outbounds"][0];

        assert_eq!(proxy["tls"]["server_name"], "origin.example");
        assert_eq!(proxy["tls"]["utls"]["fingerprint"], "firefox");
        assert_eq!(proxy["transport"]["type"], "ws");
        assert_eq!(proxy["transport"]["path"], "/vless");
        assert_eq!(proxy["transport"]["headers"]["Host"], "cdn.example");
    }

    #[test]
    fn generates_grpc_transport_without_xray_authority_field() {
        let profile = tls_profile(TransportType::Grpc, Some("grpc.example"), Some(" svc "));
        let config_json = SingBoxConfigGenerator::generate(&profile, &settings());
        let proxy = &config_json["outbounds"][0];

        assert_eq!(proxy["transport"]["type"], "grpc");
        assert_eq!(proxy["transport"]["service_name"], "svc");
        assert!(proxy["transport"].get("authority").is_none());
    }

    fn reality_profile(
        transport: TransportType,
        host: Option<&str>,
        path: Option<&str>,
    ) -> ServerProfile {
        ServerProfile {
            id: "reality".to_string(),
            name: "Reality".to_string(),
            protocol: ProtocolType::Vless,
            server: "edge.example".to_string(),
            port: 443,
            uuid: "00000000-0000-4000-8000-000000000001".to_string(),
            transport,
            host: host.map(str::to_string),
            path: path.map(str::to_string),
            flow: Some(FlowType::XtlsRprxVision),
            tls: Some(TlsConfig {
                enabled: true,
                security: SecurityType::Reality,
                server_name: "gateway.example".to_string(),
                public_key: Some("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=".to_string()),
                short_id: Some("1234abcd".to_string()),
                fingerprint: Some("chrome".to_string()),
            }),
        }
    }

    fn tls_profile(
        transport: TransportType,
        host: Option<&str>,
        path: Option<&str>,
    ) -> ServerProfile {
        ServerProfile {
            id: "tls".to_string(),
            name: "TLS".to_string(),
            protocol: ProtocolType::Vless,
            server: "edge.example".to_string(),
            port: 443,
            uuid: "00000000-0000-4000-8000-000000000001".to_string(),
            transport,
            host: host.map(str::to_string),
            path: path.map(str::to_string),
            flow: None,
            tls: Some(TlsConfig {
                enabled: true,
                security: SecurityType::Tls,
                server_name: "origin.example".to_string(),
                public_key: None,
                short_id: None,
                fingerprint: Some("firefox".to_string()),
            }),
        }
    }

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
}
