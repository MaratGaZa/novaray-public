//! Парсер стандартных ссылок VLESS Reality URI
use crate::config::{
    FlowType, ProtocolType, SecurityType, ServerProfile, TlsConfig, TransportType,
};
use anyhow::{anyhow, Context, Result};
use percent_encoding::percent_decode_str;
use url::Url;

pub struct VlessParser;

const CRITICAL_QUERY_KEYS: [&str; 14] = [
    "flow",
    "security",
    "type",
    "headerType",
    "sni",
    "pbk",
    "sid",
    "fp",
    "encryption",
    "host",
    "path",
    "serviceName",
    "authority",
    "mode",
];

fn mis_cased_critical_query_key(key: &str) -> Option<&'static str> {
    CRITICAL_QUERY_KEYS
        .iter()
        .copied()
        .find(|canonical| key != *canonical && key.eq_ignore_ascii_case(canonical))
}

fn validate_tcp_header_type(value: &str) -> Result<()> {
    match value.trim().to_lowercase().as_str() {
        "none" => Ok(()),
        other => Err(anyhow!(
            "Неподдерживаемый параметр 'headerType': '{}'. Поддерживается только 'none'",
            other
        )),
    }
}

impl VlessParser {
    /// Парсит ссылку формата `vless://uuid@host:port?query#name`
    pub fn parse_uri(uri_str: &str) -> Result<ServerProfile> {
        let url = Url::parse(uri_str).context("Некорректный формат URI")?;

        if url.scheme() != "vless" {
            return Err(anyhow!(
                "Ожидалась схема 'vless://', получено '{}'",
                url.scheme()
            ));
        }

        let uuid = url.username().to_string();
        if uuid.trim().is_empty() {
            return Err(anyhow!("UUID не может быть пустым"));
        }

        let host = url
            .host_str()
            .ok_or_else(|| anyhow!("Хост сервера отсутствует в URI"))?
            .to_string();

        let port = url
            .port()
            .ok_or_else(|| anyhow!("Порт сервера отсутствует в URI"))?;

        let name = match url.fragment() {
            Some(frag) if !frag.trim().is_empty() => {
                percent_decode_str(frag).decode_utf8_lossy().to_string()
            }
            _ => format!("{}:{}", host, port),
        };

        let is_ip_host = host.parse::<std::net::IpAddr>().is_ok()
            || (host.starts_with('[')
                && host.ends_with(']')
                && host[1..host.len() - 1].parse::<std::net::IpAddr>().is_ok());

        // Query параметры
        let mut flow: Option<FlowType> = None;
        let mut security = SecurityType::None;
        // Default SNI only if host is a domain name (not an IP literal)
        let mut sni = if is_ip_host {
            String::new()
        } else {
            host.clone()
        };
        let mut pbk = None;
        let mut sid = None;
        let mut fp = None;
        let mut transport = TransportType::Tcp;
        let mut transport_host = None;
        let mut transport_path = None;
        let mut grpc_specific_parameter = None;
        let mut grpc_mode = None;

        for (k, v) in url.query_pairs() {
            match k.as_ref() {
                "flow" => {
                    let parsed_flow: FlowType = v
                        .parse()
                        .map_err(|e: String| anyhow!("Ошибка параметра 'flow': {}", e))?;
                    flow = Some(parsed_flow);
                }
                "security" => {
                    let parsed_security: SecurityType = v
                        .parse()
                        .map_err(|e: String| anyhow!("Ошибка параметра 'security': {}", e))?;
                    security = parsed_security;
                }
                "type" => {
                    transport = v
                        .parse()
                        .map_err(|e: String| anyhow!("Ошибка параметра 'type': {}", e))?;
                }
                "headerType" => validate_tcp_header_type(&v)?,
                "sni" => sni = v.to_string(),
                "pbk" => pbk = Some(v.to_string()),
                "sid" => sid = Some(v.to_string()),
                "fp" => fp = Some(v.to_string()),
                "host" => {
                    set_transport_value(&mut transport_host, v.as_ref(), "host", "host")?;
                }
                "path" => {
                    set_transport_value(&mut transport_path, v.as_ref(), "path", "path")?;
                }
                "serviceName" => {
                    if set_transport_value(&mut transport_path, v.as_ref(), "path", "serviceName")?
                    {
                        grpc_specific_parameter = Some("serviceName");
                    }
                }
                "authority" => {
                    if set_transport_value(&mut transport_host, v.as_ref(), "host", "authority")? {
                        grpc_specific_parameter = Some("authority");
                    }
                }
                "mode" => {
                    let normalized = v.trim();
                    if !normalized.is_empty() {
                        grpc_mode = Some(normalized.to_lowercase());
                    }
                }
                _ => {
                    if let Some(canonical) = mis_cased_critical_query_key(&k) {
                        return Err(anyhow!(
                            "Некорректный регистр query-параметра '{}': ожидается '{}'",
                            k,
                            canonical
                        ));
                    }
                }
            }
        }

        if transport == TransportType::Grpc {
            if let Some(mode) = grpc_mode.as_deref() {
                if mode != "gun" {
                    return Err(anyhow!(
                        "Неподдерживаемый gRPC mode '{}'. Поддерживается только 'gun'",
                        mode
                    ));
                }
            }
        } else if let Some(parameter) = grpc_specific_parameter {
            return Err(anyhow!(
                "Параметр '{}' применим только к type=grpc",
                parameter
            ));
        }

        let tls = if security != SecurityType::None {
            Some(TlsConfig {
                enabled: true,
                security,
                server_name: sni.clone(),
                public_key: pbk,
                short_id: sid,
                fingerprint: fp,
            })
        } else {
            None
        };

        if transport != TransportType::Tcp
            && transport_host
                .as_deref()
                .map(str::trim)
                .unwrap_or_default()
                .is_empty()
            && !sni.trim().is_empty()
        {
            transport_host = Some(sni.clone());
        }

        let safe_host_id = host.replace(['.', ':', '[', ']'], "-");
        let profile_id = format!("vless-{}-{}", safe_host_id, port);

        let profile = ServerProfile {
            id: profile_id,
            name,
            protocol: ProtocolType::Vless,
            server: host,
            port,
            uuid,
            transport,
            host: transport_host,
            path: transport_path,
            flow,
            tls,
        };

        // Валидируем сформированный профиль
        profile
            .validate()
            .map_err(|e| anyhow!("Ошибка валидации профиля: {}", e))?;

        Ok(profile)
    }
}

fn set_transport_value(
    target: &mut Option<String>,
    value: &str,
    canonical_field: &str,
    query_key: &str,
) -> Result<bool> {
    let normalized = value.trim();
    if normalized.is_empty() {
        return Ok(false);
    }
    if let Some(existing) = target.as_deref() {
        if existing != normalized {
            return Err(anyhow!(
                "Конфликтующие значения transport-параметров для '{}': '{}' и '{}={}'",
                canonical_field,
                existing,
                query_key,
                normalized
            ));
        }
    } else {
        *target = Some(normalized.to_string());
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_vless_reality_uri() {
        let uri = "vless://00000000-0000-4000-8000-000000000001@192.0.2.10:443?security=reality&encryption=none&pbk=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8&headerType=none&fp=chrome&type=tcp&flow=xtls-rprx-vision&sni=gateway.icloud.com&sid=0123456789abcdef#Test%20Reality%20Profile%20A";

        let profile = VlessParser::parse_uri(uri).expect("Должен успешно распарсить ссылку");

        assert_eq!(profile.protocol, ProtocolType::Vless);
        assert_eq!(profile.server, "192.0.2.10");
        assert_eq!(profile.port, 443);
        assert_eq!(profile.uuid, "00000000-0000-4000-8000-000000000001");
        assert_eq!(profile.flow, Some(FlowType::XtlsRprxVision));
        assert_eq!(profile.name, "Test Reality Profile A");

        let tls = profile.tls.expect("TLS конфиг должен присутствовать");
        assert_eq!(tls.security, SecurityType::Reality);
        assert_eq!(tls.server_name, "gateway.icloud.com");
        assert_eq!(tls.short_id.as_deref(), Some("0123456789abcdef"));
        assert_eq!(tls.fingerprint.as_deref(), Some("chrome"));
        assert_eq!(
            tls.public_key.as_deref(),
            Some("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8")
        );
    }

    #[test]
    fn test_parse_without_fragment_uses_host_port_fallback() {
        let uri = "vless://00000000-0000-4000-8000-000000000001@203.0.113.30:8443?security=reality&sni=reality-test.example&pbk=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
        let profile =
            VlessParser::parse_uri(uri).expect("Парсинг без имени в фрагменте и без sid/fp");

        assert_eq!(profile.name, "203.0.113.30:8443");
        assert_eq!(profile.server, "203.0.113.30");
        assert_eq!(profile.port, 8443);
        let tls = profile.tls.expect("TLS должен быть включен");
        assert_eq!(
            tls.public_key.as_deref(),
            Some("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8")
        );
        assert_eq!(tls.short_id, None);
        assert_eq!(tls.fingerprint, None);
    }

    #[test]
    fn test_parse_tls_standard_security() {
        let uri = "vless://00000000-0000-4000-8000-000000000001@tls.example.com:443?security=tls&sni=tls.example.com#TLS%20Node";
        let profile = VlessParser::parse_uri(uri).expect("Парсинг стандартного TLS");

        let tls = profile.tls.expect("TLS должен быть включен");
        assert_eq!(tls.security, SecurityType::Tls);
        assert_eq!(tls.server_name, "tls.example.com");
        assert!(tls.public_key.is_none());
    }

    #[test]
    fn test_parse_ipv6_with_standard_tls_without_sni() {
        let uri = "vless://00000000-0000-4000-8000-000000000001@[2001:db8::1]:443?security=tls";
        let profile = VlessParser::parse_uri(uri)
            .expect("IPv6 сервер со стандартным TLS должен импортироваться");

        let tls = profile.tls.expect("TLS должен быть включен");
        assert_eq!(tls.security, SecurityType::Tls);
        assert_eq!(tls.server_name, "");
        assert_eq!(profile.server, "[2001:db8::1]");
        assert_eq!(profile.port, 443);
    }

    #[test]
    fn test_parse_ipv6_with_standard_tls_and_explicit_sni() {
        let uri = "vless://00000000-0000-4000-8000-000000000001@[2001:db8::1]:443?security=tls&sni=example.com";
        let profile =
            VlessParser::parse_uri(uri).expect("IPv6 сервер с явным SNI должен импортироваться");

        let tls = profile.tls.expect("TLS должен быть включен");
        assert_eq!(tls.security, SecurityType::Tls);
        assert_eq!(tls.server_name, "example.com");
    }

    #[test]
    fn test_parse_reality_without_sni_on_ip_host_fails() {
        let uri = "vless://00000000-0000-4000-8000-000000000001@203.0.113.30:443?security=reality&pbk=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
        let res = VlessParser::parse_uri(uri);
        assert!(
            res.is_err(),
            "Reality на IP без явного SNI должен отклоняться"
        );
        assert!(res
            .unwrap_err()
            .to_string()
            .contains("для Reality обязателен непустой Server Name (SNI)"));
    }

    #[test]
    fn test_parse_unknown_security_fails() {
        let uri = "vless://00000000-0000-4000-8000-000000000001@203.0.113.30:443?security=bogus";
        let res = VlessParser::parse_uri(uri);
        assert!(res.is_err());
        assert!(res
            .unwrap_err()
            .to_string()
            .contains("Неподдерживаемый тип безопасности"));
    }

    #[test]
    fn test_parse_unknown_flow_fails() {
        let uri = "vless://00000000-0000-4000-8000-000000000001@203.0.113.30:443?flow=bogus";
        let res = VlessParser::parse_uri(uri);
        assert!(res.is_err());
        assert!(res
            .unwrap_err()
            .to_string()
            .contains("Неподдерживаемый тип flow"));
    }

    #[test]
    fn test_parse_default_tcp_and_explicit_tcp_raw_are_equivalent() {
        let without_type = "vless://00000000-0000-4000-8000-000000000001@tls.example.com:443?security=tls&sni=tls.example.com#TLS%20Node";
        let explicit_tcp = "vless://00000000-0000-4000-8000-000000000001@tls.example.com:443?security=tls&sni=tls.example.com&type=tcp#TLS%20Node";
        let explicit_raw = "vless://00000000-0000-4000-8000-000000000001@tls.example.com:443?security=tls&sni=tls.example.com&type=raw#TLS%20Node";

        let default_profile = VlessParser::parse_uri(without_type).expect("TCP по умолчанию");
        let explicit_profile = VlessParser::parse_uri(explicit_tcp).expect("Явный TCP");
        let raw_profile = VlessParser::parse_uri(explicit_raw).expect("RAW alias TCP");

        assert_eq!(default_profile, explicit_profile);
        assert_eq!(default_profile, raw_profile);
    }

    #[test]
    fn test_parse_websocket_transport_and_inherit_host_from_sni() {
        let uri = "vless://00000000-0000-4000-8000-000000000001@edge.example:443?security=tls&sni=origin.example&type=ws&path=%2Fvless";
        let profile =
            VlessParser::parse_uri(uri).expect("WebSocket transport должен поддерживаться");

        assert_eq!(profile.transport, TransportType::Ws);
        assert_eq!(profile.host.as_deref(), Some("origin.example"));
        assert_eq!(profile.path.as_deref(), Some("/vless"));
    }

    #[test]
    fn test_parse_grpc_transport_with_explicit_authority_and_path() {
        let uri = "vless://00000000-0000-4000-8000-000000000001@edge.example:443?security=tls&sni=origin.example&type=grpc&authority=grpc.example&serviceName=svc&mode=gun";
        let profile = VlessParser::parse_uri(uri).expect("gRPC transport должен поддерживаться");

        assert_eq!(profile.transport, TransportType::Grpc);
        assert_eq!(profile.host.as_deref(), Some("grpc.example"));
        assert_eq!(profile.path.as_deref(), Some("svc"));
    }

    #[test]
    fn test_parse_empty_transport_values_are_absent_and_trimmed() {
        let tcp = "vless://uuid@edge.example:443?type=tcp&host=%20%20&path=&mode=auto";
        let tcp_profile = VlessParser::parse_uri(tcp)
            .expect("Пустые transport-параметры и чужой TCP mode должны игнорироваться");
        assert_eq!(tcp_profile.host, None);
        assert_eq!(tcp_profile.path, None);

        let grpc = "vless://uuid@edge.example:443?type=grpc&host=cdn.example&authority=%20%20&serviceName=%20svc%20&mode=gun";
        let grpc_profile =
            VlessParser::parse_uri(grpc).expect("Пустой authority не должен конфликтовать с host");
        assert_eq!(grpc_profile.host.as_deref(), Some("cdn.example"));
        assert_eq!(grpc_profile.path.as_deref(), Some("svc"));
    }

    #[test]
    fn test_parse_ws_and_grpc_without_tls_use_server_host_fallback() {
        for (transport, parameter) in [("ws", "path=%2Fvless"), ("grpc", "serviceName=svc")] {
            let uri = format!("vless://uuid@203.0.113.10:443?type={transport}&{parameter}");
            let profile = VlessParser::parse_uri(&uri)
                .expect("WS/gRPC без TLS и явного host должны использовать server fallback");
            assert_eq!(profile.host, None);
            assert_eq!(profile.effective_transport_host(), "203.0.113.10");
        }
    }

    #[test]
    fn test_parse_reality_transport_compatibility_fails_closed() {
        let base = "vless://uuid@edge.example:443?security=reality&sni=origin.example&pbk=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
        let ws = format!("{base}&type=ws&path=%2Fvless");
        let error = VlessParser::parse_uri(&ws)
            .expect_err("Reality + WebSocket должен отклоняться до генерации")
            .to_string();
        assert!(error.contains("Reality не поддерживается с WebSocket"));

        let grpc = format!("{base}&type=grpc&serviceName=svc&mode=gun");
        VlessParser::parse_uri(&grpc).expect("Reality + gRPC поддерживается Xray");
    }

    #[test]
    fn test_parse_http_transports_require_absolute_path() {
        for (transport, path) in [("ws", ""), ("ws", "relative"), ("grpc", "")] {
            let uri = format!(
                "vless://00000000-0000-4000-8000-000000000001@edge.example:443?security=tls&sni=origin.example&type={transport}&path={path}"
            );
            let error = VlessParser::parse_uri(&uri)
                .expect_err("ws/grpc без абсолютного path должен отклоняться")
                .to_string();
            assert!(error.contains("path, начинающийся с '/'") || error.contains("serviceName"));
        }
    }

    #[test]
    fn test_parse_grpc_unsupported_mode_and_misplaced_parameters_fail_closed() {
        for uri in [
            "vless://uuid@edge.example:443?security=tls&type=grpc&serviceName=svc&mode=multi",
            "vless://uuid@edge.example:443?security=tls&type=ws&path=%2Fvless&serviceName=svc",
            "vless://uuid@edge.example:443?security=tls&type=tcp&authority=grpc.example",
        ] {
            assert!(VlessParser::parse_uri(uri).is_err());
        }
    }

    #[test]
    fn test_parse_grpc_custom_path_service_name_fails_closed() {
        for parameter in [
            "serviceName=%2Fsvc",
            "path=%2Fsvc",
            "serviceName=svc%2Fnested",
        ] {
            let uri = format!("vless://uuid@edge.example:443?security=tls&type=grpc&{parameter}");
            let error = VlessParser::parse_uri(&uri)
                .expect_err("gRPC custom-path syntax вне текущей capability")
                .to_string();
            assert!(error.contains("serviceName без пробелов и '/'"));
        }
    }

    #[test]
    fn test_parse_xtls_vision_with_non_tcp_transport_fails_closed() {
        let uri = "vless://00000000-0000-4000-8000-000000000001@edge.example:443?security=tls&sni=origin.example&type=ws&path=%2Fvless&flow=xtls-rprx-vision";
        let error = VlessParser::parse_uri(uri)
            .expect_err("XTLS Vision поверх WebSocket должен отклоняться")
            .to_string();
        assert!(error.contains("XTLS Vision поддерживается только с TCP"));
    }

    #[test]
    fn test_parse_unsupported_transport_fails_closed() {
        for transport in [
            "httpupgrade",
            "xhttp",
            "h2",
            "quic",
            "kcp",
            "unknown-transport",
        ] {
            let uri = format!(
                "vless://00000000-0000-4000-8000-000000000001@server.example:443?security=tls&type={transport}"
            );
            let error = VlessParser::parse_uri(&uri)
                .expect_err("Неподдерживаемый transport обязан отклоняться")
                .to_string();

            assert!(error.contains("Ошибка параметра 'type'"));
            assert!(error.contains("Неподдерживаемый транспорт VLESS"));
            assert!(error.contains(transport));
        }
    }

    #[test]
    fn test_parse_tcp_header_type_none_only() {
        let accepted = "vless://00000000-0000-4000-8000-000000000001@server.example:443?security=tls&type=raw&headerType=none";
        VlessParser::parse_uri(accepted).expect("headerType=none должен поддерживаться");

        for header_type in ["http", "unknown-header"] {
            let uri = format!(
                "vless://00000000-0000-4000-8000-000000000001@server.example:443?security=tls&type=tcp&headerType={header_type}&host=cdn.example.com&path=%2F"
            );
            let error = VlessParser::parse_uri(&uri)
                .expect_err("Неподдерживаемый TCP headerType обязан отклоняться")
                .to_string();
            assert!(error.contains("Неподдерживаемый параметр 'headerType'"));
            assert!(error.contains(header_type));
        }
    }

    #[test]
    fn test_parse_mis_cased_critical_query_keys_fail_closed() {
        for (key, value, canonical) in [
            ("Type", "ws", "type"),
            ("Security", "reality", "security"),
            ("Flow", "xtls-rprx-vision", "flow"),
            ("HeaderType", "http", "headerType"),
            ("SNI", "example.com", "sni"),
            ("PBK", "key", "pbk"),
            ("SID", "abcd", "sid"),
            ("FP", "chrome", "fp"),
            ("Encryption", "none", "encryption"),
            ("Host", "example.com", "host"),
            ("Path", "/vless", "path"),
            ("ServiceName", "svc", "serviceName"),
            ("Authority", "grpc.example", "authority"),
            ("Mode", "gun", "mode"),
        ] {
            let uri = format!(
                "vless://00000000-0000-4000-8000-000000000001@server.example:443?{key}={value}"
            );
            let error = VlessParser::parse_uri(&uri)
                .expect_err("Некорректный регистр критичного ключа обязан отклоняться")
                .to_string();
            assert!(error.contains("Некорректный регистр query-параметра"));
            assert!(error.contains(canonical));
        }
    }

    #[test]
    fn test_parse_empty_uuid_fails() {
        let uri = "vless://@203.0.113.30:443";
        let res = VlessParser::parse_uri(uri);
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("UUID"));
    }

    #[test]
    fn test_parse_invalid_scheme_fails() {
        let uri = "http://google.com";
        let res = VlessParser::parse_uri(uri);
        assert!(res.is_err());
    }

    #[test]
    fn test_parse_missing_port_fails() {
        let uri = "vless://uuid@host";
        let res = VlessParser::parse_uri(uri);
        assert!(res.is_err());
    }
}
