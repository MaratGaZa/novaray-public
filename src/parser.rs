//! Парсер стандартных ссылок VLESS Reality URI
use crate::config::{
    FlowType, ProtocolType, SecurityType, ServerProfile, TlsConfig, TransportType,
};
use anyhow::{anyhow, Result};
use percent_encoding::percent_decode_str;
use url::{Host, Url};

pub struct VlessParser;

pub const MAX_VLESS_URI_BYTES: usize = 16 * 1024;

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

fn reject_duplicate_critical_query_keys(url: &Url) -> Result<()> {
    let mut seen = [false; CRITICAL_QUERY_KEYS.len()];
    // Scan decoded keys before interpreting any values, including invalid or empty ones.
    for (key, _) in url.query_pairs() {
        let key = key.trim();
        if let Some(index) = CRITICAL_QUERY_KEYS.iter().position(|known| *known == key) {
            if seen[index] {
                return Err(anyhow!(
                    "Повтор критичного query-параметра '{}'",
                    CRITICAL_QUERY_KEYS[index]
                ));
            }
            seen[index] = true;
        }
    }
    Ok(())
}

fn noncanonical_critical_query_key(key: &str) -> Option<&'static str> {
    CRITICAL_QUERY_KEYS
        .iter()
        .copied()
        .find(|canonical| key != *canonical && key.trim().eq_ignore_ascii_case(canonical))
}

fn reject_invalid_query_names(url: &Url) -> Result<()> {
    for (key, _) in url.query_pairs() {
        if key.is_empty()
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        {
            if let Some(canonical) = noncanonical_critical_query_key(&key) {
                if key.trim() != key.as_ref() {
                    return Err(anyhow!(
                        "Пробелы в имени query-параметра: ожидается '{}'",
                        canonical
                    ));
                }
            }
            return Err(anyhow!("Недопустимое имя query-параметра"));
        }
    }
    Ok(())
}

fn validate_tcp_header_type(value: &str) -> Result<()> {
    match value.trim().to_lowercase().as_str() {
        "none" => Ok(()),
        _ => Err(anyhow!(
            "Неподдерживаемый параметр 'headerType': поддерживается только 'none'"
        )),
    }
}

impl VlessParser {
    /// Парсит ссылку формата `vless://uuid@host:port?query#name`
    pub fn parse_uri(uri_str: &str) -> Result<ServerProfile> {
        if uri_str.len() > MAX_VLESS_URI_BYTES {
            return Err(anyhow!("VLESS URI превышает лимит 16 KiB"));
        }
        let url = Url::parse(uri_str).map_err(|_| anyhow!("Некорректный формат URI"))?;

        if url.scheme() != "vless" {
            return Err(anyhow!("Ожидалась схема 'vless://'"));
        }

        reject_duplicate_critical_query_keys(&url)?;
        reject_invalid_query_names(&url)?;

        let uuid = url.username().to_string();
        if uuid.trim().is_empty() {
            return Err(anyhow!("UUID не может быть пустым"));
        }

        let uri_host = url
            .host_str()
            .ok_or_else(|| anyhow!("Хост сервера отсутствует в URI"))?;
        // Keep URI brackets for legacy identity, but not for the engine server address.
        let host = match url.host() {
            Some(Host::Ipv6(address)) => address.to_string(),
            _ => uri_host.to_string(),
        };

        let port = url
            .port()
            .ok_or_else(|| anyhow!("Порт сервера отсутствует в URI"))?;

        let name = match url.fragment() {
            Some(frag) if !frag.trim().is_empty() => {
                percent_decode_str(frag).decode_utf8_lossy().to_string()
            }
            _ => format!("{}:{}", uri_host, port),
        };

        let is_ip_host = host.parse::<std::net::IpAddr>().is_ok();

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
                    let parsed_flow: FlowType = v.parse().map_err(|_: String| {
                        anyhow!("Ошибка параметра 'flow': Неподдерживаемый тип flow")
                    })?;
                    flow = Some(parsed_flow);
                }
                "security" => {
                    let parsed_security: SecurityType = v.parse().map_err(|_: String| {
                        anyhow!("Ошибка параметра 'security': Неподдерживаемый тип безопасности")
                    })?;
                    security = parsed_security;
                }
                "type" => {
                    transport = v.parse().map_err(|_: String| {
                        anyhow!("Ошибка параметра 'type': неподдерживаемый транспорт VLESS")
                    })?;
                }
                "headerType" => validate_tcp_header_type(&v)?,
                "sni" => sni = v.to_string(),
                "pbk" => pbk = Some(v.to_string()),
                "sid" => sid = Some(v.to_string()),
                "fp" => fp = Some(v.to_string()),
                "host" => {
                    set_transport_value(&mut transport_host, v.as_ref(), "host")?;
                }
                "path" => {
                    set_transport_value(&mut transport_path, v.as_ref(), "path")?;
                }
                "serviceName" => {
                    if set_transport_value(&mut transport_path, v.as_ref(), "path")? {
                        grpc_specific_parameter = Some("serviceName");
                    }
                }
                "authority" => {
                    if set_transport_value(&mut transport_host, v.as_ref(), "host")? {
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
                    if let Some(canonical) = noncanonical_critical_query_key(&k) {
                        if k.trim() != k.as_ref() {
                            return Err(anyhow!(
                                "Пробелы в имени query-параметра: ожидается '{}'",
                                canonical
                            ));
                        }
                        return Err(anyhow!(
                            "Некорректный регистр query-параметра: ожидается '{}'",
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
                        "Неподдерживаемый gRPC mode: поддерживается только 'gun'"
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

        let safe_host_id = uri_host.replace(['.', ':', '[', ']'], "-");
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
            .map_err(|_| anyhow!("Ошибка валидации профиля VLESS"))?;

        Ok(profile)
    }
}

fn set_transport_value(
    target: &mut Option<String>,
    value: &str,
    canonical_field: &str,
) -> Result<bool> {
    let normalized = value.trim();
    if normalized.is_empty() {
        return Ok(false);
    }
    if let Some(existing) = target.as_deref() {
        if existing != normalized {
            return Err(anyhow!(
                "Конфликтующие значения transport-параметров для '{}'",
                canonical_field
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
    fn invalid_name_matrix_rejects_all_critical_keys_before_values() {
        // This list intentionally does not read CRITICAL_QUERY_KEYS.
        for key in [
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
        ] {
            for (encoded, literal) in [
                ("%E2%80%8B", "\u{200b}"),
                ("%E2%80%8C", "\u{200c}"),
                ("%E2%80%8D", "\u{200d}"),
                ("%EF%BB%BF", "\u{feff}"),
                ("%C2%AD", "\u{ad}"),
                ("%00", "%00"),
                ("%E1%A0%8E", "\u{180e}"),
                ("%E2%81%A0", "\u{2060}"),
            ] {
                for pad in [encoded, literal] {
                    for malformed in [
                        format!("{pad}{key}"),
                        format!("{key}{pad}"),
                        format!("{}{}{}", &key[..1], pad, &key[1..]),
                    ] {
                        for query in [
                            format!("{malformed}=private-value"),
                            format!("{malformed}=private-value&{key}=invalid"),
                            format!("{key}=invalid&{malformed}=private-value"),
                        ] {
                            let error = VlessParser::parse_uri(&format!(
                                "vless://private@edge.example:443?{query}#private-name"
                            ))
                            .unwrap_err();
                            assert_eq!(error.to_string(), "Недопустимое имя query-параметра");
                            assert!(error.source().is_none());
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn name_charset_keeps_valid_unknowns_and_rejects_invalid_unknowns() {
        VlessParser::parse_uri(
            "vless://test@edge.example:443?unknown_1=a&unknown_1=b&x-y=c&%78-y=d",
        )
        .unwrap();
        for key in [
            "",
            "%00",
            "sec%20urity",
            "unknown%20name",
            "unknown!",
            "%ZZunknown",
            "unknown%",
            "%FFunknown",
            "%C3%A9",
            "%E2%80%8Bunknown",
        ] {
            let error = VlessParser::parse_uri(&format!(
                "vless://test@edge.example:443?security=invalid&{key}=private"
            ))
            .unwrap_err();
            assert_eq!(error.to_string(), "Недопустимое имя query-параметра");
        }
    }

    const PADDED_TEST_KEYS: [&str; 14] = [
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

    #[test]
    fn padded_critical_keys_cannot_bypass_duplicate_guard() {
        for key in PADDED_TEST_KEYS {
            for pad in ["+", "%20", "%09", "%0A", "%0D", "%C2%A0", "%E2%80%83"] {
                for padded in [
                    format!("{pad}{key}"),
                    format!("{key}{pad}"),
                    format!("{pad}{key}{pad}"),
                ] {
                    for (first, second) in [
                        (key, padded.as_str()),
                        (padded.as_str(), key),
                        (padded.as_str(), padded.as_str()),
                    ] {
                        let error = VlessParser::parse_uri(&format!(
                            "vless://test@edge.example:443?{first}=private-a&{second}=private-b"
                        ))
                        .unwrap_err();
                        assert_eq!(
                            error.to_string(),
                            format!("Повтор критичного query-параметра '{key}'")
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn padded_single_critical_keys_are_rejected_without_echoing_padding() {
        for key in PADDED_TEST_KEYS {
            for spelling in [key.to_string(), key.to_ascii_uppercase()] {
                for pad in ["+", "%20", "%09", "%0A", "%0D", "%C2%A0", "%E2%80%83"] {
                    for padded in [format!("{pad}{spelling}"), format!("{spelling}{pad}")] {
                        let error = VlessParser::parse_uri(&format!(
                            "vless://test@edge.example:443?{padded}=private-value"
                        ))
                        .unwrap_err();
                        assert_eq!(
                            error.to_string(),
                            format!("Пробелы в имени query-параметра: ожидается '{key}'")
                        );
                        assert!(error.source().is_none());
                    }
                }
            }
        }
        for query in ["+unknown+=a", "sec%20urity=ignored"] {
            let error =
                VlessParser::parse_uri(&format!("vless://test@edge.example:443?{query}&unknown=b"))
                    .unwrap_err();
            assert_eq!(error.to_string(), "Недопустимое имя query-параметра");
        }
    }

    #[test]
    fn mixed_case_key_keeps_spelling_error_priority_over_duplicate() {
        for query in ["Security=none&security=none", "security=none&Security=none"] {
            let error = VlessParser::parse_uri(&format!("vless://test@edge.example:443?{query}"))
                .unwrap_err();
            assert_eq!(
                error.to_string(),
                "Некорректный регистр query-параметра: ожидается 'security'"
            );
        }
        for query in [
            "+Security=none&security=none",
            "security=none&Security%20=none",
        ] {
            let error = VlessParser::parse_uri(&format!("vless://test@edge.example:443?{query}"))
                .unwrap_err();
            assert_eq!(
                error.to_string(),
                "Пробелы в имени query-параметра: ожидается 'security'"
            );
        }
    }

    #[test]
    fn duplicate_query_matrix_rejects_every_critical_key_before_values() {
        // Keep the public contract independent of the implementation's key list.
        for key in [
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
        ] {
            let bare = format!("vless://test@edge.example:443?{key}&{key}");
            assert_eq!(
                VlessParser::parse_uri(&bare).unwrap_err().to_string(),
                format!("Повтор критичного query-параметра '{key}'")
            );
            for (first, second) in [
                ("private-a", "private-b"),
                ("same", "same"),
                ("", ""),
                ("", "value"),
                ("value", ""),
            ] {
                for (left, right) in [(first, second), (second, first)] {
                    let uri = format!("vless://private-credential@private.example:443?{key}={left}&ignored=between&{key}={right}#private-name");
                    let error = VlessParser::parse_uri(&uri).unwrap_err();
                    assert_eq!(
                        error.to_string(),
                        format!("Повтор критичного query-параметра '{key}'")
                    );
                    assert!(error.source().is_none());
                }
            }
        }
    }

    #[test]
    fn duplicate_query_decodes_key_spellings_before_comparison() {
        for key in CRITICAL_QUERY_KEYS {
            let encoded: String = key.bytes().map(|byte| format!("%{byte:02X}")).collect();
            for (first, second) in [
                (key, encoded.as_str()),
                (encoded.as_str(), key),
                (encoded.as_str(), encoded.as_str()),
            ] {
                let uri = format!("vless://test@edge.example:443?{first}=a&{second}=b");
                assert_eq!(
                    VlessParser::parse_uri(&uri).unwrap_err().to_string(),
                    format!("Повтор критичного query-параметра '{key}'")
                );
            }
        }
    }

    #[test]
    fn duplicate_query_single_keys_and_unknown_repeats_remain_compatible() {
        let values = [
            "xtls-rprx-vision",
            "none",
            "tcp",
            "none",
            "origin.example",
            "unused",
            "unused",
            "unused",
            "none",
            "",
            "",
            "",
            "",
            "",
        ];
        assert_eq!(values.len(), CRITICAL_QUERY_KEYS.len());
        for (key, value) in CRITICAL_QUERY_KEYS.into_iter().zip(values) {
            let uri = format!("vless://test@edge.example:443?{key}={value}&unknown=a&unknown=b");
            VlessParser::parse_uri(&uri).unwrap();
        }
        // An encoded delimiter in a value is data, not another query key.
        let profile = VlessParser::parse_uri(
            "vless://test@edge.example:443?type=ws&path=%2Fws%3Ftype%3Dtcp%26type%3Dgrpc",
        )
        .unwrap();
        assert_eq!(profile.path.as_deref(), Some("/ws?type=tcp&type=grpc"));
    }

    #[test]
    fn duplicate_query_does_not_merge_distinct_transport_aliases() {
        for query in [
            "host=cdn.example&authority=cdn.example&path=svc&serviceName=svc",
            "authority=cdn.example&host=cdn.example&serviceName=svc&path=svc",
        ] {
            let profile =
                VlessParser::parse_uri(&format!("vless://test@edge.example:443?type=grpc&{query}"))
                    .unwrap();
            assert_eq!(profile.host.as_deref(), Some("cdn.example"));
            assert_eq!(profile.path.as_deref(), Some("svc"));
        }
        for query in [
            "host=a.example&authority=b.example",
            "authority=b.example&host=a.example",
            "path=a&serviceName=b",
            "serviceName=b&path=a",
        ] {
            let error =
                VlessParser::parse_uri(&format!("vless://test@edge.example:443?type=grpc&{query}"))
                    .unwrap_err();
            assert!(error
                .to_string()
                .contains("Конфликтующие значения transport-параметров"));
        }
    }

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
        assert_eq!(profile.server, "2001:db8::1");
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
            .contains("Ошибка валидации профиля VLESS"));
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
        assert_eq!(error, "Ошибка валидации профиля VLESS");

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
            assert_eq!(error, "Ошибка валидации профиля VLESS");
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
            assert_eq!(error, "Ошибка валидации профиля VLESS");
        }
    }

    #[test]
    fn test_parse_xtls_vision_with_non_tcp_transport_fails_closed() {
        let uri = "vless://00000000-0000-4000-8000-000000000001@edge.example:443?security=tls&sni=origin.example&type=ws&path=%2Fvless&flow=xtls-rprx-vision";
        let error = VlessParser::parse_uri(uri)
            .expect_err("XTLS Vision поверх WebSocket должен отклоняться")
            .to_string();
        assert_eq!(error, "Ошибка валидации профиля VLESS");
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
            assert!(error.contains("неподдерживаемый транспорт VLESS"));
            assert!(!error.contains(transport));
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
            assert!(!error.contains(header_type));
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
