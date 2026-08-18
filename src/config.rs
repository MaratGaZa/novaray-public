//! Модели конфигурации серверов и пользовательских настроек
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

/// Поддерживаемые сетевые протоколы
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProtocolType {
    Vless,
}

impl fmt::Display for ProtocolType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Vless => write!(f, "vless"),
        }
    }
}

impl FromStr for ProtocolType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_lowercase().as_str() {
            "vless" => Ok(Self::Vless),
            other => Err(format!("Неподдерживаемый протокол: '{}'", other)),
        }
    }
}

/// Поддерживаемые типы транспорта VLESS.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransportType {
    #[default]
    Tcp,
    Ws,
    Grpc,
}

impl fmt::Display for TransportType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp => write!(f, "tcp"),
            Self::Ws => write!(f, "ws"),
            Self::Grpc => write!(f, "grpc"),
        }
    }
}

impl FromStr for TransportType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_lowercase().as_str() {
            "tcp" | "raw" => Ok(Self::Tcp),
            "ws" | "websocket" => Ok(Self::Ws),
            "grpc" => Ok(Self::Grpc),
            other => Err(format!(
                "Неподдерживаемый транспорт VLESS: '{}'. Поддерживаются 'tcp' (alias 'raw'), 'ws' и 'grpc'",
                other
            )),
        }
    }
}

/// Типы безопасности и шифрования сетевого соединения
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SecurityType {
    None,
    Tls,
    Reality,
}

impl fmt::Display for SecurityType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => write!(f, "none"),
            Self::Tls => write!(f, "tls"),
            Self::Reality => write!(f, "reality"),
        }
    }
}

impl FromStr for SecurityType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_lowercase().as_str() {
            "none" => Ok(Self::None),
            "tls" => Ok(Self::Tls),
            "reality" => Ok(Self::Reality),
            other => Err(format!("Неподдерживаемый тип безопасности: '{}'", other)),
        }
    }
}

/// Режимы XTLS Flow
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FlowType {
    #[serde(rename = "xtls-rprx-vision")]
    XtlsRprxVision,
}

impl fmt::Display for FlowType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::XtlsRprxVision => write!(f, "xtls-rprx-vision"),
        }
    }
}

impl FromStr for FlowType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_lowercase().as_str() {
            "xtls-rprx-vision" => Ok(Self::XtlsRprxVision),
            other => Err(format!("Неподдерживаемый тип flow: '{}'", other)),
        }
    }
}

/// Режимы раздельного туннелирования (Split Tunneling Modes)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SplitTunnelMode {
    /// Весь трафик направляется через VPN прокси
    ProxyAll,
    /// Трафик из списков направляется напрямую (в обход VPN), остальной через VPN
    BypassSelected,
    /// Только трафик из списков направляется через VPN, остальной напрямую
    ProxySelected,
    /// Трафик из списков блокируется (blackhole)
    BlockSelected,
}

impl fmt::Display for SplitTunnelMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProxyAll => write!(f, "proxy_all"),
            Self::BypassSelected => write!(f, "bypass_selected"),
            Self::ProxySelected => write!(f, "proxy_selected"),
            Self::BlockSelected => write!(f, "block_selected"),
        }
    }
}

impl FromStr for SplitTunnelMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_lowercase().as_str() {
            "proxy_all" => Ok(Self::ProxyAll),
            "bypass_selected" => Ok(Self::BypassSelected),
            "proxy_selected" => Ok(Self::ProxySelected),
            "block_selected" => Ok(Self::BlockSelected),
            other => Err(format!(
                "Неподдерживаемый режим раздельного туннелирования: '{}'",
                other
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppConfig {
    #[serde(rename = "$schema", default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    pub version: u32,
    pub active_profile_id: String,
    pub profiles: Vec<ServerProfile>,
}

impl AppConfig {
    pub fn find_active_profile(&self) -> Option<&ServerProfile> {
        self.profiles
            .iter()
            .find(|p| p.id == self.active_profile_id)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.profiles.is_empty() {
            return Err("Список профилей серверов пуст".to_string());
        }
        if self.find_active_profile().is_none() {
            return Err(format!(
                "Активный профиль '{}' не найден в списке профилей",
                self.active_profile_id
            ));
        }

        let mut seen_ids = HashSet::new();
        for profile in &self.profiles {
            if !seen_ids.insert(&profile.id) {
                return Err(format!("Обнаружен дубликат ID профиля: '{}'", profile.id));
            }
            profile.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerProfile {
    pub id: String,
    pub name: String,
    pub protocol: ProtocolType,
    pub server: String,
    pub port: u16,
    pub uuid: String,
    #[serde(default)]
    pub transport: TransportType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flow: Option<FlowType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsConfig>,
}

impl ServerProfile {
    pub fn validate(&self) -> Result<(), String> {
        if self.server.trim().is_empty() {
            return Err(format!(
                "Профиль '{}': адрес сервера не может быть пустым",
                self.id
            ));
        }
        if self.port == 0 {
            return Err(format!("Профиль '{}': порт не может быть 0", self.id));
        }
        if self.uuid.trim().is_empty() {
            return Err(format!("Профиль '{}': UUID не может быть пустым", self.id));
        }
        if self.flow.is_some() && self.transport != TransportType::Tcp {
            return Err(format!(
                "Профиль '{}': XTLS Vision поддерживается только с TCP transport",
                self.id
            ));
        }
        if self.transport == TransportType::Ws
            && self
                .tls
                .as_ref()
                .is_some_and(|tls| tls.enabled && tls.security == SecurityType::Reality)
        {
            return Err(format!(
                "Профиль '{}': Reality не поддерживается с WebSocket transport; используйте TCP/RAW или gRPC",
                self.id
            ));
        }
        match self.transport {
            TransportType::Tcp => {
                if self.host.is_some() || self.path.is_some() {
                    return Err(format!(
                        "Профиль '{}': host/path не применимы к TCP transport",
                        self.id
                    ));
                }
            }
            TransportType::Ws => {
                let path = self.path.as_deref().map(str::trim).unwrap_or_default();
                if path.is_empty() || !path.starts_with('/') {
                    return Err(format!(
                        "Профиль '{}': для WebSocket обязателен path, начинающийся с '/'",
                        self.id
                    ));
                }
                self.validate_transport_host()?;
            }
            TransportType::Grpc => {
                let service_name = self.path.as_deref().map(str::trim).unwrap_or_default();
                if service_name.is_empty()
                    || service_name.contains('/')
                    || service_name
                        .chars()
                        .any(|c| c.is_whitespace() || c.is_control())
                {
                    return Err(format!(
                        "Профиль '{}': для gRPC обязателен непустой стандартный serviceName без пробелов и '/'",
                        self.id
                    ));
                }
                self.validate_transport_host()?;
            }
        }
        if let Some(ref tls) = self.tls {
            tls.validate(&self.id)?;
        }
        Ok(())
    }

    fn validate_transport_host(&self) -> Result<(), String> {
        let host = self.effective_transport_host();
        if host.chars().any(|c| c.is_whitespace() || c.is_control()) || host.contains('/') {
            return Err(format!(
                "Профиль '{}': некорректный transport host '{}'",
                self.id, host
            ));
        }
        Ok(())
    }

    pub(crate) fn effective_transport_host(&self) -> &str {
        self.host
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .or_else(|| {
                self.tls
                    .as_ref()
                    .map(|tls| tls.server_name.trim())
                    .filter(|value| !value.is_empty())
            })
            .unwrap_or_else(|| self.server.trim())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    pub enabled: bool,
    pub security: SecurityType,
    pub server_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub short_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
}

impl TlsConfig {
    pub fn validate(&self, profile_id: &str) -> Result<(), String> {
        let sni = self.server_name.trim();

        // Валидация uTLS fingerprint для TLS и Reality
        if self.security != SecurityType::None {
            if let Some(ref fp) = self.fingerprint {
                let fp_trimmed = fp.trim();
                if !fp_trimmed.is_empty() && !is_valid_fingerprint(fp_trimmed) {
                    return Err(format!(
                        "Профиль '{}': неподдерживаемый uTLS fingerprint '{}'",
                        profile_id, fp_trimmed
                    ));
                }
            }
        }

        match self.security {
            SecurityType::Reality => {
                if sni.is_empty() {
                    return Err(format!(
                        "Профиль '{}': для Reality обязателен непустой Server Name (SNI)",
                        profile_id
                    ));
                }
                if !is_valid_sni_hostname(sni) {
                    return Err(format!(
                        "Профиль '{}': некорректный формат Server Name (SNI) '{}'",
                        profile_id, sni
                    ));
                }

                match self.public_key {
                    Some(ref pk) => {
                        let pk_trimmed = pk.trim();
                        if pk_trimmed.is_empty() {
                            return Err(format!(
                                "Профиль '{}': для Reality обязателен непустой public_key",
                                profile_id
                            ));
                        }
                        if !is_valid_reality_public_key(pk_trimmed) {
                            return Err(format!(
                                "Профиль '{}': некорректный public_key (ожидается 32-байтный Base64 ключ Reality, получено '{}')",
                                profile_id, pk_trimmed
                            ));
                        }
                    }
                    None => {
                        return Err(format!(
                            "Профиль '{}': для Reality обязателен непустой public_key",
                            profile_id
                        ));
                    }
                }

                if let Some(ref sid) = self.short_id {
                    let sid_trimmed = sid.trim();
                    if !sid_trimmed.is_empty()
                        && (!sid_trimmed.chars().all(|c| c.is_ascii_hexdigit())
                            || sid_trimmed.len() > 16
                            || sid_trimmed.len() % 2 != 0)
                    {
                        return Err(format!(
                            "Профиль '{}': short_id должен быть hex-строкой четной длины до 16 символов, получено '{}'",
                            profile_id, sid_trimmed
                        ));
                    }
                }
            }
            SecurityType::Tls => {
                if !sni.is_empty() && !is_valid_sni_hostname(sni) {
                    return Err(format!(
                        "Профиль '{}': некорректный формат Server Name (SNI) '{}'",
                        profile_id, sni
                    ));
                }
            }
            SecurityType::None => {}
        }
        Ok(())
    }
}

pub fn decode_reality_public_key(pk: &str) -> Option<[u8; 32]> {
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    use base64::Engine;

    let s = pk.trim();
    if s.is_empty() {
        return None;
    }

    let decoded = URL_SAFE_NO_PAD
        .decode(s)
        .or_else(|_| URL_SAFE.decode(s))
        .or_else(|_| STANDARD_NO_PAD.decode(s))
        .or_else(|_| STANDARD.decode(s))
        .ok()?;

    if decoded.len() == 32 {
        let mut key = [0u8; 32];
        key.copy_from_slice(&decoded);
        Some(key)
    } else {
        None
    }
}

pub fn is_valid_reality_public_key(pk: &str) -> bool {
    decode_reality_public_key(pk).is_some()
}

pub fn to_raw_url_safe_reality_public_key(pk: &str) -> Option<String> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    let bytes = decode_reality_public_key(pk)?;
    Some(URL_SAFE_NO_PAD.encode(bytes))
}

pub fn is_valid_sni_hostname(s: &str) -> bool {
    let s = s.trim();
    if s.is_empty() || s.len() > 253 {
        return false;
    }

    // RFC 6066: IPv4 и IPv6 адресные литералы запрещены в SNI
    if s.parse::<IpAddr>().is_ok()
        || (s.starts_with('[') && s.ends_with(']') && s[1..s.len() - 1].parse::<IpAddr>().is_ok())
    {
        return false;
    }

    // Проверка синтаксиса доменного имени (RFC 1123 / RFC 6066)
    if s.starts_with('.') || s.ends_with('.') {
        return false;
    }

    for label in s.split('.') {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            || label.starts_with('-')
            || label.ends_with('-')
        {
            return false;
        }
    }

    true
}

fn is_valid_fingerprint(s: &str) -> bool {
    matches!(
        s.to_lowercase().as_str(),
        "chrome"
            | "firefox"
            | "safari"
            | "ios"
            | "android"
            | "edge"
            | "360"
            | "qq"
            | "random"
            | "randomized"
            | "randomizednoalpn"
    )
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserSettings {
    #[serde(rename = "$schema", default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    pub version: u32,
    pub client: ClientSettings,
    pub split_tunneling: SplitTunnelingSettings,
}

impl UserSettings {
    pub fn validate(&self) -> Result<(), String> {
        if self.client.local_socks_port == 0 || self.client.local_http_port == 0 {
            return Err("Локальные порты прокси не могут быть 0".to_string());
        }
        if self.client.local_socks_port == self.client.local_http_port {
            return Err("Порты SOCKS5 и HTTP не должны совпадать".to_string());
        }
        self.split_tunneling.validate()?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientSettings {
    pub auto_connect_on_launch: bool,
    pub kill_switch: bool,
    pub system_notifications: bool,
    pub dns_servers: Vec<String>,
    pub local_socks_port: u16,
    pub local_http_port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SplitTunnelingSettings {
    pub enabled: bool,
    pub mode: SplitTunnelMode,
    pub direct_domains: Vec<String>,
    pub direct_ips: Vec<String>,
    pub direct_apps: Vec<String>,
}

impl SplitTunnelingSettings {
    pub fn validate(&self) -> Result<(), String> {
        for rule in &self.direct_domains {
            let trimmed = rule.trim();
            if trimmed.is_empty() {
                return Err("Правило домена не может быть пустой строкой".to_string());
            }
            if let Some(geosite) = trimmed.strip_prefix("geosite:") {
                if geosite != "category-ru" {
                    return Err(format!(
                        "Неподдерживаемая категория geosite: '{}'. Допустима только 'category-ru'",
                        trimmed
                    ));
                }
            }
        }
        for rule in &self.direct_ips {
            let trimmed = rule.trim();
            if trimmed.is_empty() {
                return Err("Правило IP не может быть пустой строкой".to_string());
            }
            if trimmed == "geoip:private" {
                continue;
            }
            if trimmed.parse::<IpAddr>().is_err() {
                return Err(format!(
                    "Неподдерживаемое или некорректное IP правило: '{}'. Допустимы только 'geoip:private' или валидный IP-адрес",
                    trimmed
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_app_config_validation() {
        let config = AppConfig {
            schema: None,
            version: 1,
            active_profile_id: "p1".to_string(),
            profiles: vec![ServerProfile {
                id: "p1".to_string(),
                name: "Test Server".to_string(),
                protocol: ProtocolType::Vless,
                server: "203.0.113.30".to_string(),
                port: 443,
                uuid: "uuid-1234".to_string(),
                transport: TransportType::Tcp,
                host: None,
                path: None,
                flow: Some(FlowType::XtlsRprxVision),
                tls: None,
            }],
        };

        assert!(config.validate().is_ok());
        assert_eq!(config.find_active_profile().unwrap().server, "203.0.113.30");
    }

    #[test]
    fn test_config_empty_profiles_fails() {
        let config = AppConfig {
            schema: None,
            version: 1,
            active_profile_id: "p1".to_string(),
            profiles: vec![],
        };

        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_missing_active_profile_fails() {
        let config = AppConfig {
            schema: None,
            version: 1,
            active_profile_id: "nonexistent".to_string(),
            profiles: vec![ServerProfile {
                id: "p1".to_string(),
                name: "Server 1".to_string(),
                protocol: ProtocolType::Vless,
                server: "192.0.2.53".to_string(),
                port: 443,
                uuid: "u1".to_string(),
                transport: TransportType::Tcp,
                host: None,
                path: None,
                flow: None,
                tls: None,
            }],
        };

        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_duplicate_profile_id_fails() {
        let config = AppConfig {
            schema: None,
            version: 1,
            active_profile_id: "p1".to_string(),
            profiles: vec![
                ServerProfile {
                    id: "p1".to_string(),
                    name: "Server 1".to_string(),
                    protocol: ProtocolType::Vless,
                    server: "192.0.2.53".to_string(),
                    port: 443,
                    uuid: "u1".to_string(),
                    transport: TransportType::Tcp,
                    host: None,
                    path: None,
                    flow: None,
                    tls: None,
                },
                ServerProfile {
                    id: "p1".to_string(),
                    name: "Server 2 Duplicate".to_string(),
                    protocol: ProtocolType::Vless,
                    server: "192.0.2.22".to_string(),
                    port: 443,
                    uuid: "u2".to_string(),
                    transport: TransportType::Tcp,
                    host: None,
                    path: None,
                    flow: None,
                    tls: None,
                },
            ],
        };

        assert!(config.validate().is_err());
        assert!(config
            .validate()
            .unwrap_err()
            .contains("дубликат ID профиля"));
    }

    #[test]
    fn test_profile_empty_server_fails() {
        let profile = ServerProfile {
            id: "p1".to_string(),
            name: "Server".to_string(),
            protocol: ProtocolType::Vless,
            server: "".to_string(),
            port: 443,
            uuid: "u1".to_string(),
            transport: TransportType::Tcp,
            host: None,
            path: None,
            flow: None,
            tls: None,
        };

        assert!(profile.validate().is_err());
    }

    #[test]
    fn test_profile_zero_port_fails() {
        let profile = ServerProfile {
            id: "p1".to_string(),
            name: "Server".to_string(),
            protocol: ProtocolType::Vless,
            server: "192.0.2.53".to_string(),
            port: 0,
            uuid: "u1".to_string(),
            transport: TransportType::Tcp,
            host: None,
            path: None,
            flow: None,
            tls: None,
        };

        assert!(profile.validate().is_err());
    }

    #[test]
    fn test_profile_empty_uuid_fails() {
        let profile = ServerProfile {
            id: "p1".to_string(),
            name: "Server".to_string(),
            protocol: ProtocolType::Vless,
            server: "192.0.2.53".to_string(),
            port: 443,
            uuid: "  ".to_string(),
            transport: TransportType::Tcp,
            host: None,
            path: None,
            flow: None,
            tls: None,
        };

        assert!(profile.validate().is_err());
    }

    #[test]
    fn test_tls_empty_or_invalid_sni_fails() {
        let profile = ServerProfile {
            id: "p1".to_string(),
            name: "Server".to_string(),
            protocol: ProtocolType::Vless,
            server: "192.0.2.53".to_string(),
            port: 443,
            uuid: "u1".to_string(),
            transport: TransportType::Tcp,
            host: None,
            path: None,
            flow: None,
            tls: Some(TlsConfig {
                enabled: true,
                security: SecurityType::Reality,
                server_name: "  ".to_string(),
                public_key: Some("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=".to_string()),
                short_id: Some("1234abcd".to_string()),
                fingerprint: Some("chrome".to_string()),
            }),
        };

        assert!(profile.validate().is_err());
        assert!(profile
            .validate()
            .unwrap_err()
            .contains("Server Name (SNI)"));

        let profile_invalid_sni = ServerProfile {
            id: "p1".to_string(),
            name: "Server".to_string(),
            protocol: ProtocolType::Vless,
            server: "192.0.2.53".to_string(),
            port: 443,
            uuid: "u1".to_string(),
            transport: TransportType::Tcp,
            host: None,
            path: None,
            flow: None,
            tls: Some(TlsConfig {
                enabled: true,
                security: SecurityType::Tls,
                server_name: "invalid sni/with/slash".to_string(),
                public_key: None,
                short_id: None,
                fingerprint: Some("chrome".to_string()),
            }),
        };

        assert!(profile_invalid_sni.validate().is_err());
        assert!(profile_invalid_sni
            .validate()
            .unwrap_err()
            .contains("некорректный формат Server Name (SNI)"));

        // IP literal as SNI is forbidden
        let profile_ip_sni = ServerProfile {
            id: "p1".to_string(),
            name: "Server".to_string(),
            protocol: ProtocolType::Vless,
            server: "192.0.2.53".to_string(),
            port: 443,
            uuid: "u1".to_string(),
            transport: TransportType::Tcp,
            host: None,
            path: None,
            flow: None,
            tls: Some(TlsConfig {
                enabled: true,
                security: SecurityType::Tls,
                server_name: "203.0.113.30".to_string(),
                public_key: None,
                short_id: None,
                fingerprint: None,
            }),
        };
        assert!(profile_ip_sni.validate().is_err());
        assert!(profile_ip_sni
            .validate()
            .unwrap_err()
            .contains("некорректный формат Server Name (SNI)"));
    }

    #[test]
    fn test_sni_hostname_validation_helper() {
        // Valid hostnames
        assert!(is_valid_sni_hostname("gateway.icloud.com"));
        assert!(is_valid_sni_hostname("dl.google.com"));
        assert!(is_valid_sni_hostname("tls.example.com"));
        assert!(is_valid_sni_hostname("my-server-1.org"));
        assert!(is_valid_sni_hostname("localhost"));

        // Invalid: IP literals (RFC 6066)
        assert!(!is_valid_sni_hostname("203.0.113.30"));
        assert!(!is_valid_sni_hostname("192.0.2.10"));
        assert!(!is_valid_sni_hostname("2001:db8::1"));
        assert!(!is_valid_sni_hostname("[2001:db8::1]"));

        // Invalid: format / RFC 1123 violations
        assert!(!is_valid_sni_hostname(""));
        assert!(!is_valid_sni_hostname("...."));
        assert!(!is_valid_sni_hostname("-"));
        assert!(!is_valid_sni_hostname("a..b"));
        assert!(!is_valid_sni_hostname("a_b"));
        assert!(!is_valid_sni_hostname("локальный.рф"));
        assert!(!is_valid_sni_hostname("invalid/host"));
        assert!(!is_valid_sni_hostname("invalid host with spaces"));
        assert!(!is_valid_sni_hostname("-start-hyphen.com"));
        assert!(!is_valid_sni_hostname("end-hyphen-.com"));
    }

    #[test]
    fn test_reality_public_key_validation_helper() {
        // Valid 32-byte X25519 public keys (43 chars unpadded or 44 chars padded)
        assert!(is_valid_reality_public_key(
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
        ));
        assert!(is_valid_reality_public_key(
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
        ));
        assert!(is_valid_reality_public_key(
            "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8="
        ));
        assert!(is_valid_reality_public_key(
            "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8"
        ));

        // Test conversion to canonical 43-character raw URL-safe Base64
        assert_eq!(
            to_raw_url_safe_reality_public_key("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=")
                .unwrap(),
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
        );
        assert_eq!(
            to_raw_url_safe_reality_public_key("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8")
                .unwrap(),
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
        );

        // Invalid keys: wrong decoded length or invalid base64
        assert!(!is_valid_reality_public_key(""));
        assert!(!is_valid_reality_public_key("a"));
        assert!(!is_valid_reality_public_key("="));
        assert!(!is_valid_reality_public_key("===="));
        assert!(!is_valid_reality_public_key("AAAA"));
        assert!(!is_valid_reality_public_key("key123"));
        assert!(!is_valid_reality_public_key("validbase64key=="));
        assert!(!is_valid_reality_public_key(
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8N8y9X4N8y9X4N8y9X4N8y9X4N8y9X4N8y9X4="
        ));
        assert!(!is_valid_reality_public_key(
            "invalid public key with spaces!@#"
        ));
        assert!(to_raw_url_safe_reality_public_key("invalid key").is_none());
    }

    #[test]
    fn test_reality_missing_public_key_fails() {
        let profile_no_pk = ServerProfile {
            id: "p1".to_string(),
            name: "Server".to_string(),
            protocol: ProtocolType::Vless,
            server: "192.0.2.53".to_string(),
            port: 443,
            uuid: "u1".to_string(),
            transport: TransportType::Tcp,
            host: None,
            path: None,
            flow: None,
            tls: Some(TlsConfig {
                enabled: true,
                security: SecurityType::Reality,
                server_name: "reality-test.example".to_string(),
                public_key: None,
                short_id: None,
                fingerprint: None,
            }),
        };
        assert!(profile_no_pk.validate().is_err());
        assert!(profile_no_pk
            .validate()
            .unwrap_err()
            .contains("обязателен непустой public_key"));
    }

    #[test]
    fn test_reality_invalid_public_key_or_short_id_fails() {
        let profile_bad_pk = ServerProfile {
            id: "p1".to_string(),
            name: "Server".to_string(),
            protocol: ProtocolType::Vless,
            server: "192.0.2.53".to_string(),
            port: 443,
            uuid: "u1".to_string(),
            transport: TransportType::Tcp,
            host: None,
            path: None,
            flow: None,
            tls: Some(TlsConfig {
                enabled: true,
                security: SecurityType::Reality,
                server_name: "reality-test.example".to_string(),
                public_key: Some("invalid public key with spaces #$^".to_string()),
                short_id: None,
                fingerprint: None,
            }),
        };
        assert!(profile_bad_pk.validate().is_err());
        assert!(profile_bad_pk
            .validate()
            .unwrap_err()
            .contains("некорректный public_key"));

        // Odd length short_id (e.g. 3 hex chars)
        let profile_odd_sid = ServerProfile {
            id: "p1".to_string(),
            name: "Server".to_string(),
            protocol: ProtocolType::Vless,
            server: "192.0.2.53".to_string(),
            port: 443,
            uuid: "u1".to_string(),
            transport: TransportType::Tcp,
            host: None,
            path: None,
            flow: None,
            tls: Some(TlsConfig {
                enabled: true,
                security: SecurityType::Reality,
                server_name: "reality-test.example".to_string(),
                public_key: Some("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8".to_string()),
                short_id: Some("abc".to_string()),
                fingerprint: None,
            }),
        };
        assert!(profile_odd_sid.validate().is_err());
        assert!(profile_odd_sid
            .validate()
            .unwrap_err()
            .contains("четной длины до 16 символов"));

        let profile_bad_sid = ServerProfile {
            id: "p1".to_string(),
            name: "Server".to_string(),
            protocol: ProtocolType::Vless,
            server: "192.0.2.53".to_string(),
            port: 443,
            uuid: "u1".to_string(),
            transport: TransportType::Tcp,
            host: None,
            path: None,
            flow: None,
            tls: Some(TlsConfig {
                enabled: true,
                security: SecurityType::Reality,
                server_name: "reality-test.example".to_string(),
                public_key: Some("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8".to_string()),
                short_id: Some("not_a_hex_short_id_xyz".to_string()),
                fingerprint: None,
            }),
        };
        assert!(profile_bad_sid.validate().is_err());
        assert!(profile_bad_sid
            .validate()
            .unwrap_err()
            .contains("short_id должен быть hex-строкой"));

        let profile_bad_fp = ServerProfile {
            id: "p1".to_string(),
            name: "Server".to_string(),
            protocol: ProtocolType::Vless,
            server: "192.0.2.53".to_string(),
            port: 443,
            uuid: "u1".to_string(),
            transport: TransportType::Tcp,
            host: None,
            path: None,
            flow: None,
            tls: Some(TlsConfig {
                enabled: true,
                security: SecurityType::Tls,
                server_name: "reality-test.example".to_string(),
                public_key: None,
                short_id: None,
                fingerprint: Some("unsupported_custom_browser".to_string()),
            }),
        };
        assert!(profile_bad_fp.validate().is_err());
        assert!(profile_bad_fp
            .validate()
            .unwrap_err()
            .contains("неподдерживаемый uTLS fingerprint"));
    }

    #[test]
    fn test_settings_port_collision_fails() {
        let settings = UserSettings {
            schema: None,
            version: 1,
            client: ClientSettings {
                auto_connect_on_launch: false,
                kill_switch: true,
                system_notifications: true,
                dns_servers: vec!["192.0.2.53".to_string()],
                local_socks_port: 10808,
                local_http_port: 10808,
            },
            split_tunneling: SplitTunnelingSettings {
                enabled: true,
                mode: SplitTunnelMode::BypassSelected,
                direct_domains: vec![],
                direct_ips: vec![],
                direct_apps: vec![],
            },
        };

        assert!(settings.validate().is_err());
    }

    #[test]
    fn test_settings_zero_ports_fail() {
        let settings = UserSettings {
            schema: None,
            version: 1,
            client: ClientSettings {
                auto_connect_on_launch: false,
                kill_switch: true,
                system_notifications: true,
                dns_servers: vec!["192.0.2.53".to_string()],
                local_socks_port: 0,
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

        assert!(settings.validate().is_err());
    }

    #[test]
    fn test_split_tunneling_unsupported_geosite_fails_validation() {
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
                enabled: true,
                mode: SplitTunnelMode::BypassSelected,
                direct_domains: vec!["geosite:unsupported_cat".to_string()],
                direct_ips: vec![],
                direct_apps: vec![],
            },
        };

        assert!(settings.validate().is_err());
        assert!(settings
            .validate()
            .unwrap_err()
            .contains("Неподдерживаемая категория geosite"));
    }

    #[test]
    fn test_split_tunneling_unsupported_geoip_fails_validation() {
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
                enabled: true,
                mode: SplitTunnelMode::ProxySelected,
                direct_domains: vec![],
                direct_ips: vec!["geoip:us".to_string()],
                direct_apps: vec![],
            },
        };

        assert!(settings.validate().is_err());
        assert!(settings
            .validate()
            .unwrap_err()
            .contains("Неподдерживаемое или некорректное IP правило"));
    }

    #[test]
    fn test_typed_enums_roundtrip_and_display() {
        // ProtocolType
        let proto = ProtocolType::Vless;
        assert_eq!(proto.to_string(), "vless");
        assert_eq!("vless".parse::<ProtocolType>().unwrap(), proto);
        assert!("unknown".parse::<ProtocolType>().is_err());

        // TransportType
        assert_eq!(TransportType::Tcp.to_string(), "tcp");
        assert_eq!("tcp".parse::<TransportType>().unwrap(), TransportType::Tcp);
        assert_eq!("raw".parse::<TransportType>().unwrap(), TransportType::Tcp);
        assert_eq!(
            " TCP ".parse::<TransportType>().unwrap(),
            TransportType::Tcp
        );
        assert_eq!("ws".parse::<TransportType>().unwrap(), TransportType::Ws);
        assert_eq!(
            "websocket".parse::<TransportType>().unwrap(),
            TransportType::Ws
        );
        assert_eq!(
            "grpc".parse::<TransportType>().unwrap(),
            TransportType::Grpc
        );
        assert!("httpupgrade".parse::<TransportType>().is_err());

        // SecurityType
        assert_eq!(SecurityType::Reality.to_string(), "reality");
        assert_eq!(SecurityType::Tls.to_string(), "tls");
        assert_eq!(SecurityType::None.to_string(), "none");
        assert_eq!(
            "reality".parse::<SecurityType>().unwrap(),
            SecurityType::Reality
        );
        assert_eq!("tls".parse::<SecurityType>().unwrap(), SecurityType::Tls);
        assert_eq!("none".parse::<SecurityType>().unwrap(), SecurityType::None);
        assert!("".parse::<SecurityType>().is_err());
        assert!("realiti".parse::<SecurityType>().is_err());

        // FlowType
        let flow = FlowType::XtlsRprxVision;
        assert_eq!(flow.to_string(), "xtls-rprx-vision");
        assert_eq!("xtls-rprx-vision".parse::<FlowType>().unwrap(), flow);
        assert!("unknown-flow".parse::<FlowType>().is_err());

        // SplitTunnelMode
        assert_eq!(SplitTunnelMode::ProxyAll.to_string(), "proxy_all");
        assert_eq!(
            SplitTunnelMode::BypassSelected.to_string(),
            "bypass_selected"
        );
        assert_eq!(SplitTunnelMode::ProxySelected.to_string(), "proxy_selected");
        assert_eq!(SplitTunnelMode::BlockSelected.to_string(), "block_selected");

        assert_eq!(
            "proxy_all".parse::<SplitTunnelMode>().unwrap(),
            SplitTunnelMode::ProxyAll
        );
        assert_eq!(
            "bypass_selected".parse::<SplitTunnelMode>().unwrap(),
            SplitTunnelMode::BypassSelected
        );
        assert_eq!(
            "proxy_selected".parse::<SplitTunnelMode>().unwrap(),
            SplitTunnelMode::ProxySelected
        );
        assert_eq!(
            "block_selected".parse::<SplitTunnelMode>().unwrap(),
            SplitTunnelMode::BlockSelected
        );
        assert!("invalid_mode".parse::<SplitTunnelMode>().is_err());
        assert!("bypass".parse::<SplitTunnelMode>().is_err());
    }

    #[test]
    fn test_unknown_fields_rejected_by_serde() {
        let json_with_unknown = r#"{
            "version": 1,
            "active_profile_id": "p1",
            "unknown_field": "some_value",
            "profiles": []
        }"#;

        let res: Result<AppConfig, _> = serde_json::from_str(json_with_unknown);
        assert!(res.is_err(), "Неизвестное поле должно вызывать ошибку");
    }

    #[test]
    fn test_config_json_roundtrip() {
        let original = AppConfig {
            schema: None,
            version: 1,
            active_profile_id: "p1".to_string(),
            profiles: vec![ServerProfile {
                id: "p1".to_string(),
                name: "Server 1".to_string(),
                protocol: ProtocolType::Vless,
                server: "192.0.2.53".to_string(),
                port: 443,
                uuid: "u1".to_string(),
                transport: TransportType::Tcp,
                host: None,
                path: None,
                flow: Some(FlowType::XtlsRprxVision),
                tls: Some(TlsConfig {
                    enabled: true,
                    security: SecurityType::Reality,
                    server_name: "reality-test.example".to_string(),
                    public_key: Some("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=".to_string()),
                    short_id: Some("1234abcd".to_string()),
                    fingerprint: Some("chrome".to_string()),
                }),
            }],
        };

        let json_str = serde_json::to_string_pretty(&original).unwrap();
        let deserialized: AppConfig = serde_json::from_str(&json_str).unwrap();

        assert_eq!(original, deserialized);
    }
}
