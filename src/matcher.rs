//! Механизм сопоставления правил раздельного туннелирования (Split Tunneling Matcher)
use crate::config::{SplitTunnelMode, SplitTunnelingSettings};
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoutingDecision {
    Direct,
    Proxy,
    Block,
}

pub struct SplitTunnelMatcher<'a> {
    settings: &'a SplitTunnelingSettings,
}

impl<'a> SplitTunnelMatcher<'a> {
    pub fn new(settings: &'a SplitTunnelingSettings) -> Self {
        Self { settings }
    }

    /// Проверка, содержится ли домен в настроенных правилах
    fn is_domain_in_list(&self, domain: &str) -> bool {
        let clean_domain = domain.trim().to_lowercase();

        for rule in &self.settings.direct_domains {
            let rule = rule.trim().to_lowercase();
            let pattern = if let Some(stripped) = rule.strip_prefix("domain:") {
                stripped
            } else if rule.starts_with("geosite:") {
                if rule == "geosite:category-ru" && clean_domain.ends_with(".ru") {
                    return true;
                }
                continue;
            } else {
                &rule
            };

            if clean_domain == pattern || clean_domain.ends_with(&format!(".{}", pattern)) {
                return true;
            }
        }

        false
    }

    /// Проверка, содержится ли IP-адрес в настроенных правилах
    fn is_ip_in_list(&self, ip_str: &str) -> bool {
        let parsed_ip = match ip_str.trim().parse::<IpAddr>() {
            Ok(ip) => ip,
            Err(_) => return false,
        };

        for rule in &self.settings.direct_ips {
            let rule = rule.trim();
            if rule == "geoip:private" {
                if is_private_or_loopback(parsed_ip) {
                    return true;
                }
            } else if let Ok(rule_ip) = rule.parse::<IpAddr>() {
                if parsed_ip == rule_ip {
                    return true;
                }
            }
        }

        false
    }

    /// Проверка, содержится ли идентификатор приложения в настроенных правилах
    fn is_app_in_list(&self, app_identifier: &str) -> bool {
        let clean_id = app_identifier.trim().to_lowercase();

        for direct_app in &self.settings.direct_apps {
            if clean_id == direct_app.trim().to_lowercase() {
                return true;
            }
        }

        false
    }

    /// Проверка правила маршрутизации для доменного имени в соответствии с режимом
    pub fn match_domain(&self, domain: &str) -> RoutingDecision {
        if !self.settings.enabled {
            return RoutingDecision::Proxy;
        }

        let in_list = self.is_domain_in_list(domain);

        match self.settings.mode {
            SplitTunnelMode::ProxyAll => RoutingDecision::Proxy,
            SplitTunnelMode::BypassSelected => {
                if in_list {
                    RoutingDecision::Direct
                } else {
                    RoutingDecision::Proxy
                }
            }
            SplitTunnelMode::ProxySelected => {
                if in_list {
                    RoutingDecision::Proxy
                } else {
                    RoutingDecision::Direct
                }
            }
            SplitTunnelMode::BlockSelected => {
                if in_list {
                    RoutingDecision::Block
                } else {
                    RoutingDecision::Proxy
                }
            }
        }
    }

    /// Проверка правила маршрутизации для IP-адреса в соответствии с режимом
    pub fn match_ip(&self, ip_str: &str) -> RoutingDecision {
        if !self.settings.enabled {
            return RoutingDecision::Proxy;
        }

        let in_list = self.is_ip_in_list(ip_str);

        match self.settings.mode {
            SplitTunnelMode::ProxyAll => RoutingDecision::Proxy,
            SplitTunnelMode::BypassSelected => {
                if in_list {
                    RoutingDecision::Direct
                } else {
                    RoutingDecision::Proxy
                }
            }
            SplitTunnelMode::ProxySelected => {
                if in_list {
                    RoutingDecision::Proxy
                } else {
                    RoutingDecision::Direct
                }
            }
            SplitTunnelMode::BlockSelected => {
                if in_list {
                    RoutingDecision::Block
                } else {
                    RoutingDecision::Proxy
                }
            }
        }
    }

    /// Проверка правила маршрутизации для программы (по bundle ID или имени процесса)
    pub fn match_app(&self, app_identifier: &str) -> RoutingDecision {
        if !self.settings.enabled {
            return RoutingDecision::Proxy;
        }

        let in_list = self.is_app_in_list(app_identifier);

        match self.settings.mode {
            SplitTunnelMode::ProxyAll => RoutingDecision::Proxy,
            SplitTunnelMode::BypassSelected => {
                if in_list {
                    RoutingDecision::Direct
                } else {
                    RoutingDecision::Proxy
                }
            }
            SplitTunnelMode::ProxySelected => {
                if in_list {
                    RoutingDecision::Proxy
                } else {
                    RoutingDecision::Direct
                }
            }
            SplitTunnelMode::BlockSelected => {
                if in_list {
                    RoutingDecision::Block
                } else {
                    RoutingDecision::Proxy
                }
            }
        }
    }
}

fn is_private_or_loopback(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => ipv4.is_loopback() || ipv4.is_private() || ipv4.is_link_local(),
        IpAddr::V6(ipv6) => ipv6.is_loopback() || ipv6.is_unicast_link_local(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn get_test_settings(mode: SplitTunnelMode) -> SplitTunnelingSettings {
        SplitTunnelingSettings {
            enabled: true,
            mode,
            direct_domains: vec![
                "geosite:category-ru".to_string(),
                "domain:gosuslugi.ru".to_string(),
                "kinopoisk.ru".to_string(),
            ],
            direct_ips: vec!["geoip:private".to_string(), "198.51.100.1".to_string()],
            direct_apps: vec![
                "com.yandex.desktop.music".to_string(),
                "Telegram".to_string(),
                "Slack".to_string(),
            ],
        }
    }

    #[test]
    fn test_direct_domain_exact_match() {
        let settings = get_test_settings(SplitTunnelMode::BypassSelected);
        let matcher = SplitTunnelMatcher::new(&settings);

        assert_eq!(
            matcher.match_domain("gosuslugi.ru"),
            RoutingDecision::Direct
        );
        assert_eq!(
            matcher.match_domain("kinopoisk.ru"),
            RoutingDecision::Direct
        );
    }

    #[test]
    fn test_direct_domain_subdomain_match() {
        let settings = get_test_settings(SplitTunnelMode::BypassSelected);
        let matcher = SplitTunnelMatcher::new(&settings);

        assert_eq!(
            matcher.match_domain("sub.gosuslugi.ru"),
            RoutingDecision::Direct
        );
        assert_eq!(
            matcher.match_domain("deep.nested.sub.kinopoisk.ru"),
            RoutingDecision::Direct
        );
    }

    #[test]
    fn test_foreign_domain_routes_to_proxy() {
        let settings = get_test_settings(SplitTunnelMode::BypassSelected);
        let matcher = SplitTunnelMatcher::new(&settings);

        assert_eq!(matcher.match_domain("google.com"), RoutingDecision::Proxy);
        assert_eq!(
            matcher.match_domain("instagram.com"),
            RoutingDecision::Proxy
        );
    }

    #[test]
    fn test_ru_tld_geosite_match() {
        let settings = get_test_settings(SplitTunnelMode::BypassSelected);
        let matcher = SplitTunnelMatcher::new(&settings);

        assert_eq!(matcher.match_domain("habr.ru"), RoutingDecision::Direct);
        assert_eq!(matcher.match_domain("yandex.ru"), RoutingDecision::Direct);
        assert_eq!(matcher.match_domain("ya.ru"), RoutingDecision::Direct);
    }

    #[test]
    fn test_disabled_split_tunneling_routes_everything_to_proxy() {
        let mut settings = get_test_settings(SplitTunnelMode::BypassSelected);
        settings.enabled = false;
        let matcher = SplitTunnelMatcher::new(&settings);

        assert_eq!(matcher.match_domain("gosuslugi.ru"), RoutingDecision::Proxy);
        assert_eq!(matcher.match_app("Telegram"), RoutingDecision::Proxy);
        assert_eq!(matcher.match_ip("127.0.0.1"), RoutingDecision::Proxy);
    }

    #[test]
    fn test_domain_case_insensitivity_and_whitespace() {
        let settings = get_test_settings(SplitTunnelMode::BypassSelected);
        let matcher = SplitTunnelMatcher::new(&settings);

        assert_eq!(
            matcher.match_domain("  GOSUSLUGI.RU  "),
            RoutingDecision::Direct
        );
        assert_eq!(
            matcher.match_domain("Kinopoisk.RU"),
            RoutingDecision::Direct
        );
    }

    #[test]
    fn test_domain_partial_match_does_not_false_positive() {
        let settings = get_test_settings(SplitTunnelMode::BypassSelected);
        let matcher = SplitTunnelMatcher::new(&settings);

        assert_eq!(
            matcher.match_domain("notgosuslugi.ru.com"),
            RoutingDecision::Proxy
        );
        assert_eq!(
            matcher.match_domain("fakekinopoisk.ru.net"),
            RoutingDecision::Proxy
        );
    }

    #[test]
    fn test_ip_matching_modes() {
        let settings = get_test_settings(SplitTunnelMode::BypassSelected);
        let matcher = SplitTunnelMatcher::new(&settings);

        // Private / Loopback IP -> Direct
        assert_eq!(matcher.match_ip("127.0.0.1"), RoutingDecision::Direct);
        assert_eq!(matcher.match_ip("192.168.1.1"), RoutingDecision::Direct);
        assert_eq!(matcher.match_ip("10.0.0.5"), RoutingDecision::Direct);

        // Exact IP in direct_ips -> Direct
        assert_eq!(matcher.match_ip("198.51.100.1"), RoutingDecision::Direct);

        // Foreign public IP -> Proxy
        assert_eq!(matcher.match_ip("198.51.100.53"), RoutingDecision::Proxy);
        assert_eq!(matcher.match_ip("192.0.2.53"), RoutingDecision::Proxy);

        // Malformed IP -> Proxy (fail-safe)
        assert_eq!(
            matcher.match_ip("185.196.not-an-ip"),
            RoutingDecision::Proxy
        );
        assert_eq!(matcher.match_ip("999.0.0.1"), RoutingDecision::Proxy);
    }

    #[test]
    fn test_app_split_routing() {
        let settings = get_test_settings(SplitTunnelMode::BypassSelected);
        let matcher = SplitTunnelMatcher::new(&settings);

        assert_eq!(matcher.match_app("telegram"), RoutingDecision::Direct);
        assert_eq!(matcher.match_app("Telegram"), RoutingDecision::Direct);
        assert_eq!(
            matcher.match_app("com.yandex.desktop.music"),
            RoutingDecision::Direct
        );
        assert_eq!(matcher.match_app("Chrome"), RoutingDecision::Proxy);
    }

    #[test]
    fn test_split_tunnel_modes() {
        // ProxyAll
        let proxy_all_settings = get_test_settings(SplitTunnelMode::ProxyAll);
        let matcher1 = SplitTunnelMatcher::new(&proxy_all_settings);
        assert_eq!(
            matcher1.match_domain("gosuslugi.ru"),
            RoutingDecision::Proxy
        );
        assert_eq!(matcher1.match_app("Telegram"), RoutingDecision::Proxy);

        // ProxySelected
        let proxy_selected_settings = get_test_settings(SplitTunnelMode::ProxySelected);
        let matcher2 = SplitTunnelMatcher::new(&proxy_selected_settings);
        assert_eq!(
            matcher2.match_domain("gosuslugi.ru"),
            RoutingDecision::Proxy
        );
        assert_eq!(
            matcher2.match_domain("foreign.com"),
            RoutingDecision::Direct
        );
        assert_eq!(matcher2.match_app("Telegram"), RoutingDecision::Proxy);
        assert_eq!(matcher2.match_app("OtherApp"), RoutingDecision::Direct);

        // BlockSelected
        let block_settings = get_test_settings(SplitTunnelMode::BlockSelected);
        let matcher3 = SplitTunnelMatcher::new(&block_settings);
        assert_eq!(
            matcher3.match_domain("gosuslugi.ru"),
            RoutingDecision::Block
        );
        assert_eq!(matcher3.match_domain("foreign.com"), RoutingDecision::Proxy);
        assert_eq!(matcher3.match_app("Telegram"), RoutingDecision::Block);
        assert_eq!(matcher3.match_app("OtherApp"), RoutingDecision::Proxy);
    }
}
