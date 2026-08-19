//! Проверки generated config реальным pinned sing-box.
//!
//! Эти тесты opt-in: они требуют локальный бинарник sing-box v1.13.18 и не
//! скачивают/не распространяют engine artifact.
use novaray_core::config::{
    AppConfig, ClientSettings, SplitTunnelMode, SplitTunnelingSettings, UserSettings,
};
use novaray_core::config_generator::EngineConfigStrategy;
use novaray_core::engine::{
    cleanup_runtime_config, preflight_check_config_with_strategy, write_secure_runtime_config,
};
use novaray_core::parser::VlessParser;
use std::path::PathBuf;
use std::time::Duration;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires NOVARAY_SING_BOX_BIN pointing to pinned sing-box v1.13.18"]
async fn generated_reality_tcp_config_passes_real_sing_box_preflight() {
    let sing_box_bin = PathBuf::from(
        std::env::var("NOVARAY_SING_BOX_BIN")
            .expect("NOVARAY_SING_BOX_BIN должен указывать на sing-box v1.13.18"),
    );
    let profile = VlessParser::parse_uri("vless://00000000-0000-4000-8000-000000000001@edge.example:443?type=tcp&security=reality&pbk=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=&fp=chrome&sni=gateway.example&sid=1234abcd&flow=xtls-rprx-vision#SingBoxRealityTcp")
        .expect("Reality TCP URI должен быть валиден");
    let settings = UserSettings {
        schema: None,
        version: 1,
        client: ClientSettings {
            auto_connect_on_launch: false,
            kill_switch: false,
            system_notifications: true,
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
    let app_config = AppConfig {
        schema: None,
        version: 1,
        active_profile_id: profile.id.clone(),
        profiles: vec![profile],
    };
    let active = app_config.find_active_profile().unwrap();
    let generated = EngineConfigStrategy::SingBox.generate(active, &settings);
    let json = serde_json::to_string_pretty(&generated).unwrap();
    let config_path = write_secure_runtime_config(None, &json).unwrap();

    let result = preflight_check_config_with_strategy(
        &sing_box_bin,
        &config_path,
        Duration::from_secs(5),
        EngineConfigStrategy::SingBox,
    )
    .await;
    cleanup_runtime_config(&config_path).unwrap();

    result.expect("sing-box check -c для generated Reality TCP config должен пройти");
}
