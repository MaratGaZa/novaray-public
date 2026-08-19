use novaray_core::config::{
    AppConfig, ClientSettings, ProtocolType, SecurityType, SplitTunnelMode, SplitTunnelingSettings,
    TransportType, UserSettings,
};
use novaray_core::config_generator::EngineConfigStrategy;
use novaray_core::core::SupervisorState;

#[cfg(unix)]
use novaray_core::core::is_process_alive;
use novaray_core::engine::{
    cleanup_runtime_config, find_pinned_checksum, get_pinned_engine_releases,
    verify_engine_artifact, write_secure_runtime_config, EngineError, ProxyService,
};

#[cfg(unix)]
use novaray_core::engine::{preflight_check_config, ProxyServiceOptions};
use novaray_core::parser::VlessParser;
use novaray_core::sing_box_generator::SingBoxConfigGenerator;
use novaray_core::xray_generator::XrayConfigGenerator;
use std::path::Path;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
static TEST_COUNTER: AtomicU64 = AtomicU64::new(1);
static TEST_PORT_OFFSET: AtomicU16 = AtomicU16::new(0);

fn unique_temp_file(prefix: &str, suffix: &str) -> std::path::PathBuf {
    let count = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "{}_{}_{}_{}{}",
        prefix,
        std::process::id(),
        count,
        nanos,
        suffix
    ))
}

static TEST_BASE_OFFSET: std::sync::OnceLock<u16> = std::sync::OnceLock::new();

fn get_base_port_offset() -> u16 {
    *TEST_BASE_OFFSET.get_or_init(|| {
        let pid_part = ((std::process::id() as u16) % 30) * 150;
        let time_part = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_millis() as u16)
            % 30
            * 50;
        pid_part.wrapping_add(time_part)
    })
}

async fn allocate_isolated_test_ports() -> (u16, u16) {
    let base = get_base_port_offset();
    let step = TEST_PORT_OFFSET.fetch_add(50, Ordering::SeqCst);
    let p1 = 18000 + ((base.wrapping_add(step)) % 8000);
    let p2 = p1 + 1;
    (p1, p2)
}

async fn allocate_isolated_test_port() -> u16 {
    let base = get_base_port_offset();
    let step = TEST_PORT_OFFSET.fetch_add(50, Ordering::SeqCst);
    18000 + ((base.wrapping_add(step)) % 8000)
}

#[test]
fn test_secure_runtime_config_lifecycle_and_permissions() {
    let secret_payload = r#"{"secret": "vless-reality-private-key-12345"}"#;
    let config_path = write_secure_runtime_config(None, secret_payload)
        .expect("Runtime-конфиг должен быть успешно записан");
    assert!(config_path.exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&config_path).unwrap().permissions();
        assert_eq!(
            perms.mode() & 0o777,
            0o600,
            "Файл runtime-конфига должен иметь права 0600"
        );
    }

    cleanup_runtime_config(&config_path).expect("Очистка конфига должна пройти успешно");
    assert!(
        !config_path.exists(),
        "Файл runtime-конфигурации должен быть удален с диска"
    );
}

#[test]
fn test_engine_artifact_verification_checksum_and_permissions() {
    let mock_bin = unique_temp_file("mock_engine", ".sh");
    std::fs::write(&mock_bin, b"#!/bin/sh\nexit 0\n").unwrap();

    #[cfg(unix)]
    {
        let mut perms = std::fs::metadata(&mock_bin).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&mock_bin, perms).unwrap();
    }

    // 1. Проверка без указания чексуммы (вычисление фактической)
    let artifact =
        verify_engine_artifact(&mock_bin, None).expect("Верификация бинарника должна пройти");
    assert_eq!(artifact.path, mock_bin);
    assert!(!artifact.sha256.is_empty());

    // 2. Проверка с верной чексуммой
    let verify_correct = verify_engine_artifact(&mock_bin, Some(&artifact.sha256));
    assert!(verify_correct.is_ok());

    // 3. Проверка с неверной чексуммой
    let verify_wrong = verify_engine_artifact(
        &mock_bin,
        Some("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    );
    assert!(matches!(
        verify_wrong,
        Err(EngineError::ChecksumMismatch { .. })
    ));

    // 4. Проверка несуществующего файла
    let verify_nonexistent =
        verify_engine_artifact(Path::new("/tmp/nonexistent_engine_bin_99999"), None);
    assert!(matches!(
        verify_nonexistent,
        Err(EngineError::BinaryNotFound(_))
    ));

    let _ = std::fs::remove_file(&mock_bin);
}

#[test]
fn test_engine_config_strategy_preserves_xray_and_adds_sing_box() {
    let profile = VlessParser::parse_uri("vless://00000000-0000-4000-8000-000000000001@edge.example:443?type=grpc&security=tls&sni=origin.example&fp=chrome&serviceName=svc#StrategyProfile")
        .expect("gRPC TLS profile должен быть валиден");
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

    assert_eq!(profile.transport, TransportType::Grpc);

    let xray = EngineConfigStrategy::Xray.generate(&profile, &settings);
    let sing_box = EngineConfigStrategy::SingBox.generate(&profile, &settings);

    assert_eq!(xray, XrayConfigGenerator::generate(&profile, &settings));
    assert_eq!(
        sing_box,
        SingBoxConfigGenerator::generate(&profile, &settings)
    );
    assert_eq!(xray["outbounds"][0]["protocol"], "vless");
    assert_eq!(sing_box["outbounds"][0]["type"], "vless");
    assert_eq!(xray["outbounds"][0]["streamSettings"]["network"], "grpc");
    assert_eq!(sing_box["outbounds"][0]["transport"]["type"], "grpc");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_vless_reality_uri_to_proxy_service_pipeline_e2e() {
    // 1. Парсинг валидного VLESS Reality URI
    let uri = "vless://00000000-0000-4000-8000-000000000001@127.0.0.1:8443?type=tcp&security=reality&pbk=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=&fp=chrome&sni=example.com&sid=abcd#IntegrationProfile";
    let profile = VlessParser::parse_uri(uri).expect("VLESS URI должен быть успешно распарсен");
    assert_eq!(profile.protocol, ProtocolType::Vless);
    assert_eq!(
        profile.tls.as_ref().unwrap().security,
        SecurityType::Reality
    );

    // 2. Выделяем свободные локальные порты для SOCKS и HTTP inbounds
    let (socks_port, http_port) = allocate_isolated_test_ports().await;

    let config = AppConfig {
        schema: None,
        version: 1,
        active_profile_id: profile.id.clone(),
        profiles: vec![profile.clone()],
    };

    let settings = UserSettings {
        schema: None,
        version: 1,
        client: ClientSettings {
            auto_connect_on_launch: false,
            kill_switch: false,
            system_notifications: true,
            dns_servers: vec!["192.0.2.53".to_string()],
            local_socks_port: socks_port,
            local_http_port: http_port,
        },
        split_tunneling: SplitTunnelingSettings {
            enabled: true,
            mode: SplitTunnelMode::BypassSelected,
            direct_domains: vec!["internal.corp".to_string()],
            direct_ips: vec!["geoip:private".to_string(), "192.168.1.1".to_string()],
            direct_apps: vec!["Safari".to_string()],
        },
    };

    config.validate().expect("Конфигурация должна быть валидна");
    settings.validate().expect("Настройки должны быть валидны");

    // 3. Проверяем полную валидацию конфигурации и генерацию Xray JSON
    let active = config.find_active_profile().unwrap();
    let xray_json = XrayConfigGenerator::generate(active, &settings);
    assert!(xray_json.get("inbounds").is_some());
    assert!(xray_json.get("outbounds").is_some());

    // Проверяем, что Reality password нормализован в Raw URL-Safe Base64
    let outbounds = xray_json["outbounds"].as_array().unwrap();
    let vless_outbound = &outbounds[0];
    let reality_settings = &vless_outbound["streamSettings"]["realitySettings"];
    assert_eq!(
        reality_settings["password"].as_str().unwrap(),
        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
    );

    // 4. Проверяем генерацию inbounds с заданными локальными портами
    let inbounds = xray_json["inbounds"].as_array().unwrap();
    assert_eq!(inbounds.len(), 2);
    assert_eq!(inbounds[0]["protocol"].as_str().unwrap(), "socks");
    assert_eq!(inbounds[0]["port"].as_u64().unwrap(), socks_port as u64);
    assert_eq!(inbounds[1]["protocol"].as_str().unwrap(), "http");
    assert_eq!(inbounds[1]["port"].as_u64().unwrap(), http_port as u64);

    // 5. Проверяем запись защищенного runtime-конфига
    let serialized = serde_json::to_string_pretty(&xray_json).unwrap();
    let config_file = write_secure_runtime_config(None, &serialized).unwrap();
    assert!(config_file.exists());
    cleanup_runtime_config(&config_file).unwrap();
    assert!(!config_file.exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg(unix)]
async fn test_proxy_service_full_mock_engine_lifecycle_and_tcp_proxy() {
    let uri = "vless://00000000-0000-4000-8000-000000000001@127.0.0.1:8443?type=tcp&security=reality&pbk=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=&fp=chrome&sni=example.com&sid=abcd#LifecycleProfile";
    let profile = VlessParser::parse_uri(uri).unwrap();
    let (socks_port, http_port) = allocate_isolated_test_ports().await;

    let config = AppConfig {
        schema: None,
        version: 1,
        active_profile_id: profile.id.clone(),
        profiles: vec![profile],
    };

    let settings = UserSettings {
        schema: None,
        version: 1,
        client: ClientSettings {
            auto_connect_on_launch: false,
            kill_switch: false,
            system_notifications: true,
            dns_servers: vec!["192.0.2.53".to_string()],
            local_socks_port: socks_port,
            local_http_port: http_port,
        },
        split_tunneling: SplitTunnelingSettings {
            enabled: false,
            mode: SplitTunnelMode::ProxyAll,
            direct_domains: vec![],
            direct_ips: vec![],
            direct_apps: vec![],
        },
    };

    // Создаем исполняемый mock engine скрипт
    let mock_bin = unique_temp_file("mock_xray_bin", ".py");
    let script_content = r#"#!/usr/bin/env python3
import sys, socket, time, json, threading

if len(sys.argv) >= 3 and sys.argv[1] == "run" and sys.argv[2] == "-test":
    sys.exit(0)

config_path = sys.argv[-1]
with open(config_path) as f:
    cfg = json.load(f)

socks_port = cfg["inbounds"][0]["port"]

def handle_client(client):
    try:
        data = client.recv(1024)
        if data:
            client.sendall(b"HTTP/1.1 200 OK\r\n\r\nNovaRay-Engine-OK")
    except:
        pass
    finally:
        client.close()

def run_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    except Exception:
        pass
    s.bind(('127.0.0.1', socks_port))
    s.listen(128)
    while True:
        try:
            client, _ = s.accept()
            t = threading.Thread(target=handle_client, args=(client,))
            t.daemon = True
            t.start()
        except:
            break

t = threading.Thread(target=run_server)
t.daemon = True
t.start()

print(f"Xray started on port {socks_port}")
sys.stdout.flush()
time.sleep(30)
"#;
    std::fs::write(&mock_bin, script_content).unwrap();

    let mut perms = std::fs::metadata(&mock_bin).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&mock_bin, perms).unwrap();

    let mut proxy_service = ProxyService::new();
    let start_res = proxy_service
        .start(&mock_bin, None, &config, &settings)
        .await;
    assert!(
        start_res.is_ok(),
        "ProxyService должен успешно запуститься с mock engine"
    );
    assert_eq!(proxy_service.state(), SupervisorState::Ready);
    assert!(proxy_service.is_running());

    let pid = proxy_service.pid().expect("PID должен быть доступен");
    assert!(is_process_alive(pid));

    // Подключаемся к прокси-порту и делаем TCP-запрос
    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", socks_port))
        .await
        .expect("Клиент должен подключиться к SOCKS порту");
    stream
        .write_all(b"GET / HTTP/1.1\r\n\r\n")
        .await
        .expect("Запрос должен быть отправлен");

    let mut buf = [0u8; 256];
    let n = stream
        .read(&mut buf)
        .await
        .expect("Ответ должен быть прочитан");
    let resp = String::from_utf8_lossy(&buf[..n]);
    assert!(resp.contains("NovaRay-Engine-OK"));

    // Останавливаем сервис
    let stop_res = proxy_service.stop().await;
    assert!(stop_res.is_ok());
    assert_eq!(proxy_service.state(), SupervisorState::Stopped);

    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(
        !is_process_alive(pid),
        "Процесс движка должен быть гарантированно завершен"
    );

    let _ = std::fs::remove_file(&mock_bin);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_proxy_service_negative_invalid_config_fails_fast() {
    let mut proxy_service = ProxyService::new();

    // Невалидный AppConfig (нет профилей)
    let invalid_config = AppConfig {
        schema: None,
        version: 1,
        active_profile_id: "missing".to_string(),
        profiles: vec![],
    };

    let (socks_port, http_port) = allocate_isolated_test_ports().await;
    let settings = UserSettings {
        schema: None,
        version: 1,
        client: ClientSettings {
            auto_connect_on_launch: false,
            kill_switch: false,
            system_notifications: true,
            dns_servers: vec!["192.0.2.53".to_string()],
            local_socks_port: socks_port,
            local_http_port: http_port,
        },
        split_tunneling: SplitTunnelingSettings {
            enabled: false,
            mode: SplitTunnelMode::ProxyAll,
            direct_domains: vec![],
            direct_ips: vec![],
            direct_apps: vec![],
        },
    };

    let res = proxy_service
        .start(Path::new("python3"), None, &invalid_config, &settings)
        .await;

    assert!(
        res.is_err(),
        "Невалидный конфиг должен быть отклонен до запуска"
    );
    assert!(matches!(res, Err(EngineError::ConfigValidationError(_))));
    assert_eq!(proxy_service.state(), SupervisorState::Stopped);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_proxy_service_negative_nonexistent_binary_fails() {
    let mut proxy_service = ProxyService::new();

    let uri = "vless://00000000-0000-4000-8000-000000000001@127.0.0.1:8443?type=tcp&security=reality&pbk=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=&fp=chrome&sni=example.com&sid=abcd#Profile";
    let profile = VlessParser::parse_uri(uri).unwrap();
    let config = AppConfig {
        schema: None,
        version: 1,
        active_profile_id: profile.id.clone(),
        profiles: vec![profile],
    };
    let (socks_port, http_port) = allocate_isolated_test_ports().await;
    let settings = UserSettings {
        schema: None,
        version: 1,
        client: ClientSettings {
            auto_connect_on_launch: false,
            kill_switch: false,
            system_notifications: true,
            dns_servers: vec!["192.0.2.53".to_string()],
            local_socks_port: socks_port,
            local_http_port: http_port,
        },
        split_tunneling: SplitTunnelingSettings {
            enabled: false,
            mode: SplitTunnelMode::ProxyAll,
            direct_domains: vec![],
            direct_ips: vec![],
            direct_apps: vec![],
        },
    };

    let res = proxy_service
        .start(
            Path::new("/nonexistent_engine_path_xyz_12345"),
            None,
            &config,
            &settings,
        )
        .await;

    assert!(res.is_err());
    assert!(matches!(res, Err(EngineError::BinaryNotFound(_))));
    assert_eq!(proxy_service.state(), SupervisorState::Stopped);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_mock_proxy_server_tcp_request_and_response() {
    // Поднимаем тестовый TCP прокси-сервер
    let proxy_port = allocate_isolated_test_port().await;
    let listener = TcpListener::bind(("127.0.0.1", proxy_port)).await.unwrap();

    let server_task = tokio::spawn(async move {
        if let Ok((mut socket, _)) = listener.accept().await {
            let mut buf = [0u8; 1024];
            let n = socket.read(&mut buf).await.unwrap_or(0);
            if n > 0 {
                let _ = socket
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nNovaRay-Mock")
                    .await;
            }
        }
    });

    // Делаем TCP-запрос к прокси-серверу
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut client = TcpStream::connect(format!("127.0.0.1:{}", proxy_port))
        .await
        .expect("Клиент должен успешно подключиться к прокси-порту");

    client
        .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await
        .expect("Запрос должен быть отправлен");

    let mut response_buf = [0u8; 512];
    let n = client
        .read(&mut response_buf)
        .await
        .expect("Ответ должен быть прочитан");
    let response = String::from_utf8_lossy(&response_buf[..n]);

    assert!(
        response.contains("NovaRay-Mock"),
        "Ответ от прокси-сервера должен содержать 'NovaRay-Mock'"
    );

    let _ = server_task.await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg(unix)]
async fn test_proxy_service_start_when_already_running_returns_error() {
    let uri = "vless://00000000-0000-4000-8000-000000000001@127.0.0.1:8443?type=tcp&security=reality&pbk=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=&fp=chrome&sni=example.com&sid=abcd#AlreadyRunningProfile";
    let profile = VlessParser::parse_uri(uri).unwrap();

    let (socks_port, http_port) = allocate_isolated_test_ports().await;

    let config = AppConfig {
        schema: None,
        version: 1,
        active_profile_id: profile.id.clone(),
        profiles: vec![profile],
    };

    let settings = UserSettings {
        schema: None,
        version: 1,
        client: ClientSettings {
            auto_connect_on_launch: false,
            kill_switch: false,
            system_notifications: true,
            dns_servers: vec!["192.0.2.53".to_string()],
            local_socks_port: socks_port,
            local_http_port: http_port,
        },
        split_tunneling: SplitTunnelingSettings {
            enabled: false,
            mode: SplitTunnelMode::ProxyAll,
            direct_domains: vec![],
            direct_ips: vec![],
            direct_apps: vec![],
        },
    };

    let mock_bin = unique_temp_file("mock_running_xray", ".py");
    let script_content = r#"#!/usr/bin/env python3
import sys, socket, time, json, threading

if len(sys.argv) >= 3 and sys.argv[1] == "run" and sys.argv[2] == "-test":
    sys.exit(0)

config_path = sys.argv[-1]
with open(config_path) as f:
    cfg = json.load(f)

socks_port = cfg["inbounds"][0]["port"]

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
except Exception:
    pass
s.bind(('127.0.0.1', socks_port))
s.listen(128)
print(f"Xray started on port {socks_port}")
sys.stdout.flush()
time.sleep(30)
"#;
    std::fs::write(&mock_bin, script_content).unwrap();
    let mut perms = std::fs::metadata(&mock_bin).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&mock_bin, perms).unwrap();

    let mut proxy_service = ProxyService::new();
    let options = ProxyServiceOptions {
        enable_preflight_check: true,
        preflight_timeout: Duration::from_secs(5),
        readiness_timeout: Duration::from_secs(10),
        ..Default::default()
    };
    let res1 = proxy_service
        .start_with_options(&mock_bin, &config, &settings, &options)
        .await;
    assert!(res1.is_ok(), "res1 failed with: {:?}", res1);
    assert!(proxy_service.is_running());

    // Повторный вызов start() на работающем сервисе обязан вернуть ошибку AlreadyRunning
    let res2 = proxy_service
        .start_with_options(&mock_bin, &config, &settings, &options)
        .await;
    assert!(res2.is_err(), "res2 should be Err, but got: {:?}", res2);
    assert!(
        matches!(res2, Err(EngineError::AlreadyRunning(_))),
        "Повторный вызов start должен возвращать EngineError::AlreadyRunning, получено: {:?}",
        res2
    );

    let _ = proxy_service.stop().await;
    let _ = std::fs::remove_file(&mock_bin);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_proxy_service_port_in_use_fails_fast_before_spawn() {
    let uri = "vless://00000000-0000-4000-8000-000000000001@127.0.0.1:8443?type=tcp&security=reality&pbk=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=&fp=chrome&sni=example.com&sid=abcd#PortInUseProfile";
    let profile = VlessParser::parse_uri(uri).unwrap();

    let (occupied_port, free_port) = allocate_isolated_test_ports().await;
    // Занимаем SOCKS порт сокетом и подключаемся для гарантированного EADDRINUSE
    let _occupied_listener = TcpListener::bind(("127.0.0.1", occupied_port))
        .await
        .unwrap();
    let _conn = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", occupied_port)).await;

    let config = AppConfig {
        schema: None,
        version: 1,
        active_profile_id: profile.id.clone(),
        profiles: vec![profile],
    };

    let settings = UserSettings {
        schema: None,
        version: 1,
        client: ClientSettings {
            auto_connect_on_launch: false,
            kill_switch: false,
            system_notifications: true,
            dns_servers: vec!["192.0.2.53".to_string()],
            local_socks_port: occupied_port,
            local_http_port: free_port,
        },
        split_tunneling: SplitTunnelingSettings {
            enabled: false,
            mode: SplitTunnelMode::ProxyAll,
            direct_domains: vec![],
            direct_ips: vec![],
            direct_apps: vec![],
        },
    };

    let mut proxy_service = ProxyService::new();
    let res = proxy_service
        .start(Path::new("/dummy_path"), None, &config, &settings)
        .await;

    assert!(res.is_err());
    assert!(
        matches!(res, Err(EngineError::PortInUse(p)) if p == occupied_port),
        "Должна возвращаться ошибка EngineError::PortInUse({}), получено: {:?}",
        occupied_port,
        res
    );
    assert_eq!(proxy_service.state(), SupervisorState::Stopped);
}

#[test]
fn test_pinned_engine_releases_and_checksum_lookup() {
    let releases = get_pinned_engine_releases();
    assert!(
        !releases.is_empty(),
        "Список зафиксированных релизов не должен быть пустым"
    );

    let macos_arm64 = releases
        .iter()
        .find(|r| {
            r.engine_name == "xray-core" && r.target_os == "macos" && r.target_arch == "arm64"
        })
        .expect("Xray-core v26.3.27 для macos arm64 должен быть зафиксирован");
    assert_eq!(macos_arm64.version, "v26.3.27");
    assert_eq!(macos_arm64.archive_name, "Xray-macos-arm64-v8a.zip");
    assert_eq!(
        macos_arm64.archive_sha256,
        "2e93a67e8aa1936ecefb307e120830fcbd4c643ab9b1c46a2d0838d5f8409eaf"
    );

    let linux_arm64 = releases
        .iter()
        .find(|r| {
            r.engine_name == "xray-core" && r.target_os == "linux" && r.target_arch == "arm64"
        })
        .expect("Xray-core v26.3.27 для linux arm64 должен быть зафиксирован");
    assert_eq!(linux_arm64.version, "v26.3.27");
    assert_eq!(linux_arm64.archive_name, "Xray-linux-arm64-v8a.zip");
    assert_eq!(
        linux_arm64.archive_sha256,
        "4d30283ae614e3057f730f67cd088a42be6fdf91f8639d82cb69e48cde80413c"
    );

    let linux_x86_64 = releases
        .iter()
        .find(|r| {
            r.engine_name == "xray-core" && r.target_os == "linux" && r.target_arch == "x86_64"
        })
        .expect("Xray-core v26.3.27 для linux x86_64 должен быть зафиксирован");
    assert_eq!(linux_x86_64.version, "v26.3.27");
    assert_eq!(linux_x86_64.archive_name, "Xray-linux-64.zip");
    assert_eq!(
        linux_x86_64.archive_sha256,
        "23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae"
    );

    let checksum = find_pinned_checksum("xray-core", "v26.3.27");
    if std::env::consts::OS == "macos" && std::env::consts::ARCH == "aarch64" {
        assert_eq!(
            checksum,
            Some("2e93a67e8aa1936ecefb307e120830fcbd4c643ab9b1c46a2d0838d5f8409eaf")
        );
    }

    let sing_box_macos_arm64 = releases
        .iter()
        .find(|r| r.engine_name == "sing-box" && r.target_os == "macos" && r.target_arch == "arm64")
        .expect("sing-box v1.13.18 для macos arm64 должен быть зафиксирован");
    assert_eq!(sing_box_macos_arm64.version, "v1.13.18");
    assert_eq!(
        sing_box_macos_arm64.revision,
        "45ca32dcb966f07f97fc888fe8586e359dbe8405"
    );
    assert_eq!(
        sing_box_macos_arm64.archive_name,
        "sing-box-1.13.18-darwin-arm64.tar.gz"
    );
    assert_eq!(
        sing_box_macos_arm64.archive_sha256,
        "9fbc05946b584423457a2778035e0cee2d9b239a4af5ae1932d9b79991149107"
    );
    assert_eq!(
        sing_box_macos_arm64.binary_sha256,
        Some("020ecf20d3faa9ec3e917762085f0581aafbd3dd87a69573ae7345fc66fabc7f")
    );

    let sing_box_checksum = find_pinned_checksum("sing-box", "v1.13.18");
    if std::env::consts::OS == "macos" && std::env::consts::ARCH == "aarch64" {
        assert_eq!(sing_box_checksum, Some(sing_box_macos_arm64.archive_sha256));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg(unix)]
async fn test_proxy_service_preflight_validation_success_and_failure() {
    let mock_preflight_bin = unique_temp_file("mock_preflight_xray", ".py");

    let script_content = r#"#!/usr/bin/env python3
import sys, socket, time, json

if len(sys.argv) >= 3 and sys.argv[1] == "run" and sys.argv[2] == "-test":
    config_path = sys.argv[-1]
    with open(config_path) as f:
        content = f.read()
    if "FAIL_PREFLIGHT_TEST" in content:
        sys.stderr.write("Xray preflight check failed: invalid configuration\n")
        sys.exit(1)
    else:
        sys.stdout.write("Xray config test passed\n")
        sys.exit(0)

if len(sys.argv) >= 3 and sys.argv[1] == "run" and sys.argv[2] == "-c":
    config_path = sys.argv[-1]
    with open(config_path) as f:
        cfg = json.load(f)
    socks_port = cfg["inbounds"][0]["port"]
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    except Exception:
        pass
    s.bind(('127.0.0.1', socks_port))
    s.listen(128)
    print(f"Xray started on port {socks_port}")
    sys.stdout.flush()
    time.sleep(30)
"#;
    std::fs::write(&mock_preflight_bin, script_content).unwrap();
    let mut perms = std::fs::metadata(&mock_preflight_bin)
        .unwrap()
        .permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&mock_preflight_bin, perms).unwrap();

    let uri = "vless://00000000-0000-4000-8000-000000000001@127.0.0.1:8443?type=tcp&security=reality&pbk=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=&fp=chrome&sni=example.com&sid=abcd#PreflightProfile";
    let profile = VlessParser::parse_uri(uri).unwrap();

    let (socks_port, http_port) = allocate_isolated_test_ports().await;

    let config = AppConfig {
        schema: None,
        version: 1,
        active_profile_id: profile.id.clone(),
        profiles: vec![profile],
    };

    let settings = UserSettings {
        schema: None,
        version: 1,
        client: ClientSettings {
            auto_connect_on_launch: false,
            kill_switch: false,
            system_notifications: true,
            dns_servers: vec!["192.0.2.53".to_string()],
            local_socks_port: socks_port,
            local_http_port: http_port,
        },
        split_tunneling: SplitTunnelingSettings {
            enabled: false,
            mode: SplitTunnelMode::ProxyAll,
            direct_domains: vec![],
            direct_ips: vec![],
            direct_apps: vec![],
        },
    };

    // 1. Успешный запуск с pre-flight валидацией
    let mut proxy_service = ProxyService::new();
    let options = ProxyServiceOptions {
        enable_preflight_check: true,
        preflight_timeout: Duration::from_secs(5),
        ..Default::default()
    };
    let start_res = proxy_service
        .start_with_options(&mock_preflight_bin, &config, &settings, &options)
        .await;
    assert!(
        start_res.is_ok(),
        "Pre-flight проверка должна успешно пройти"
    );
    assert!(proxy_service.is_running());
    let _ = proxy_service.stop().await;

    // 2. Провал pre-flight проверки
    let bad_config_path = unique_temp_file("bad_config", ".json");
    std::fs::write(&bad_config_path, "FAIL_PREFLIGHT_TEST").unwrap();
    let preflight_err = preflight_check_config(
        &mock_preflight_bin,
        &bad_config_path,
        Duration::from_secs(5),
    )
    .await;
    assert!(preflight_err.is_err());
    assert!(
        matches!(preflight_err, Err(EngineError::ConfigPreflightFailed(_))),
        "Невалидная конфигурация должна отклоняться с ConfigPreflightFailed, получено: {:?}",
        preflight_err
    );

    let _ = std::fs::remove_file(&bad_config_path);
    let _ = std::fs::remove_file(&mock_preflight_bin);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg(unix)]
async fn test_proxy_service_preflight_timeout_fails_safely() {
    let mock_hanging_bin = unique_temp_file("mock_hanging_xray", ".py");

    let script_content = r#"#!/usr/bin/env python3
import sys, time, os

if len(sys.argv) >= 3 and sys.argv[1] == "run" and sys.argv[2] == "-test":
    config_path = sys.argv[-1]
    with open(config_path + ".pid", "w") as f:
        f.write(str(os.getpid()))
        f.flush()
    # Зависаем на pre-flight проверке
    time.sleep(30)
    sys.exit(0)
"#;
    std::fs::write(&mock_hanging_bin, script_content).unwrap();
    let mut perms = std::fs::metadata(&mock_hanging_bin).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&mock_hanging_bin, perms).unwrap();

    let dummy_config = unique_temp_file("dummy_config", ".json");
    let pid_file = std::path::PathBuf::from(format!("{}.pid", dummy_config.display()));
    std::fs::write(&dummy_config, "{}").unwrap();

    // Запускаем с коротким таймаутом 200 мс
    let preflight_err =
        preflight_check_config(&mock_hanging_bin, &dummy_config, Duration::from_millis(200)).await;

    assert!(preflight_err.is_err());
    assert!(
        matches!(preflight_err, Err(EngineError::ConfigPreflightFailed(_))),
        "Зависший pre-flight должен прерываться по таймауту с ConfigPreflightFailed, получено: {:?}",
        preflight_err
    );

    // Проверяем, что процесс был гарантированно убит при таймауте (zero process residue)
    for _ in 0..10 {
        if pid_file.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    if let Ok(pid_str) = std::fs::read_to_string(&pid_file) {
        if let Ok(pid) = pid_str.trim().parse::<u32>() {
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert!(
                !is_process_alive(pid),
                "Процесс PID {} должен быть гарантированно убит после таймаута pre-flight (zero process residue)",
                pid
            );
        }
    }

    let _ = std::fs::remove_file(&pid_file);
    let _ = std::fs::remove_file(&dummy_config);
    let _ = std::fs::remove_file(&mock_hanging_bin);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[cfg(unix)]
async fn test_proxy_service_real_socks5_and_http_proxy_handshake_and_upstream_traffic() {
    // 1. Поднимаем реальный upstream TCP эхо-сервер
    let echo_port = allocate_isolated_test_port().await;
    let echo_listener = TcpListener::bind(("127.0.0.1", echo_port)).await.unwrap();

    let echo_server_task = tokio::spawn(async move {
        while let Ok((mut socket, _)) = echo_listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let n = socket.read(&mut buf).await.unwrap_or(0);
                if n > 0 {
                    let req_str = String::from_utf8_lossy(&buf[..n]);
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: 21\r\nConnection: close\r\n\r\nEcho:{}\r\n",
                        req_str.lines().next().unwrap_or("UNKNOWN")
                    );
                    let _ = socket.write_all(response.as_bytes()).await;
                }
            });
        }
    });

    // 2. Выделяем свободные порты под SOCKS и HTTP inbounds
    let (socks_port, http_port) = allocate_isolated_test_ports().await;

    // 3. Создаем mock engine скрипт с поддержкой реального SOCKS5 (RFC 1928) и HTTP Forward Proxy
    let mock_engine_bin = unique_temp_file("mock_full_e2e_xray", ".py");

    let script_content = format!(
        r#"#!/usr/bin/env python3
import sys, socket, time, json, threading, struct

if len(sys.argv) >= 3 and sys.argv[1] == "run" and sys.argv[2] == "-test":
    sys.stdout.write("Xray config test OK\n")
    sys.exit(0)

if len(sys.argv) >= 3 and sys.argv[1] == "run" and sys.argv[2] == "-c":
    config_path = sys.argv[-1]
    with open(config_path) as f:
        cfg = json.load(f)

    socks_port = cfg["inbounds"][0]["port"]
    http_port = cfg["inbounds"][1]["port"]

    # 1. SOCKS5 Server (RFC 1928)
    def handle_socks5(client):
        try:
            # Greeting: \x05 \x01 \x00
            greeting = client.recv(3)
            if not greeting or greeting[0] != 5:
                client.close()
                return
            # Reply: Version 5, Method 0 (No Auth)
            client.sendall(b"\x05\x00")

            # Request: \x05 \x01 (CONNECT) \x00 \x01 (IPv4) [4 bytes IP] [2 bytes Port]
            req = client.recv(10)
            if not req or len(req) < 10 or req[1] != 1:
                client.close()
                return

            target_ip = socket.inet_ntoa(req[4:8])
            target_port = struct.unpack("!H", req[8:10])[0]

            # Connect to target upstream
            upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            upstream.connect((target_ip, target_port))

            # Success reply
            client.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")

            # Relay bidirectional
            def pipe(src, dst):
                try:
                    while True:
                        data = src.recv(4096)
                        if not data:
                            break
                        dst.sendall(data)
                except:
                    pass
                finally:
                    try: dst.shutdown(socket.SHUT_WR)
                    except: pass

            t1 = threading.Thread(target=pipe, args=(client, upstream))
            t2 = threading.Thread(target=pipe, args=(upstream, client))
            t1.daemon = True
            t2.daemon = True
            t1.start()
            t2.start()
            t1.join()
            t2.join()
        except:
            pass
        finally:
            client.close()

    def run_socks5():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except Exception:
            pass
        s.bind(('127.0.0.1', socks_port))
        s.listen(128)
        while True:
            try:
                c, _ = s.accept()
                t = threading.Thread(target=handle_socks5, args=(c,))
                t.daemon = True
                t.start()
            except:
                break

    # 2. HTTP Proxy Server
    def handle_http(client):
        try:
            req_data = client.recv(4096)
            if not req_data:
                client.close()
                return
            # Forward directly to target upstream {echo_port}
            upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            upstream.connect(('127.0.0.1', {echo_port}))
            upstream.sendall(req_data)
            resp = upstream.recv(4096)
            client.sendall(resp)
        except:
            pass
        finally:
            client.close()

    def run_http():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except Exception:
            pass
        s.bind(('127.0.0.1', http_port))
        s.listen(128)
        while True:
            try:
                c, _ = s.accept()
                t = threading.Thread(target=handle_http, args=(c,))
                t.daemon = True
                t.start()
            except:
                break

    t_s = threading.Thread(target=run_socks5)
    t_s.daemon = True
    t_s.start()

    t_h = threading.Thread(target=run_http)
    t_h.daemon = True
    t_h.start()

    print(f"Xray E2E engine started socks={{socks_port}} http={{http_port}}")
    sys.stdout.flush()
    time.sleep(30)
"#
    );

    std::fs::write(&mock_engine_bin, script_content).unwrap();
    let mut perms = std::fs::metadata(&mock_engine_bin).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&mock_engine_bin, perms).unwrap();

    let uri = "vless://00000000-0000-4000-8000-000000000001@127.0.0.1:8443?type=tcp&security=reality&pbk=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=&fp=chrome&sni=example.com&sid=abcd#E2EProxyProfile";
    let profile = VlessParser::parse_uri(uri).unwrap();

    let config = AppConfig {
        schema: None,
        version: 1,
        active_profile_id: profile.id.clone(),
        profiles: vec![profile],
    };

    let settings = UserSettings {
        schema: None,
        version: 1,
        client: ClientSettings {
            auto_connect_on_launch: false,
            kill_switch: false,
            system_notifications: true,
            dns_servers: vec!["192.0.2.53".to_string()],
            local_socks_port: socks_port,
            local_http_port: http_port,
        },
        split_tunneling: SplitTunnelingSettings {
            enabled: false,
            mode: SplitTunnelMode::ProxyAll,
            direct_domains: vec![],
            direct_ips: vec![],
            direct_apps: vec![],
        },
    };

    let mut proxy_service = ProxyService::new();
    let options = ProxyServiceOptions {
        enable_preflight_check: true,
        ..Default::default()
    };

    let start_res = proxy_service
        .start_with_options(&mock_engine_bin, &config, &settings, &options)
        .await;
    if let Err(ref e) = start_res {
        eprintln!("TEST_START_ERROR: {:?}", e);
    }
    assert!(
        start_res.is_ok(),
        "ProxyService должен успешно запуститься с pre-flight проверкой: {:?}",
        start_res
    );
    assert_eq!(proxy_service.state(), SupervisorState::Ready);

    let pid = proxy_service.pid().expect("PID должен присутствовать");
    assert!(is_process_alive(pid));

    // 4. Проверка протокольного SOCKS5 handshake (RFC 1928) и передачи трафика к upstream
    let mut socks_client = TcpStream::connect(format!("127.0.0.1:{}", socks_port))
        .await
        .expect("Клиент должен подключиться к SOCKS5 порту");

    // Отправляем SOCKS5 greeting: [VER=5, NMETHODS=1, METHOD=0 (No Auth)]
    socks_client
        .write_all(&[0x05, 0x01, 0x00])
        .await
        .expect("SOCKS5 greeting должен отправиться");

    let mut greeting_resp = [0u8; 2];
    socks_client
        .read_exact(&mut greeting_resp)
        .await
        .expect("SOCKS5 greeting response должен быть получен");
    assert_eq!(
        greeting_resp,
        [0x05, 0x00],
        "Сервер должен ответить SOCKS5 No Authentication (0x05, 0x00)"
    );

    // Отправляем SOCKS5 CONNECT запрос к 127.0.0.1:{echo_port}
    let port_bytes = echo_port.to_be_bytes();
    let connect_req = [
        0x05,
        0x01,
        0x00,
        0x01, // VER=5, CMD=CONNECT, RSV=0, ATYP=IPv4
        127,
        0,
        0,
        1, // IPv4: 127.0.0.1
        port_bytes[0],
        port_bytes[1], // Port
    ];
    socks_client
        .write_all(&connect_req)
        .await
        .expect("SOCKS5 connect request должен отправиться");

    let mut connect_resp = [0u8; 10];
    socks_client
        .read_exact(&mut connect_resp)
        .await
        .expect("SOCKS5 connect response должен быть получен");
    assert_eq!(
        connect_resp[0..2],
        [0x05, 0x00],
        "SOCKS5 connect должен ответить успехом (REP=0x00)"
    );

    // Отправляем HTTP-запрос через установленный SOCKS5 туннель
    socks_client
        .write_all(b"GET /socks5-tunnel HTTP/1.1\r\nHost: target\r\n\r\n")
        .await
        .expect("HTTP-запрос должен отправиться через SOCKS5");

    let mut socks_data_buf = [0u8; 256];
    let socks_read_n = socks_client
        .read(&mut socks_data_buf)
        .await
        .expect("Ответ через SOCKS5 должен быть прочитан");
    let socks_resp_str = String::from_utf8_lossy(&socks_data_buf[..socks_read_n]);
    assert!(
        socks_resp_str.contains("Echo:GET /socks5-tunnel HTTP/1.1"),
        "Ответ от upstream сервера через SOCKS5 должен содержать Echo, получено: {}",
        socks_resp_str
    );

    // 5. Проверка HTTP Forward Proxy через HTTP-inbound порт
    let mut http_client = TcpStream::connect(format!("127.0.0.1:{}", http_port))
        .await
        .expect("Клиент должен подключиться к HTTP прокси порту");

    http_client
        .write_all(b"GET /http-forward HTTP/1.1\r\nHost: target\r\n\r\n")
        .await
        .expect("HTTP-запрос должен отправиться на HTTP прокси");

    let mut http_data_buf = [0u8; 256];
    let http_read_n = http_client
        .read(&mut http_data_buf)
        .await
        .expect("Ответ от HTTP прокси должен быть прочитан");
    let http_resp_str = String::from_utf8_lossy(&http_data_buf[..http_read_n]);
    assert!(
        http_resp_str.contains("Echo:GET /http-forward HTTP/1.1"),
        "Ответ от upstream сервера через HTTP proxy должен содержать Echo, получено: {}",
        http_resp_str
    );

    // 6. Graceful остановка и проверка отсутствия процессов
    let stop_res = proxy_service.stop().await;
    assert!(stop_res.is_ok(), "Остановка сервиса должна пройти успешно");
    assert_eq!(proxy_service.state(), SupervisorState::Stopped);

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        !is_process_alive(pid),
        "Процесс движка должен быть гарантированно завершен"
    );

    echo_server_task.abort();
    let _ = std::fs::remove_file(&mock_engine_bin);
}
