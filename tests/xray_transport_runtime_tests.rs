//! Проверки generated transport config реальным pinned Xray-core.
//!
//! Тест игнорируется по умолчанию, поскольку бинарник не входит в репозиторий. Запуск:
//! `NOVARAY_XRAY_BIN=/path/to/xray cargo test --test xray_transport_runtime_tests -- --ignored`.

use novaray_core::config::{
    ClientSettings, ProtocolType, SecurityType, ServerProfile, SplitTunnelMode,
    SplitTunnelingSettings, TlsConfig, TransportType, UserSettings,
};
use novaray_core::engine::{
    cleanup_runtime_config, preflight_check_config, write_secure_runtime_config,
};
use novaray_core::xray_generator::XrayConfigGenerator;
use serde_json::{json, Value};
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::{Child, Command};

#[tokio::test]
#[ignore = "requires NOVARAY_XRAY_BIN pointing to pinned Xray-core v26.3.27"]
async fn generated_websocket_and_grpc_configs_pass_real_xray_preflight() {
    let binary = std::env::var("NOVARAY_XRAY_BIN")
        .expect("NOVARAY_XRAY_BIN должен указывать на Xray-core v26.3.27");
    let settings = settings();

    for (transport, host, path) in [
        (TransportType::Ws, "cdn.example", "/vless"),
        (TransportType::Grpc, "grpc.example", "svc"),
    ] {
        let profile = profile(transport, host, path);
        profile.validate().expect("Профиль должен быть валиден");
        let generated = XrayConfigGenerator::generate(&profile, &settings);
        let json = serde_json::to_string_pretty(&generated).unwrap();
        let config_path = write_secure_runtime_config(None, &json).unwrap();

        let result =
            preflight_check_config(Path::new(&binary), &config_path, Duration::from_secs(10)).await;
        let _ = cleanup_runtime_config(&config_path);
        result
            .unwrap_or_else(|error| panic!("Xray pre-flight для {transport} не пройден: {error}"));
    }

    let mut reality_grpc = profile(TransportType::Grpc, "grpc.example", "svc");
    reality_grpc.tls = Some(TlsConfig {
        enabled: true,
        security: SecurityType::Reality,
        server_name: "origin.example".to_string(),
        public_key: Some("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8".to_string()),
        short_id: Some(String::new()),
        fingerprint: Some("chrome".to_string()),
    });
    reality_grpc
        .validate()
        .expect("Reality + gRPC профиль должен быть валиден");
    let generated = XrayConfigGenerator::generate(&reality_grpc, &settings);
    let config_path =
        write_secure_runtime_config(None, &serde_json::to_string_pretty(&generated).unwrap())
            .unwrap();
    let result =
        preflight_check_config(Path::new(&binary), &config_path, Duration::from_secs(10)).await;
    let _ = cleanup_runtime_config(&config_path);
    result.expect("Xray pre-flight для Reality + gRPC должен пройти");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires NOVARAY_XRAY_BIN pointing to pinned Xray-core v26.3.27"]
async fn websocket_and_grpc_transport_real_local_http_requests() {
    let binary = std::env::var("NOVARAY_XRAY_BIN")
        .expect("NOVARAY_XRAY_BIN должен указывать на Xray-core v26.3.27");

    for transport in [TransportType::Ws, TransportType::Grpc] {
        run_transport_request(Path::new(&binary), transport).await;
    }
}

async fn run_transport_request(binary: &Path, transport: TransportType) {
    let server_port = reserve_port();
    let socks_port = reserve_port();
    let http_port = reserve_port();
    let target_listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let target_port = target_listener.local_addr().unwrap().port();
    let target_task = tokio::spawn(async move {
        let (mut stream, _) = target_listener.accept().await.unwrap();
        let mut request = vec![0_u8; 4096];
        let read = stream.read(&mut request).await.unwrap();
        assert!(String::from_utf8_lossy(&request[..read]).starts_with("GET /transport"));
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 20\r\nConnection: close\r\n\r\nNovaRay transport OK")
            .await
            .unwrap();
    });

    let (host, path) = match transport {
        TransportType::Ws => ("localhost", "/vless"),
        TransportType::Grpc => ("localhost", "svc"),
        TransportType::Tcp => unreachable!(),
    };
    let server_config = xray_server_config(transport, server_port, path);
    let server_path =
        write_secure_runtime_config(None, &serde_json::to_string_pretty(&server_config).unwrap())
            .unwrap();
    preflight_check_config(binary, &server_path, Duration::from_secs(10))
        .await
        .unwrap();
    let mut server = spawn_xray(binary, &server_path);
    wait_for_port(server_port).await;

    let mut client_settings = settings();
    client_settings.client.local_socks_port = socks_port;
    client_settings.client.local_http_port = http_port;
    let mut client_profile = profile(transport, host, path);
    client_profile.server = "127.0.0.1".to_string();
    client_profile.port = server_port;
    client_profile.tls = None;
    let client_config = XrayConfigGenerator::generate(&client_profile, &client_settings);
    let client_path =
        write_secure_runtime_config(None, &serde_json::to_string_pretty(&client_config).unwrap())
            .unwrap();
    preflight_check_config(binary, &client_path, Duration::from_secs(10))
        .await
        .unwrap();
    let mut client = spawn_xray(binary, &client_path);
    wait_for_port(socks_port).await;

    let response = request_through_socks5(socks_port, target_port).await;
    assert!(response.contains("200 OK"));
    assert!(response.contains("NovaRay transport OK"));
    target_task.await.unwrap();

    stop_child(&mut client).await;
    stop_child(&mut server).await;
    cleanup_runtime_config(&client_path).unwrap();
    cleanup_runtime_config(&server_path).unwrap();
}

fn xray_server_config(transport: TransportType, port: u16, path: &str) -> Value {
    let mut stream_settings = json!({
        "network": transport.to_string(),
        "security": "none"
    });
    match transport {
        TransportType::Ws => {
            stream_settings["wsSettings"] = json!({ "path": path });
        }
        TransportType::Grpc => {
            stream_settings["grpcSettings"] = json!({
                "serviceName": path,
                "multiMode": false
            });
        }
        TransportType::Tcp => unreachable!(),
    }

    json!({
        "log": { "loglevel": "warning" },
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": port,
            "protocol": "vless",
            "settings": {
                "clients": [{ "id": "00000000-0000-4000-8000-000000000001" }],
                "decryption": "none"
            },
            "streamSettings": stream_settings
        }],
        "outbounds": [{ "protocol": "freedom", "tag": "direct" }]
    })
}

fn reserve_port() -> u16 {
    std::net::TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn spawn_xray(binary: &Path, config_path: &Path) -> Child {
    let mut command = Command::new(binary);
    command
        .args(["run", "-c"])
        .arg(config_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    command.spawn().unwrap()
}

async fn wait_for_port(port: u16) {
    for _ in 0..200 {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("Порт {port} не открылся за timeout");
}

async fn request_through_socks5(socks_port: u16, target_port: u16) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", socks_port)).await.unwrap();
    stream.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut greeting = [0_u8; 2];
    stream.read_exact(&mut greeting).await.unwrap();
    assert_eq!(greeting, [0x05, 0x00]);

    let [port_high, port_low] = target_port.to_be_bytes();
    stream
        .write_all(&[0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, port_high, port_low])
        .await
        .unwrap();
    let mut connect_response = [0_u8; 10];
    stream.read_exact(&mut connect_response).await.unwrap();
    assert_eq!(connect_response[0], 0x05);
    assert_eq!(connect_response[1], 0x00);

    stream
        .write_all(b"GET /transport HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    String::from_utf8(response).unwrap()
}

async fn stop_child(child: &mut Child) {
    let _ = child.kill().await;
    let _ = child.wait().await;
}

fn profile(transport: TransportType, host: &str, path: &str) -> ServerProfile {
    ServerProfile {
        id: format!("runtime-{transport}"),
        name: format!("Runtime {transport}"),
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
