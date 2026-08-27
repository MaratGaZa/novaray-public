use std::io::Write;
use std::process::{Command, Stdio};

use novaray_core::platform_contract::{
    PlatformHelperEvent, PlatformHelperStatus, PlatformKind, PlatformObservedState,
    MAX_PLATFORM_MESSAGE_BYTES,
};

fn helper_bin() -> &'static str {
    env!("CARGO_BIN_EXE_novaray-platform-helper")
}

fn run_helper_stdin(input: &[u8]) -> std::process::Output {
    let mut child = Command::new(helper_bin())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn helper");

    child
        .stdin
        .as_mut()
        .expect("helper stdin")
        .write_all(input)
        .expect("write helper stdin");

    child.wait_with_output().expect("wait helper")
}

#[test]
fn helper_help_describes_side_effect_free_skeleton() {
    let output = Command::new(helper_bin())
        .arg("--help")
        .output()
        .expect("run helper --help");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("novaray-platform-helper"));
    assert!(stdout.contains("does not run as root"));
    assert!(stdout.contains("mutate routes/DNS/firewall"));
}

#[test]
fn helper_unexpected_arguments_are_usage_errors() {
    let output = Command::new(helper_bin())
        .arg("--unexpected")
        .output()
        .expect("run helper with bad arg");

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");
    assert!(stderr.contains("unexpected argument"));
}

#[test]
fn helper_status_command_returns_mac_os_idle_status() {
    let output = run_helper_stdin(br#"{"type":"status"}"#);

    assert_eq!(output.status.code(), Some(0));
    let event: PlatformHelperEvent =
        serde_json::from_slice(&output.stdout).expect("parse helper event");
    assert_eq!(
        event,
        PlatformHelperEvent::Status(PlatformHelperStatus {
            protocol_version: 1,
            platform: PlatformKind::MacOs,
            capabilities: vec![
                novaray_core::platform_contract::PlatformCapability::Tun,
                novaray_core::platform_contract::PlatformCapability::Ipv4,
                novaray_core::platform_contract::PlatformCapability::Ipv6,
                novaray_core::platform_contract::PlatformCapability::Dns,
                novaray_core::platform_contract::PlatformCapability::Firewall,
                novaray_core::platform_contract::PlatformCapability::KillSwitch,
                novaray_core::platform_contract::PlatformCapability::RecoveryJournal,
            ],
            observed_state: PlatformObservedState::Idle,
        })
    );
}

#[test]
fn helper_rejects_unknown_fields_fail_closed() {
    let output = run_helper_stdin(br#"{"type":"status","payload":null,"extra":true}"#);

    assert_eq!(output.status.code(), Some(3));
    let event: PlatformHelperEvent =
        serde_json::from_slice(&output.stdout).expect("parse helper event");
    assert!(matches!(
        event,
        PlatformHelperEvent::CommandRejected(reason)
            if reason.starts_with("invalid_command_json: line=1 column=")
    ));
}

#[test]
fn helper_rejects_oversized_stdin_before_deserialization() {
    let output = run_helper_stdin(&vec![b'x'; MAX_PLATFORM_MESSAGE_BYTES + 128]);

    assert_eq!(output.status.code(), Some(3));
    let event: PlatformHelperEvent =
        serde_json::from_slice(&output.stdout).expect("parse helper event");
    assert_eq!(
        event,
        PlatformHelperEvent::CommandRejected(format!(
            "payload_too_large: limit={MAX_PLATFORM_MESSAGE_BYTES}"
        ))
    );
}

#[test]
fn helper_parse_rejection_does_not_echo_input_values() {
    let output = run_helper_stdin(
        br#"{"type":"handshake","payload":{"protocol_version":1,"min_supported_protocol_version":1,"required_capabilities":"00000000-0000-4000-8000-000000000001"}}"#,
    );

    assert_eq!(output.status.code(), Some(3));
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("invalid_command_json"));
    assert!(!stdout.contains("00000000-0000-4000-8000-000000000001"));
}
