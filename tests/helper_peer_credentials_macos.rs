#![cfg(target_os = "macos")]

use std::cell::Cell;
use std::fs;
use std::io::{self, ErrorKind};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use novaray_core::helper_runtime_admission::{
    inspect_macos_peer_credentials, HelperRuntimeAdmissionAdapter,
    HelperRuntimeAdmissionAdapterError, HelperRuntimeAdmissionError,
    HelperRuntimeAdmissionExecutor, HelperRuntimeAdmissionPolicy, HelperRuntimeAdmissionRequest,
    HelperRuntimeAuthorizationExternalForm, HelperRuntimePeerCredentials,
};
use novaray_core::platform_contract::{
    CoreHello, HelperHello, PlatformCapability, PlatformKind, CURRENT_PLATFORM_CONTRACT_VERSION,
};

const CLIENT_SOCKET_ENV: &str = "NOVARAY_TEST_PEER_SOCKET";
const CHILD_TIMEOUT: Duration = Duration::from_secs(5);
static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

#[test]
fn cross_process_peer_credentials_stop_uid_mismatch_before_authorization() {
    let temp = PrivateSocketDir::new();
    let socket_path = temp.path().join("peer.sock");
    let listener = UnixListener::bind(&socket_path).expect("bind cross-process test socket");
    fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))
        .expect("set private socket permissions");

    assert_eq!(mode(temp.path()), 0o700);
    assert_eq!(mode(&socket_path), 0o600);

    let mut child = ChildGuard::spawn(&socket_path);
    let connection = accept_with_timeout(&listener, &mut child);
    let kernel_peer =
        inspect_macos_peer_credentials(&connection).expect("inspect child credentials");
    let expected_uid = different_unprivileged_uid(kernel_peer.effective_uid);
    let right_checks = Rc::new(Cell::new(0));
    let session_ids = Rc::new(Cell::new(0));
    let adapter = CrossProcessPeerAdapter {
        right_checks: Rc::clone(&right_checks),
        session_ids: Rc::clone(&session_ids),
    };

    let error = HelperRuntimeAdmissionExecutor::new(
        adapter,
        macos_helper(),
        HelperRuntimeAdmissionPolicy::new(expected_uid).unwrap(),
    )
    .admit(connection, admission_request())
    .unwrap_err();

    assert_eq!(error, HelperRuntimeAdmissionError::UnexpectedPeerUid);
    assert_eq!(right_checks.get(), 0);
    assert_eq!(session_ids.get(), 0);

    let output = child.wait_with_output();
    assert!(
        output.status.success(),
        "peer fixture failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let reported_peer = parse_reported_credentials(&output.stdout);
    assert_eq!(kernel_peer, reported_peer);

    drop(listener);
    let temp_path = temp.into_path();
    assert!(
        !temp_path.exists(),
        "temporary socket state must be removed"
    );
}

#[test]
fn helper_peer_client_fixture() {
    let Some(socket_path) = std::env::var_os(CLIENT_SOCKET_ENV) else {
        return;
    };

    let _connection = UnixStream::connect(socket_path).expect("connect peer fixture socket");
    // SAFETY: these credential getters have no pointer arguments or caller preconditions.
    let (effective_uid, effective_gid) = unsafe { (libc::geteuid(), libc::getegid()) };
    println!("uid={effective_uid} gid={effective_gid}");
    thread::sleep(Duration::from_millis(200));
}

struct CrossProcessPeerAdapter {
    right_checks: Rc<Cell<u32>>,
    session_ids: Rc<Cell<u32>>,
}

impl HelperRuntimeAdmissionAdapter for CrossProcessPeerAdapter {
    type Connection = UnixStream;

    fn peer_credentials(
        &mut self,
        connection: &Self::Connection,
    ) -> Result<HelperRuntimePeerCredentials, HelperRuntimeAdmissionAdapterError> {
        inspect_macos_peer_credentials(connection).map_err(|_| HelperRuntimeAdmissionAdapterError)
    }

    fn validate_runtime_right(
        &mut self,
        _connection: &mut Self::Connection,
        _authorization: &HelperRuntimeAuthorizationExternalForm,
    ) -> Result<(), HelperRuntimeAdmissionAdapterError> {
        self.right_checks.set(self.right_checks.get() + 1);
        Ok(())
    }

    fn generate_session_id(&mut self) -> Result<String, HelperRuntimeAdmissionAdapterError> {
        self.session_ids.set(self.session_ids.get() + 1);
        Ok("must-not-be-generated".to_string())
    }
}

struct PrivateSocketDir {
    path: Option<PathBuf>,
}

impl PrivateSocketDir {
    fn new() -> Self {
        let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("nr-peer-{}-{id}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).expect("create private socket directory");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .expect("set private directory permissions");
        Self { path: Some(path) }
    }

    fn path(&self) -> &Path {
        self.path.as_deref().expect("temp path is present")
    }

    fn into_path(mut self) -> PathBuf {
        let path = self.path.take().expect("temp path is present");
        fs::remove_dir_all(&path).expect("remove temporary socket directory");
        path
    }
}

impl Drop for PrivateSocketDir {
    fn drop(&mut self) {
        if let Some(path) = &self.path {
            let _ = fs::remove_dir_all(path);
        }
    }
}

struct ChildGuard {
    child: Option<Child>,
}

impl ChildGuard {
    fn spawn(socket_path: &Path) -> Self {
        let child = Command::new(std::env::current_exe().expect("resolve test executable"))
            .args(["--exact", "helper_peer_client_fixture", "--nocapture"])
            .env(CLIENT_SOCKET_ENV, socket_path)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn cross-process peer fixture");
        Self { child: Some(child) }
    }

    fn try_wait(&mut self) -> io::Result<Option<std::process::ExitStatus>> {
        self.child.as_mut().expect("child is present").try_wait()
    }

    fn wait_with_output(mut self) -> Output {
        self.child
            .take()
            .expect("child is present")
            .wait_with_output()
            .expect("wait for peer fixture")
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(child) = &mut self.child {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn accept_with_timeout(listener: &UnixListener, child: &mut ChildGuard) -> UnixStream {
    listener
        .set_nonblocking(true)
        .expect("set listener nonblocking");
    let deadline = Instant::now() + CHILD_TIMEOUT;

    loop {
        match listener.accept() {
            Ok((connection, _address)) => return connection,
            Err(error) if error.kind() == ErrorKind::WouldBlock => {}
            Err(error) => panic!("accept cross-process peer failed: {error}"),
        }

        if let Some(status) = child.try_wait().expect("inspect peer fixture status") {
            panic!("peer fixture exited before connect: {status}");
        }
        assert!(
            Instant::now() < deadline,
            "peer fixture did not connect within {CHILD_TIMEOUT:?}"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

fn parse_reported_credentials(stdout: &[u8]) -> HelperRuntimePeerCredentials {
    let output = String::from_utf8(stdout.to_vec()).expect("fixture output is UTF-8");
    let line = output
        .lines()
        .find(|line| line.starts_with("uid="))
        .expect("fixture credential line");
    let mut fields = line.split_whitespace();
    let effective_uid = parse_field(fields.next(), "uid=");
    let effective_gid = parse_field(fields.next(), "gid=");
    assert!(fields.next().is_none(), "unexpected fixture fields");
    HelperRuntimePeerCredentials {
        effective_uid,
        effective_gid,
    }
}

fn parse_field(field: Option<&str>, prefix: &str) -> u32 {
    field
        .and_then(|value| value.strip_prefix(prefix))
        .expect("fixture field prefix")
        .parse()
        .expect("fixture field value")
}

fn different_unprivileged_uid(actual: u32) -> u32 {
    if actual == 1 {
        2
    } else {
        1
    }
}

fn mode(path: &Path) -> u32 {
    fs::metadata(path)
        .expect("read path metadata")
        .permissions()
        .mode()
        & 0o777
}

fn admission_request() -> HelperRuntimeAdmissionRequest {
    HelperRuntimeAdmissionRequest {
        core_hello: CoreHello::default(),
        authorization: HelperRuntimeAuthorizationExternalForm::from_slice(&[0x5a; 32]).unwrap(),
    }
}

fn macos_helper() -> HelperHello {
    HelperHello {
        protocol_version: CURRENT_PLATFORM_CONTRACT_VERSION,
        platform: PlatformKind::MacOs,
        app_version: "0.1.0".to_string(),
        capabilities: vec![PlatformCapability::Tun],
    }
}
