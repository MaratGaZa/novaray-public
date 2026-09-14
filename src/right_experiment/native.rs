use std::ffi::{c_char, c_void, CString};
use std::fs::File;
use std::io::{self, BufRead, IsTerminal, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::process::ExitCode;
use std::ptr;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use core_foundation::base::{CFType, CFTypeRef, TCFType};
use core_foundation::dictionary::{CFDictionary, CFDictionaryRef};
use core_foundation::string::{CFString, CFStringRef};
use serde::Serialize;
use sha2::{Digest, Sha256};

use super::protocol::*;
use crate::helper_runtime_right::{
    plan_helper_runtime_right_install, HelperRuntimeAuthorizationRightInstallPlan,
    HELPER_RUNTIME_AUTHORIZATION_RULE,
};

mod shape;

#[link(name = "Security", kind = "framework")]
extern "C" {
    fn SecRandomCopyBytes(random: *const c_void, count: usize, bytes: *mut u8) -> i32;
    fn AuthorizationCreate(
        rights: *const c_void,
        environment: *const c_void,
        flags: u32,
        authorization: *mut *mut c_void,
    ) -> i32;
    fn AuthorizationFree(authorization: *mut c_void, flags: u32) -> i32;
    fn AuthorizationRightGet(name: *const c_char, definition: *mut CFDictionaryRef) -> i32;
    fn AuthorizationRightSet(
        authorization: *mut c_void,
        name: *const c_char,
        definition: CFTypeRef,
        description: CFStringRef,
        bundle: *const c_void,
        locale: CFStringRef,
    ) -> i32;
    fn AuthorizationRightRemove(authorization: *mut c_void, name: *const c_char) -> i32;
}

fn api_status(status: i32) -> Result<(), Failure> {
    match status {
        0 => Ok(()),
        -60005 => Err(Failure::Denied),
        -60006 => Err(Failure::Canceled),
        -60007 => Err(Failure::InteractionNotAllowed),
        _ => Err(Failure::Api),
    }
}

struct Authorization(*mut c_void);
impl Drop for Authorization {
    fn drop(&mut self) {
        // SAFETY: non-null reference returned by AuthorizationCreate, owned only here.
        // Destroy acquired rights rather than leaving the experiment's reference reusable.
        unsafe {
            AuthorizationFree(self.0, 1 << 3);
        }
    }
}

impl Authorization {
    fn acquire() -> Result<Self, Failure> {
        let mut raw = ptr::null_mut();
        // SAFETY: null rights/environment request no rights or credentials; valid output slot.
        // RightSet/Remove may later prompt, but only after the separate operator approval.
        let status = unsafe { AuthorizationCreate(ptr::null(), ptr::null(), 0, &mut raw) };
        let owned = if raw.is_null() { None } else { Some(Self(raw)) };
        api_status(status)?;
        owned.ok_or(Failure::Api)
    }
}

struct Journal {
    file: File,
    bytes: usize,
}
impl Journal {
    fn create(directory: &File) -> Result<Self, Failure> {
        let name = CString::new("native-right-roundtrip.jsonl").unwrap();
        // SAFETY: directory is an open directory, name is a fixed NUL-terminated basename.
        // Never open an existing manifest or follow a link; there is deliberately no resume.
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err(Failure::Journal);
        }
        // SAFETY: fd is newly opened and transfers ownership exactly once.
        let file = unsafe { File::from_raw_fd(fd) };
        file.sync_all()
            .and_then(|_| directory.sync_all())
            .map_err(|_| Failure::Journal)?;
        Ok(Self { file, bytes: 0 })
    }

    fn append(&mut self, record: &impl Serialize) -> Result<(), Failure> {
        let mut line = serde_json::to_vec(record).map_err(|_| Failure::Journal)?;
        line.push(b'\n');
        if line.len() > 16_384 || self.bytes + line.len() > 65_536 {
            return Err(Failure::Journal);
        }
        self.file
            .write_all(&line)
            .and_then(|_| self.file.sync_all())
            .map_err(|_| Failure::Journal)?;
        self.bytes += line.len();
        Ok(())
    }
}

struct NativeAdapter {
    name: CString,
    authorization: Option<Authorization>,
    journal: Journal,
    start: Instant,
}

impl Adapter for NativeAdapter {
    fn checkpoint(&mut self) -> Result<(), Failure> {
        if self.start.elapsed() >= Duration::from_secs(DEADLINE_SECONDS) {
            Err(Failure::Deadline)
        } else {
            Ok(())
        }
    }
    fn record(&mut self, record: Record) -> Result<(), Failure> {
        self.journal.append(&record)
    }
    fn authorize(&mut self) -> Result<(), Failure> {
        self.authorization = Some(Authorization::acquire()?);
        Ok(())
    }
    fn inspect(&mut self) -> Result<Observation, Failure> {
        let mut raw = ptr::null();
        // SAFETY: generated NUL-terminated name, valid writable output slot. Get returns retained CF.
        let status = unsafe { AuthorizationRightGet(self.name.as_ptr(), &mut raw) };
        let definition = if raw.is_null() {
            None
        } else {
            // SAFETY: retained result from Security; release even on inconsistent/error responses.
            Some(unsafe { CFType::wrap_under_create_rule(raw.cast()) })
        };
        match (status, definition) {
            // This special absence mapping is documented for RightGet ONLY, never for writes.
            (-60005, None) => Ok(Observation::Absent),
            (0, Some(definition)) => {
                let summary = shape::inspect(&definition)?;
                self.journal.append(&summary)?;
                let observed = crate::macos_runtime_right::classify_definition(&definition);
                if matches!(
                    plan_helper_runtime_right_install(observed),
                    Ok(HelperRuntimeAuthorizationRightInstallPlan::AlreadyOwned)
                ) {
                    Ok(Observation::Exact)
                } else {
                    Ok(Observation::Incompatible)
                }
            }
            _ => Err(Failure::Inspection),
        }
    }
    fn create(&mut self) -> Result<(), Failure> {
        let authorization = self.authorization.as_ref().ok_or(Failure::Api)?;
        let definition = CFDictionary::from_CFType_pairs(&[(
            CFString::new("rule"),
            CFString::new(HELPER_RUNTIME_AUTHORIZATION_RULE),
        )]);
        // SAFETY: owned live authorization, generated name, retained CF dictionary; optional metadata
        // is null so the candidate contains precisely the reviewed rule. No caller-defined policy.
        api_status(unsafe {
            AuthorizationRightSet(
                authorization.0,
                self.name.as_ptr(),
                definition.as_CFTypeRef(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
            )
        })
    }
    fn remove(&mut self) -> Result<(), Failure> {
        let authorization = self.authorization.as_ref().ok_or(Failure::Api)?;
        // SAFETY: owned authorization and the same generated name, used only after known create
        // success and fresh exact observation in execute(). This is NOT compare-and-delete.
        api_status(unsafe { AuthorizationRightRemove(authorization.0, self.name.as_ptr()) })
    }
}

// Watchdog exits the entire experiment if even an FFI call or stdin blocks. It never attempts
// cleanup: a killed call may already have changed the database. The durable intent remains unknown.
struct Watchdog(mpsc::Sender<()>);
impl Drop for Watchdog {
    fn drop(&mut self) {
        let _ = self.0.send(());
    }
}
fn watchdog() -> Result<Watchdog, Failure> {
    let (tx, rx) = mpsc::channel();
    std::thread::Builder::new().name("experiment-deadline".into()).spawn(move || {
        if deadline_expired(rx, Duration::from_secs(DEADLINE_SECONDS)) {
            eprintln!("deadline exceeded; effects unknown; quarantine environment; no automatic cleanup");
            std::process::exit(3);
        }
    }).map_err(|_| Failure::Api)?;
    Ok(Watchdog(tx))
}
fn deadline_expired(rx: mpsc::Receiver<()>, duration: Duration) -> bool {
    matches!(
        rx.recv_timeout(duration),
        Err(mpsc::RecvTimeoutError::Timeout)
    )
}

fn os_build() -> Result<String, Failure> {
    let key = CString::new("kern.osversion").unwrap();
    let mut bytes = [0_u8; 128];
    let mut size = bytes.len();
    // SAFETY: fixed sysctl key, bounded writable output and length; no new value (read-only).
    if unsafe {
        libc::sysctlbyname(
            key.as_ptr(),
            bytes.as_mut_ptr().cast(),
            &mut size,
            ptr::null_mut(),
            0,
        )
    } != 0
        || size == 0
        || size > bytes.len()
        || bytes[size - 1] != 0
    {
        return Err(Failure::Api);
    }
    String::from_utf8(bytes[..size - 1].to_vec()).map_err(|_| Failure::Api)
}

fn binary_digest() -> Result<String, Failure> {
    let mut file =
        File::open(std::env::current_exe().map_err(|_| Failure::Api)?).map_err(|_| Failure::Api)?;
    let mut hash = Sha256::new();
    io::copy(&mut file, &mut hash).map_err(|_| Failure::Api)?;
    Ok(hex::encode(hash.finalize()))
}

fn private_directory() -> Result<File, Failure> {
    let dir = File::open(".").map_err(|_| Failure::Journal)?;
    let metadata = dir.metadata().map_err(|_| Failure::Journal)?;
    // SAFETY: getuid/geteuid have no preconditions or side effects.
    let (uid, effective) = unsafe { (libc::getuid(), libc::geteuid()) };
    if uid == 0
        || effective != uid
        || metadata.uid() != uid
        || metadata.permissions().mode() & 0o777 != 0o700
        || !metadata.is_dir()
    {
        return Err(Failure::Journal);
    }
    // SAFETY: live directory FD. This lock excludes only cooperating runs in this directory,
    // not external database writers; isolation is still an operator precondition.
    if unsafe { libc::flock(dir.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(Failure::Journal);
    }
    Ok(dir)
}

fn read_approval(reader: impl BufRead) -> Result<Approval, Failure> {
    let mut bytes = Vec::new();
    reader
        .take(4097)
        .read_until(b'\n', &mut bytes)
        .map_err(|_| Failure::Api)?;
    if bytes.len() > 4096 || !bytes.ends_with(b"\n") {
        return Err(Failure::Api);
    }
    serde_json::from_slice(&bytes).map_err(|_| Failure::Api)
}

pub(super) fn run() -> ExitCode {
    if !io::stdin().is_terminal()
        || !io::stdout().is_terminal()
        || !io::stderr().is_terminal()
        || std::env::var_os("CI").is_some()
    {
        eprintln!("refused: private interactive terminal required; CI cannot run this experiment");
        return ExitCode::from(2);
    }
    let result = prepare_and_execute();
    match result {
        Ok(()) => {
            println!("base case verified; no Gate I/H or restore evidence claimed");
            ExitCode::SUCCESS
        }
        Err(Stop::Refused) => {
            eprintln!("experiment refused; no database mutation attempted");
            ExitCode::from(2)
        }
        Err(Stop::Quarantine {
            primary,
            journal_failed,
        }) => {
            eprintln!("experiment stopped: {primary:?}; journal_failed={journal_failed}; quarantine environment; no automatic cleanup");
            ExitCode::from(3)
        }
    }
}

fn prepare_and_execute() -> Result<(), Stop> {
    let _watchdog = watchdog().map_err(|_| Stop::Refused)?;
    let start = Instant::now();
    let dir = private_directory().map_err(|_| Stop::Refused)?;
    let digest = binary_digest().map_err(|_| Stop::Refused)?;
    let build = os_build().map_err(|_| Stop::Refused)?;
    let mut entropy = [0_u8; 16];
    // SAFETY: null selects the default secure RNG; output has exactly the requested capacity.
    if unsafe { SecRandomCopyBytes(ptr::null(), entropy.len(), entropy.as_mut_ptr()) } != 0 {
        return Err(Stop::Refused);
    }
    let name = TestName::from_entropy(entropy);
    println!("PRIVATE operator challenge (do not publish): {}\nBinary SHA-256: {digest}\nOS build: {build}\nDeadline: {DEADLINE_SECONDS}s including input.\nConfirm only in the approved disposable environment with tested whole-environment restore,\ncontrolled writers, reviewed binary and permission for authorization interaction.\nEnter the single-line approval JSON described in the protocol; otherwise abort now.", name.as_str());
    io::stdout().flush().map_err(|_| Stop::Refused)?;
    let approval = read_approval(io::stdin().lock()).map_err(|_| Stop::Refused)?;
    if !approval.validate(&name, &digest, &build) {
        return Err(Stop::Refused);
    }
    let mut journal = Journal::create(&dir).map_err(|_| Stop::Refused)?;
    journal.append(&approval).map_err(|_| Stop::Refused)?;
    let mut adapter = NativeAdapter {
        name: CString::new(name.as_str()).map_err(|_| Stop::Refused)?,
        authorization: None,
        journal,
        start,
    };
    let result = execute(&mut adapter);
    if adapter.journal.append(&result).is_err() {
        return Err(match result {
            Err(Stop::Quarantine { primary, .. }) => Stop::Quarantine {
                primary,
                journal_failed: true,
            },
            _ => Stop::Quarantine {
                primary: Failure::Journal,
                journal_failed: true,
            },
        });
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, OpenOptions};
    use std::os::unix::fs::OpenOptionsExt;

    #[test]
    fn native_write_status_denied_is_never_absence() {
        assert_eq!(api_status(-60005), Err(Failure::Denied));
        assert_eq!(api_status(-60006), Err(Failure::Canceled));
        assert_eq!(api_status(-60007), Err(Failure::InteractionNotAllowed));
        assert_eq!(api_status(0), Ok(()));
        assert_eq!(api_status(42), Err(Failure::Api));
    }
    #[test]
    fn watchdog_distinguishes_cancel_and_deadline_without_native_calls() {
        let (tx, rx) = mpsc::channel();
        tx.send(()).unwrap();
        assert!(!deadline_expired(rx, Duration::ZERO));
        let (_tx, rx) = mpsc::channel();
        assert!(deadline_expired(rx, Duration::ZERO));
    }
    #[test]
    fn bounded_approval_rejects_missing_newline_oversize_and_unknown_fields() {
        let valid = serde_json::json!({
            "environment": "fixture", "os_build": "fixture", "sdk": "fixture",
            "reviewed_commit": "a".repeat(40), "reviewed_sha256": "b".repeat(64),
            "restore_evidence": "fixture", "disposable": true, "restore_tested": true,
            "exclusive_writers": true, "allow_authorization_interaction": true,
            "confirmation": "fixture"
        });
        let encoded = format!("{valid}\n");
        assert!(read_approval(io::Cursor::new(encoded.as_bytes())).is_ok());
        let mut unknown = valid.clone();
        unknown["extra"] = true.into();
        assert!(read_approval(io::Cursor::new(format!("{unknown}\n"))).is_err());
        let mut missing = valid;
        missing.as_object_mut().unwrap().remove("disposable");
        assert!(read_approval(io::Cursor::new(format!("{missing}\n"))).is_err());
        for bytes in [b"{}".to_vec(), b"{}\n".to_vec(), vec![b'a'; 4097]] {
            assert!(read_approval(io::Cursor::new(bytes)).is_err());
        }
    }
    #[test]
    fn journal_is_private_exclusive_bounded_and_not_resumable() {
        let root = std::env::temp_dir().join(format!(
            "novaray-journal-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&root).unwrap();
        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(root.clone());
        let directory = File::open(&root).unwrap();
        let mut journal = Journal::create(&directory).unwrap();
        assert_eq!(
            journal.file.metadata().unwrap().permissions().mode() & 0o777,
            0o600
        );
        journal.append(&Record::CreateIntent).unwrap();
        assert!(Journal::create(&directory).is_err());
        assert!(journal.append(&"x".repeat(16_384)).is_err());
        journal.bytes = 65_536;
        assert!(journal.append(&Record::CreateIntent).is_err());
        drop(journal);
        let path = root.join("native-right-roundtrip.jsonl");
        assert_eq!(fs::read_to_string(&path).unwrap(), "\"CreateIntent\"\n");
        fs::remove_file(&path).unwrap();
        let target = root.join("untouched");
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&target)
            .unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(Journal::create(&directory).is_err());
        assert_eq!(fs::metadata(&target).unwrap().len(), 0);
    }
}
