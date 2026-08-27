//! Source-level launchd descriptor for the future macOS privileged helper.
//!
//! This module creates a deterministic LaunchDaemon plist for review and tests only. It does not
//! install or load a job, run as root, open IPC sockets, create `utun`, or mutate routes, DNS,
//! firewall, system proxy or packet-flow state.

use std::path::{Path, PathBuf};

use thiserror::Error;

pub const DEFAULT_LAUNCHD_LABEL: &str = "org.novaray.platform-helper";
pub const DEFAULT_HELPER_PROGRAM_PATH: &str =
    "/Library/PrivilegedHelperTools/org.novaray.platform-helper";
pub const MAX_LAUNCHD_LABEL_BYTES: usize = 128;
pub const MAX_LAUNCHD_ARGUMENT_BYTES: usize = 2048;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchdDaemonSpec {
    pub label: String,
    pub program_path: PathBuf,
    pub program_arguments: Vec<String>,
    pub disabled: bool,
    pub run_at_load: bool,
    pub keep_alive: bool,
}

impl LaunchdDaemonSpec {
    pub fn disabled_default() -> Self {
        Self {
            label: DEFAULT_LAUNCHD_LABEL.to_string(),
            program_path: PathBuf::from(DEFAULT_HELPER_PROGRAM_PATH),
            program_arguments: vec![DEFAULT_HELPER_PROGRAM_PATH.to_string()],
            disabled: true,
            run_at_load: false,
            keep_alive: false,
        }
    }

    pub fn validate(&self) -> Result<(), LaunchdDaemonError> {
        validate_label(&self.label)?;
        validate_program_path(&self.program_path)?;

        if self.program_arguments.is_empty() {
            return Err(LaunchdDaemonError::MissingProgramArgument);
        }

        if self.program_arguments[0] != program_path_string(&self.program_path)? {
            return Err(LaunchdDaemonError::ProgramArgumentMismatch);
        }

        for argument in &self.program_arguments {
            validate_argument(argument)?;
        }

        Ok(())
    }

    pub fn to_plist_xml(&self) -> Result<String, LaunchdDaemonError> {
        self.validate()?;

        let mut arguments = String::new();
        for argument in &self.program_arguments {
            arguments.push_str("    <string>");
            arguments.push_str(&escape_plist_string(argument));
            arguments.push_str("</string>\n");
        }

        Ok(format!(
            concat!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
                "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" ",
                "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n",
                "<plist version=\"1.0\">\n",
                "<dict>\n",
                "  <key>Label</key>\n",
                "  <string>{label}</string>\n",
                "  <key>ProgramArguments</key>\n",
                "  <array>\n",
                "{arguments}",
                "  </array>\n",
                "  <key>Disabled</key>\n",
                "  <{disabled}/>\n",
                "  <key>RunAtLoad</key>\n",
                "  <{run_at_load}/>\n",
                "  <key>KeepAlive</key>\n",
                "  <{keep_alive}/>\n",
                "  <key>ProcessType</key>\n",
                "  <string>Background</string>\n",
                "</dict>\n",
                "</plist>\n"
            ),
            label = escape_plist_string(&self.label),
            arguments = arguments,
            disabled = plist_bool(self.disabled),
            run_at_load = plist_bool(self.run_at_load),
            keep_alive = plist_bool(self.keep_alive),
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum LaunchdDaemonError {
    #[error("launchd label must not be empty")]
    EmptyLabel,

    #[error("launchd label exceeds {limit} bytes: {actual}")]
    OversizedLabel { limit: usize, actual: usize },

    #[error("launchd label contains an invalid character")]
    InvalidLabelCharacter,

    #[error("launchd program path must be absolute")]
    RelativeProgramPath,

    #[error("launchd program path must be valid UTF-8")]
    NonUtf8ProgramPath,

    #[error("launchd program path must not point at a shell or command dispatcher")]
    ShellProgramPath,

    #[error("launchd ProgramArguments must include the program path as argv[0]")]
    MissingProgramArgument,

    #[error("launchd ProgramArguments argv[0] must match program_path")]
    ProgramArgumentMismatch,

    #[error("launchd argument must not be empty")]
    EmptyArgument,

    #[error("launchd argument exceeds {limit} bytes: {actual}")]
    OversizedArgument { limit: usize, actual: usize },

    #[error("launchd argument contains a control character")]
    ControlCharacter,
}

fn validate_label(label: &str) -> Result<(), LaunchdDaemonError> {
    if label.is_empty() {
        return Err(LaunchdDaemonError::EmptyLabel);
    }

    let actual = label.len();
    if actual > MAX_LAUNCHD_LABEL_BYTES {
        return Err(LaunchdDaemonError::OversizedLabel {
            limit: MAX_LAUNCHD_LABEL_BYTES,
            actual,
        });
    }

    let mut previous_was_dot = true;
    for byte in label.bytes() {
        let valid = byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-');
        if !valid || (byte == b'.' && previous_was_dot) {
            return Err(LaunchdDaemonError::InvalidLabelCharacter);
        }
        previous_was_dot = byte == b'.';
    }

    if previous_was_dot {
        return Err(LaunchdDaemonError::InvalidLabelCharacter);
    }

    Ok(())
}

fn validate_program_path(path: &Path) -> Result<(), LaunchdDaemonError> {
    let path = program_path_string(path)?;
    if !path.starts_with('/') {
        return Err(LaunchdDaemonError::RelativeProgramPath);
    }

    if path.chars().any(char::is_control) {
        return Err(LaunchdDaemonError::ControlCharacter);
    }

    let file_name = path.rsplit('/').next().unwrap_or_default();
    if matches!(
        file_name,
        "sh" | "bash" | "zsh" | "fish" | "env" | "osascript"
    ) {
        return Err(LaunchdDaemonError::ShellProgramPath);
    }

    Ok(())
}

fn program_path_string(path: &Path) -> Result<&str, LaunchdDaemonError> {
    path.to_str().ok_or(LaunchdDaemonError::NonUtf8ProgramPath)
}

fn validate_argument(argument: &str) -> Result<(), LaunchdDaemonError> {
    if argument.is_empty() {
        return Err(LaunchdDaemonError::EmptyArgument);
    }

    let actual = argument.len();
    if actual > MAX_LAUNCHD_ARGUMENT_BYTES {
        return Err(LaunchdDaemonError::OversizedArgument {
            limit: MAX_LAUNCHD_ARGUMENT_BYTES,
            actual,
        });
    }

    if argument.chars().any(char::is_control) {
        return Err(LaunchdDaemonError::ControlCharacter);
    }

    Ok(())
}

fn plist_bool(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}

fn escape_plist_string(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&apos;"),
            _ => escaped.push(character),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_launchd_descriptor_is_disabled_and_deterministic() {
        let spec = LaunchdDaemonSpec::disabled_default();

        let plist = spec.to_plist_xml().expect("render plist");

        assert!(plist.contains("<string>org.novaray.platform-helper</string>"));
        assert!(plist.contains(
            "<string>/Library/PrivilegedHelperTools/org.novaray.platform-helper</string>"
        ));
        assert!(plist.contains("<key>Disabled</key>\n  <true/>"));
        assert!(plist.contains("<key>RunAtLoad</key>\n  <false/>"));
        assert!(plist.contains("<key>KeepAlive</key>\n  <false/>"));
        assert!(!plist.contains("<key>MachServices</key>"));
        assert!(!plist.contains("/bin/sh"));
        assert!(!plist.contains("route"));
        assert!(!plist.contains("pfctl"));
        assert!(!plist.contains("scutil"));
    }

    #[test]
    fn unsafe_launchd_labels_fail_closed() {
        let mut spec = LaunchdDaemonSpec::disabled_default();

        spec.label = String::new();
        assert_eq!(spec.validate(), Err(LaunchdDaemonError::EmptyLabel));

        spec.label = "org.novaray.platform_helper".to_string();
        assert_eq!(
            spec.validate(),
            Err(LaunchdDaemonError::InvalidLabelCharacter)
        );

        spec.label = "org..novaray".to_string();
        assert_eq!(
            spec.validate(),
            Err(LaunchdDaemonError::InvalidLabelCharacter)
        );
    }

    #[test]
    fn unsafe_program_paths_fail_closed() {
        let mut spec = LaunchdDaemonSpec::disabled_default();

        spec.program_path = PathBuf::from("relative/helper");
        spec.program_arguments[0] = "relative/helper".to_string();
        assert_eq!(
            spec.validate(),
            Err(LaunchdDaemonError::RelativeProgramPath)
        );

        spec.program_path = PathBuf::from("/bin/sh");
        spec.program_arguments[0] = "/bin/sh".to_string();
        assert_eq!(spec.validate(), Err(LaunchdDaemonError::ShellProgramPath));
    }

    #[test]
    fn program_arguments_are_bounded_and_match_program_path() {
        let mut spec = LaunchdDaemonSpec::disabled_default();

        spec.program_arguments.clear();
        assert_eq!(
            spec.validate(),
            Err(LaunchdDaemonError::MissingProgramArgument)
        );

        spec.program_arguments = vec!["/Library/PrivilegedHelperTools/other".to_string()];
        assert_eq!(
            spec.validate(),
            Err(LaunchdDaemonError::ProgramArgumentMismatch)
        );

        spec.program_arguments = vec![
            DEFAULT_HELPER_PROGRAM_PATH.to_string(),
            "bad\nargument".to_string(),
        ];
        assert_eq!(spec.validate(), Err(LaunchdDaemonError::ControlCharacter));
    }

    #[test]
    fn plist_values_are_xml_escaped() {
        let mut spec = LaunchdDaemonSpec::disabled_default();
        spec.program_path = PathBuf::from("/Library/PrivilegedHelperTools/org.novaray.<helper>");
        spec.program_arguments = vec![
            "/Library/PrivilegedHelperTools/org.novaray.<helper>".to_string(),
            "--name=A&B".to_string(),
        ];

        let plist = spec.to_plist_xml().expect("render escaped plist");

        assert!(plist.contains("org.novaray.&lt;helper&gt;"));
        assert!(plist.contains("--name=A&amp;B"));
    }
}
