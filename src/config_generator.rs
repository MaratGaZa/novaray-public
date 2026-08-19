//! Engine-neutral configuration generation strategy.
use crate::config::{ServerProfile, UserSettings};
use crate::sing_box_generator::SingBoxConfigGenerator;
use crate::xray_generator::XrayConfigGenerator;
use serde_json::Value;
use std::ffi::OsString;
use std::path::Path;

/// Supported external engine configuration formats.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum EngineConfigStrategy {
    /// Existing Xray-core JSON contract.
    #[default]
    Xray,
    /// sing-box JSON contract selected by ADR-004 for production direction.
    SingBox,
}

impl EngineConfigStrategy {
    pub fn engine_name(self) -> &'static str {
        match self {
            Self::Xray => "xray-core",
            Self::SingBox => "sing-box",
        }
    }

    pub fn generate(self, profile: &ServerProfile, settings: &UserSettings) -> Value {
        match self {
            Self::Xray => XrayConfigGenerator::generate(profile, settings),
            Self::SingBox => SingBoxConfigGenerator::generate(profile, settings),
        }
    }

    pub fn preflight_args(self, config_path: &Path) -> Vec<OsString> {
        match self {
            Self::Xray => vec![
                OsString::from("run"),
                OsString::from("-test"),
                OsString::from("-c"),
                config_path.as_os_str().to_os_string(),
            ],
            Self::SingBox => vec![
                OsString::from("check"),
                OsString::from("-c"),
                config_path.as_os_str().to_os_string(),
            ],
        }
    }

    pub fn run_args(self, config_path: &Path) -> Vec<OsString> {
        match self {
            Self::Xray | Self::SingBox => vec![
                OsString::from("run"),
                OsString::from("-c"),
                config_path.as_os_str().to_os_string(),
            ],
        }
    }
}
