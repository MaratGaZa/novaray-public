//! Engine-neutral configuration generation strategy.
use crate::config::{ServerProfile, UserSettings};
use crate::sing_box_generator::SingBoxConfigGenerator;
use crate::xray_generator::XrayConfigGenerator;
use serde_json::Value;

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

    pub fn preflight_args(self, config_path: &str) -> Vec<&str> {
        match self {
            Self::Xray => vec!["run", "-test", "-c", config_path],
            Self::SingBox => vec!["check", "-c", config_path],
        }
    }

    pub fn run_args(self, config_path: &str) -> Vec<&str> {
        match self {
            Self::Xray => vec!["run", "-c", config_path],
            Self::SingBox => vec!["run", "-c", config_path],
        }
    }
}
