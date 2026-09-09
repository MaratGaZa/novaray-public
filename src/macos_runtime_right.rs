//! Read-only Security framework boundary for the fixed helper runtime right.
//!
//! Only the existing single-string-rule contract is recognized. System-added fields and rule
//! arrays remain unrecognized until a separate database roundtrip establishes their semantics.
//! Observations are snapshots, not authorization to perform a later database mutation.

use std::ffi::{c_char, CStr, CString};
use std::ptr;

use core_foundation::base::{CFRange, CFType, TCFType};
use core_foundation::dictionary::{CFDictionary, CFDictionaryRef};
use core_foundation::string::{kCFStringEncodingASCII, CFString, CFStringGetBytes};
use thiserror::Error;

use crate::helper_runtime_right::{
    HelperRuntimeAuthorizationRightObservation, HELPER_RUNTIME_AUTHORIZATION_RIGHT_NAME,
    MAX_OBSERVED_RULE_BYTES,
};

const SUCCESS: i32 = 0;
const DEFINITION_NOT_FOUND: i32 = -60005;

#[link(name = "Security", kind = "framework")]
extern "C" {
    fn AuthorizationRightGet(name: *const c_char, definition: *mut CFDictionaryRef) -> i32;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum MacOsRuntimeRightInspectionError {
    #[error("helper runtime authorization right lookup failed")]
    LookupFailed,
    #[error("helper runtime authorization right lookup returned an inconsistent result")]
    InvalidResponse,
}

/// Read the fixed runtime right. No authorization reference or prompt is requested.
pub fn inspect_macos_runtime_right(
) -> Result<HelperRuntimeAuthorizationRightObservation, MacOsRuntimeRightInspectionError> {
    let name = CString::new(HELPER_RUNTIME_AUTHORIZATION_RIGHT_NAME)
        .expect("fixed runtime right name contains no NUL");
    let (status, definition) = read_definition(&name);
    classify_response(status, definition)
}

fn read_definition(name: &CStr) -> (i32, Option<CFType>) {
    let mut raw = ptr::null();
    // SAFETY: name is NUL-terminated and raw is a valid writable output slot. The API returns
    // a retained CFDictionary (AuthorizationDB.h), even though its name ends in Get.
    let status = unsafe { AuthorizationRightGet(name.as_ptr(), &mut raw) };
    let definition = if raw.is_null() {
        None
    } else {
        // SAFETY: the non-null API result is a retained CF object. CFType owns that reference
        // and releases it on every path, including errors; downcasting happens separately.
        Some(unsafe { CFType::wrap_under_create_rule(raw.cast()) })
    };
    (status, definition)
}

fn classify_response(
    status: i32,
    definition: Option<CFType>,
) -> Result<HelperRuntimeAuthorizationRightObservation, MacOsRuntimeRightInspectionError> {
    match (status, definition) {
        (DEFINITION_NOT_FOUND, None) => Ok(HelperRuntimeAuthorizationRightObservation::absent()),
        (SUCCESS, Some(definition)) => Ok(classify_definition(&definition)),
        (SUCCESS, None) | (DEFINITION_NOT_FOUND, Some(_)) => {
            Err(MacOsRuntimeRightInspectionError::InvalidResponse)
        }
        _ => Err(MacOsRuntimeRightInspectionError::LookupFailed),
    }
}

fn classify_definition(definition: &CFType) -> HelperRuntimeAuthorizationRightObservation {
    let unrecognized = HelperRuntimeAuthorizationRightObservation::unrecognized;
    let Some(dictionary) = definition.downcast::<CFDictionary>() else {
        return unrecognized();
    };
    // Reject extra fields before allocating or traversing any keys/values. Do not discard metadata.
    if dictionary.len() != 1 {
        return unrecognized();
    }
    let key = CFString::new("rule");
    let Some(raw_value) = dictionary.find(key.as_CFTypeRef()) else {
        return unrecognized();
    };
    if raw_value.is_null() {
        return unrecognized();
    }
    // SAFETY: this private decoder receives a CF property-list dictionary from Security or
    // CFType-backed test fixtures. The value is a live CF object retained by dictionary.
    let value = unsafe { CFType::wrap_under_get_rule(*raw_value) };
    let Some(rule) = value.downcast::<CFString>() else {
        return unrecognized();
    };
    let length = rule.char_len();
    if length <= 0 || length > MAX_OBSERVED_RULE_BYTES as isize {
        return unrecognized();
    }
    let mut bytes = [0_u8; MAX_OBSERVED_RULE_BYTES];
    let mut used = 0;
    // SAFETY: rule is type-checked, the range covers its bounded UTF-16 length, and the output
    // buffer has the declared capacity. ASCII conversion uses no lossy replacement byte.
    let converted = unsafe {
        CFStringGetBytes(
            rule.as_concrete_TypeRef(),
            CFRange {
                location: 0,
                length,
            },
            kCFStringEncodingASCII,
            0,
            0,
            bytes.as_mut_ptr(),
            bytes.len() as isize,
            &mut used,
        )
    };
    if converted != length || used != length {
        return unrecognized();
    }
    let Ok(rule) = std::str::from_utf8(&bytes[..used as usize]) else {
        return unrecognized();
    };
    HelperRuntimeAuthorizationRightObservation::classify_present(rule, 0)
        .unwrap_or_else(|_| unrecognized())
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_foundation::array::CFArray;
    use core_foundation::boolean::CFBoolean;
    use core_foundation::number::CFNumber;
    use core_foundation::string::CFStringCreateWithCharacters;

    use crate::helper_runtime_right::{
        plan_helper_runtime_right_install, plan_helper_runtime_right_uninstall,
        HelperRuntimeAuthorizationRightInstallPlan as Install,
        HelperRuntimeAuthorizationRightUninstallPlan as Uninstall,
        HELPER_RUNTIME_AUTHORIZATION_RULE,
    };

    fn dictionary(pairs: &[(&str, CFType)]) -> CFType {
        let pairs: Vec<_> = pairs
            .iter()
            .map(|(key, value)| (CFString::new(key), value.clone()))
            .collect();
        CFDictionary::from_CFType_pairs(&pairs).into_CFType()
    }

    fn with_rule(rule: &str) -> CFType {
        dictionary(&[("rule", CFString::new(rule).into_CFType())])
    }

    fn assert_preserved(definition: &CFType) {
        let observed = classify_definition(definition);
        assert!(plan_helper_runtime_right_install(observed).is_err());
        assert!(matches!(
            plan_helper_runtime_right_uninstall(observed),
            Uninstall::PreserveConflictingDefinition { .. }
        ));
    }

    #[test]
    fn cf_exact_single_rule_reaches_owned_planning() {
        let observed = classify_definition(&with_rule(HELPER_RUNTIME_AUTHORIZATION_RULE));
        assert_eq!(
            plan_helper_runtime_right_install(observed),
            Ok(Install::AlreadyOwned)
        );
        assert!(matches!(
            plan_helper_runtime_right_uninstall(observed),
            Uninstall::RemoveOwned { .. }
        ));
    }

    #[test]
    fn cf_extra_fields_are_not_normalized_away() {
        for key in ["class", "version", "timeout", "unknown"] {
            assert_preserved(&dictionary(&[
                (
                    "rule",
                    CFString::new(HELPER_RUNTIME_AUTHORIZATION_RULE).into_CFType(),
                ),
                (key, CFNumber::from(1_i32).into_CFType()),
            ]));
        }
    }

    #[test]
    fn cf_wrong_container_keys_and_value_types_are_preserved() {
        assert_preserved(&CFString::new("not-a-dictionary").into_CFType());
        assert_preserved(&dictionary(&[]));
        assert_preserved(&dictionary(&[(
            "other",
            CFString::new(HELPER_RUNTIME_AUTHORIZATION_RULE).into_CFType(),
        )]));
        assert_preserved(
            &CFDictionary::from_CFType_pairs(&[(
                CFNumber::from(1_i32),
                CFString::new(HELPER_RUNTIME_AUTHORIZATION_RULE),
            )])
            .into_CFType(),
        );
        for value in [
            CFBoolean::true_value().into_CFType(),
            CFNumber::from(1_i32).into_CFType(),
            dictionary(&[]),
            CFArray::from_CFTypes(&[CFString::new(HELPER_RUNTIME_AUTHORIZATION_RULE)])
                .into_CFType(),
        ] {
            assert_preserved(&dictionary(&[("rule", value)]));
        }
    }

    #[test]
    fn cf_invalid_and_nonexact_strings_are_preserved_without_echo() {
        for rule in [
            "",
            "allow",
            "AUTHENTICATE-ADMIN",
            "authenticate-admin ",
            "authenticate-admin\0suffix",
            "foreign-policy\nsecret",
            "\u{00e9}",
            &"a".repeat(MAX_OBSERVED_RULE_BYTES + 1),
        ] {
            let definition = with_rule(rule);
            assert_preserved(&definition);
            let observed = classify_definition(&definition);
            if !rule.is_empty() {
                assert!(!format!("{observed:?}").contains(rule));
            }
        }
    }

    #[test]
    fn cf_invalid_utf16_is_rejected_without_panicking() {
        let characters = [0xd800_u16];
        // SAFETY: a valid one-unit input buffer; CoreFoundation permits unpaired UTF-16 surrogates.
        let raw = unsafe { CFStringCreateWithCharacters(ptr::null(), characters.as_ptr(), 1) };
        assert!(!raw.is_null());
        // SAFETY: ownership of the non-null Create result is transferred to CFString.
        let rule = unsafe { CFString::wrap_under_create_rule(raw) };
        assert_preserved(&dictionary(&[("rule", rule.into_CFType())]));
    }

    #[test]
    fn lookup_statuses_distinguish_absence_errors_and_inconsistent_results() {
        let absent = classify_response(DEFINITION_NOT_FOUND, None).unwrap();
        assert!(matches!(
            plan_helper_runtime_right_install(absent),
            Ok(Install::CreateOwned { .. })
        ));
        assert_eq!(
            classify_response(SUCCESS, None),
            Err(MacOsRuntimeRightInspectionError::InvalidResponse)
        );
        assert_eq!(
            classify_response(DEFINITION_NOT_FOUND, Some(with_rule("secret"))),
            Err(MacOsRuntimeRightInspectionError::InvalidResponse)
        );
        for status in [-60001, -60004, -60007, -60008, 1] {
            for definition in [None, Some(with_rule("secret"))] {
                let error = classify_response(status, definition).unwrap_err();
                assert_eq!(error, MacOsRuntimeRightInspectionError::LookupFailed);
                assert!(!format!("{error:?} {error}").contains("secret"));
            }
        }
    }

    #[test]
    fn native_missing_right_is_absent_without_creation() {
        let name = CString::new(format!(
            "org.novaray.tests.readonly.{}.{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
        .unwrap();
        let (status, definition) = read_definition(&name);
        assert_eq!(status, DEFINITION_NOT_FOUND);
        assert!(definition.is_none());
        let observed = classify_response(status, definition).unwrap();
        assert_eq!(
            plan_helper_runtime_right_uninstall(observed),
            Uninstall::AlreadyAbsent
        );
    }

    #[test]
    fn native_existing_system_right_is_read_and_preserved() {
        let name = CString::new("system.preferences").unwrap();
        let (status, definition) = read_definition(&name);
        assert_eq!(status, SUCCESS);
        let definition = definition.expect("existing system right returns a definition");
        assert!(definition.downcast::<CFDictionary>().is_some());
        assert_preserved(&definition);
    }

    #[test]
    fn native_fixed_runtime_right_inspector_completes() {
        // Presence depends on the host. Do not require or modify a particular database state.
        inspect_macos_runtime_right().expect("read-only fixed runtime right lookup");
    }
}
