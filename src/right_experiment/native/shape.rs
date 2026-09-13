//! Bounded structural evidence only. Never serialize policy values or unknown key names.
use core_foundation::array::CFArray;
use core_foundation::base::{CFType, TCFType};
use core_foundation::boolean::CFBoolean;
use core_foundation::data::CFData;
use core_foundation::dictionary::CFDictionary;
use core_foundation::number::CFNumber;
use core_foundation::string::CFString;
use serde::Serialize;

use super::Failure;

#[derive(Debug, Serialize)]
pub(super) enum Shape {
    String { utf16_units: usize },
    Data { bytes: usize },
    Boolean,
    Number,
    Dictionary(Vec<Field>),
    Array(Vec<Shape>),
    Other,
}
#[derive(Debug, Serialize)]
pub(super) struct Field {
    key: Key,
    key_shape: Shape,
    value: Shape,
}
#[derive(Debug, Serialize)]
enum Key {
    Rule,
    Class,
    Version,
    Timeout,
    Created,
    Modified,
    Unknown,
}

pub(super) fn inspect(value: &CFType) -> Result<Shape, Failure> {
    visit(value, 0, &mut 64)
}

fn visit(value: &CFType, depth: usize, remaining: &mut usize) -> Result<Shape, Failure> {
    if depth > 3 || *remaining == 0 {
        return Err(Failure::Inspection);
    }
    *remaining -= 1;
    if let Some(string) = value.downcast::<CFString>() {
        let units = string.char_len();
        if !(0..=128).contains(&units) {
            return Err(Failure::Inspection);
        }
        return Ok(Shape::String {
            utf16_units: units as usize,
        });
    }
    if let Some(data) = value.downcast::<CFData>() {
        let length = data.len();
        if !(0..=1024).contains(&length) {
            return Err(Failure::Inspection);
        }
        return Ok(Shape::Data {
            bytes: length as usize,
        });
    }
    if let Some(dictionary) = value.downcast::<CFDictionary>() {
        if !(0..=16).contains(&dictionary.len()) {
            return Err(Failure::Inspection);
        }
        let (keys, values) = dictionary.get_keys_and_values();
        let mut fields = Vec::with_capacity(keys.len());
        for (key, value) in keys.into_iter().zip(values) {
            if key.is_null() || value.is_null() {
                return Err(Failure::Inspection);
            }
            // SAFETY: Security property-list or CFType-backed test dictionary; both objects are
            // live and retained by the dictionary. Borrowed references receive their own retain.
            let (key, value) = unsafe {
                (
                    CFType::wrap_under_get_rule(key),
                    CFType::wrap_under_get_rule(value),
                )
            };
            let mut known = Key::Unknown;
            if let Some(string) = key.downcast::<CFString>() {
                for (name, category) in [
                    ("rule", Key::Rule),
                    ("class", Key::Class),
                    ("version", Key::Version),
                    ("timeout", Key::Timeout),
                    ("created", Key::Created),
                    ("modified", Key::Modified),
                ] {
                    if string == CFString::new(name) {
                        known = category;
                        break;
                    }
                }
            }
            fields.push(Field {
                key: known,
                key_shape: visit(&key, depth + 1, remaining)?,
                value: visit(&value, depth + 1, remaining)?,
            });
        }
        return Ok(Shape::Dictionary(fields));
    }
    if let Some(array) = value.downcast::<CFArray>() {
        if !(0..=16).contains(&array.len()) {
            return Err(Failure::Inspection);
        }
        let mut items = Vec::with_capacity(array.len() as usize);
        for raw in array.iter() {
            if raw.is_null() {
                return Err(Failure::Inspection);
            }
            // SAFETY: array comes from Security property-list/CFType-backed fixtures and retains
            // this CF object throughout traversal. No raw pointer or value is emitted.
            let item = unsafe { CFType::wrap_under_get_rule(*raw) };
            items.push(visit(&item, depth + 1, remaining)?);
        }
        return Ok(Shape::Array(items));
    }
    if value.downcast::<CFBoolean>().is_some() {
        return Ok(Shape::Boolean);
    }
    if value.downcast::<CFNumber>().is_some() {
        return Ok(Shape::Number);
    }
    Ok(Shape::Other)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn complete_cf_shape_is_bounded_and_redacts_foreign_content() {
        let value = CFDictionary::from_CFType_pairs(&[
            (CFString::new("secret-key"), CFString::new("secret-value")),
            (CFString::new("rule"), CFString::new("authenticate-admin")),
        ])
        .into_CFType();
        let shape = inspect(&value).unwrap();
        let text = serde_json::to_string(&shape).unwrap();
        assert!(!text.contains("secret"));
        assert!(!format!("{shape:?}").contains("authenticate-admin"));
        let Shape::Dictionary(fields) = shape else {
            panic!("dictionary missing")
        };
        assert_eq!(fields.len(), 2);
        assert!(text.contains("Unknown") && text.contains("Rule"));
    }
    #[test]
    fn oversized_and_deep_shapes_fail_instead_of_truncating() {
        assert!(inspect(&CFString::new(&"x".repeat(129)).into_CFType()).is_err());
        assert!(
            inspect(&CFArray::from_CFTypes(&vec![CFString::new("x"); 17]).into_CFType()).is_err()
        );
        let mut value = CFString::new("x").into_CFType();
        for _ in 0..5 {
            value = CFArray::from_CFTypes(&[value]).into_CFType();
        }
        assert!(inspect(&value).is_err());
    }
}
