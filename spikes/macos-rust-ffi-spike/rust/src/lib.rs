use std::ffi::c_void;

pub const NOVARAY_FFI_ABI_VERSION: u32 = 1;

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NovaRayObservedState {
    Ready = 1,
}

#[repr(i32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NovaRayFfiResult {
    Ok = 0,
    NullCallback = 1,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NovaRayStateEvent {
    pub abi_version: u32,
    pub state: u32,
    pub sequence: u64,
}

pub type NovaRayStateCallback =
    unsafe extern "C" fn(event: *const NovaRayStateEvent, context: *mut c_void);

#[no_mangle]
pub extern "C" fn novaray_ffi_abi_version() -> u32 {
    NOVARAY_FFI_ABI_VERSION
}

/// Performs a synchronous Swift-to-Rust-to-Swift contract roundtrip.
///
/// # Safety
///
/// When `callback` is present, it must be valid to call with `context`. The event pointer passed to
/// the callback is valid only for the duration of that callback invocation.
#[no_mangle]
pub unsafe extern "C" fn novaray_ffi_roundtrip(
    sequence: u64,
    callback: Option<NovaRayStateCallback>,
    context: *mut c_void,
) -> i32 {
    let Some(callback) = callback else {
        return NovaRayFfiResult::NullCallback as i32;
    };

    let event = NovaRayStateEvent {
        abi_version: NOVARAY_FFI_ABI_VERSION,
        state: NovaRayObservedState::Ready as u32,
        sequence,
    };

    unsafe { callback(&event, context) };
    NovaRayFfiResult::Ok as i32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct CallbackCapture {
        event: Option<NovaRayStateEvent>,
    }

    unsafe extern "C" fn capture_event(event: *const NovaRayStateEvent, context: *mut c_void) {
        assert!(!event.is_null());
        assert!(!context.is_null());

        let capture = unsafe { &mut *context.cast::<CallbackCapture>() };
        capture.event = Some(unsafe { *event });
    }

    #[test]
    fn reports_versioned_observed_state_through_callback() {
        let mut capture = CallbackCapture::default();

        let result = unsafe {
            novaray_ffi_roundtrip(
                42,
                Some(capture_event),
                (&mut capture as *mut CallbackCapture).cast(),
            )
        };

        assert_eq!(result, NovaRayFfiResult::Ok as i32);
        assert_eq!(
            capture.event,
            Some(NovaRayStateEvent {
                abi_version: NOVARAY_FFI_ABI_VERSION,
                state: NovaRayObservedState::Ready as u32,
                sequence: 42,
            })
        );
    }

    #[test]
    fn rejects_missing_callback_without_dereferencing_context() {
        let result = unsafe { novaray_ffi_roundtrip(42, None, std::ptr::null_mut()) };

        assert_eq!(result, NovaRayFfiResult::NullCallback as i32);
    }

    #[test]
    fn c_layout_is_stable_for_version_one() {
        assert_eq!(std::mem::size_of::<NovaRayStateEvent>(), 16);
        assert_eq!(std::mem::align_of::<NovaRayStateEvent>(), 8);
    }
}
