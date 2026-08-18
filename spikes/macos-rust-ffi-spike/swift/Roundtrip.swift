import NovaRayFFI

private final class EventCapture {
    var abiVersion: UInt32?
    var state: UInt32?
    var sequence: UInt64?
}

private let sequence: UInt64 = 42
private let capture = EventCapture()
private let context = Unmanaged.passUnretained(capture).toOpaque()

private let result = novaray_ffi_roundtrip(
    sequence,
    { event, rawContext in
        guard let event, let rawContext else {
            return
        }

        let capture = Unmanaged<EventCapture>.fromOpaque(rawContext).takeUnretainedValue()
        capture.abiVersion = event.pointee.abi_version
        capture.state = event.pointee.state
        capture.sequence = event.pointee.sequence
    },
    context
)

precondition(result == NOVARAY_FFI_RESULT_OK, "Rust roundtrip returned \(result)")
precondition(novaray_ffi_abi_version() == NOVARAY_FFI_ABI_VERSION)
precondition(capture.abiVersion == NOVARAY_FFI_ABI_VERSION)
precondition(capture.state == NOVARAY_OBSERVED_STATE_READY)
precondition(capture.sequence == sequence)

print(
    "NovaRay FFI roundtrip OK: ABI \(capture.abiVersion!), "
        + "state \(capture.state!), sequence \(capture.sequence!)"
)
