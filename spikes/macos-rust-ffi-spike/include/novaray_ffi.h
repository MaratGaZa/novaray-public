#ifndef NOVARAY_FFI_H
#define NOVARAY_FFI_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NOVARAY_FFI_ABI_VERSION 1u
#define NOVARAY_FFI_RESULT_OK 0
#define NOVARAY_FFI_RESULT_NULL_CALLBACK 1
#define NOVARAY_OBSERVED_STATE_READY 1u

typedef struct NovaRayStateEvent {
    uint32_t abi_version;
    uint32_t state;
    uint64_t sequence;
} NovaRayStateEvent;

typedef void (*NovaRayStateCallback)(const NovaRayStateEvent *event, void *context);

uint32_t novaray_ffi_abi_version(void);
int32_t novaray_ffi_roundtrip(
    uint64_t sequence,
    NovaRayStateCallback callback,
    void *context
);

#ifdef __cplusplus
}
#endif

#endif
