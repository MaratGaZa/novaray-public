# macOS Rust C ABI ↔ Swift roundtrip spike

## Назначение

Этот изолированный спайк относится к execution task 4 и issue
development task #9. Он проверяет один критерий Gate A из ADR-001:
Swift 6 на Apple Silicon вызывает Rust static library, а Rust синхронно возвращает типизированное
observed-state event через C callback.

Спайк не является production ABI, не выполняет network mutation, не подключён к
`NEPacketTunnelProvider` и не доказывает работу VPN.

## Контракт версии 1

- `novaray_ffi_abi_version()` возвращает ABI version.
- `novaray_ffi_roundtrip(sequence, callback, context)` возвращает стабильный result code.
- Успешный вызов передаёт `NovaRayStateEvent` с ABI version, observed state и caller sequence.
- Отсутствующий callback отклоняется до обращения к context.
- Event pointer принадлежит Rust и действителен только во время синхронного callback.
- Контракт не передаёт строки, heap allocations, OS handles, secrets или network commands.

Ручной C header намеренно минимален. Выбор генератора bindings, ownership async events, threading,
error mapping, version-range handshake и production ABI остаются следующими архитектурными
решениями.

## Структура

```text
spikes/macos-rust-ffi-spike/
├── include/novaray_ffi.h       # versioned C declarations
├── include/module.modulemap    # Swift Clang module
├── rust/                       # standalone Rust 2021 staticlib crate
├── scripts/run-roundtrip.sh    # reproducible arm64 build/link/run check
└── swift/Roundtrip.swift       # Swift contract harness
```

## Проверка

На Apple Silicon Mac с Rust и Xcode Command Line Tools:

```bash
cargo fmt --manifest-path spikes/macos-rust-ffi-spike/rust/Cargo.toml -- --check
cargo clippy --manifest-path spikes/macos-rust-ffi-spike/rust/Cargo.toml --all-targets --locked -- -D warnings
cargo test --manifest-path spikes/macos-rust-ffi-spike/rust/Cargo.toml --all-targets --locked
./spikes/macos-rust-ffi-spike/scripts/run-roundtrip.sh
```

Ожидаемый финальный вывод roundtrip:

```text
NovaRay FFI roundtrip OK: ABI 1, state 1, sequence 42
```

## Ограничения и rollback

Проверяется только синхронный однопоточный roundtrip на arm64. Спайк не доказывает безопасность
async callback, сохранения context, concurrency, ABI migration, panic containment или runtime внутри
Network/System Extension. Rollback не затрагивает основной core: достаточно удалить этот каталог и
соответствующий CI step.
