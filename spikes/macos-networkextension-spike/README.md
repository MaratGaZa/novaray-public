# macOS SwiftUI & NetworkExtension Spike

## Назначение

Этот спайк создан в рамках **Execution Task 3** (`docs/IMPLEMENTATION_PLAN.md`) и **Gate 0.3** (`learning/05_roadmap_zero_to_hero.md`).

Спайк изолирован от основного production-кода (каталог `spikes/macos-networkextension-spike/`) и предназначен для:
1. Создания реальных macOS Application (`.app`) и System Extension (`.systemextension`) таргетов с корректным встраиванием расширения (`Contents/Library/SystemExtensions/`), `Info.plist` и `entitlements`.
2. Проверки компиляции и линковки через `xcodebuild` под macOS 14+ Apple Silicon (`arm64-apple-macosx14.0`).
3. Проверки строгой конкурентности Swift 6 (`-swift-version 6 -strict-concurrency=complete`) без предупреждений о гонках данных.
4. Проверки связки API `NETunnelProviderManager` и `OSSystemExtensionManager` для управления системным сетевым расширением `NEPacketTunnelProvider`.
5. Сбора фактуры и практических ограничений для принятия **ADR-003 (Network Topology)**.
6. Фиксации разницы между **Gate A** (локальная бесплатная разработка) и **Gate B** (платный Apple Developer Program с правами Network Extensions).

---

## Структура спайка

```
spikes/macos-networkextension-spike/
├── ../../assets/icons/macos/
│   └── NovaRayAssets.xcassets/     # Общий asset catalog с AppIcon для host app
├── NovaRaySpike.xcodeproj/           # Standalone Xcode проект
│   └── project.pbxproj               # Таргеты NovaRaySpikeApp и NovaRayPacketTunnel
├── Package.swift                     # Swift Package манифест (для модульных тестов и проверки Swift 6)
├── README.md                         # Этот документ
├── NovaRaySpikeApp/
│   ├── NovaRaySpikeApp.swift         # SwiftUI App: WindowGroup + MenuBarExtra
│   ├── ContentView.swift             # UI панели управления и диагностический лог
│   ├── TunnelManager.swift           # Менеджер NETunnelProviderManager + OSSystemExtensionRequestDelegate
│   ├── Info.plist                    # Bundle metadata хост-приложения (org.novaray.spike.app)
│   └── NovaRaySpikeApp.entitlements  # Права com.apple.developer.system-extension.install и networkextension
└── NovaRayPacketTunnel/
    ├── main.swift                    # Entrypoint демона системного расширения (startSystemExtensionMode)
    ├── PacketTunnelProvider.swift    # Реализация NEPacketTunnelProvider (IPv4/DNS/MTU/Packet Loop/Typed IPC)
    ├── Info.plist                    # Bundle metadata системного расширения (SYSX / NetworkExtension)
    └── NovaRayPacketTunnel.entitlements # Права com.apple.developer.networking.networkextension
```

Каталог `NovaRayAssets.xcassets` подключён только к target `NovaRaySpikeApp` через Resources build
phase. System Extension не получает пользовательскую app icon. Build setting
`ASSETCATALOG_COMPILER_APPICON_NAME = AppIcon` применяется в Debug и Release.

---

## Ключевые архитектурные решения и защитные механизмы

### 1. Архитектура System Extension vs App Extension (TN3134)
- Для прямой дистрибуции вне Mac App Store (Developer ID) `NEPacketTunnelProvider` **обязан** быть упакован как **System Extension** (`OSSystemExtensionManager`).
- В проекте `NovaRaySpike.xcodeproj` настроена фаза сборки `Embed System Extensions`, копирующая `org.novaray.spike.packettunnel.systemextension` в папку `Contents/Library/SystemExtensions/` внутри `NovaRaySpikeApp.app`.
- Активация System Extension требует вызова `OSSystemExtensionRequest.activationRequest` и подтверждения пользователем в «Настройках системы» (`System Settings -> Privacy & Security -> Allow`).

### 2. Защита от Network Blackhole
- В `PacketTunnelProvider.swift` **не захватывается** дефолтный маршрут (`0.0.0.0/0`) и не перехватывается весь DNS (`""`).
- Включён только изолированный тестовый диапазон `10.8.0.0/24` и тестовый домен `spike.novaray.local`. Это исключает потерю интернет-соединения при тестовом запуске до подключения реального движка Xray/Sing-box.

### 3. Точная фильтрация VPN-менеджера и асинхронный статус
- `TunnelManager` строго фильтрует системные VPN-конфигурации по `providerBundleIdentifier == "org.novaray.spike.packettunnel"`, предотвращая случайное управление чужими VPN (например, Hiddify, WireGuard и др.).
- Статус соединения не устанавливается оптимистично, а наблюдается через системные нотификации `NEVPNStatusDidChange` и свойство `connection.status`.

### 4. Типизированный IPC Allowlist
- Метод `handleAppMessage` в `PacketTunnelProvider` принимает только строго валидированный JSON (`getStatus`, `ping`) с ограничением размера до 4096 байт и не выводит произвольные полезные нагрузки в системные логи.

### 5. Swift 6 Strict Concurrency и границы статической проверки
- Код провайдера и менеджера туннеля компилируется компилятором Swift 6 со строгой проверкой многопоточности (`-swift-version 6 -strict-concurrency=complete`) без ошибок и предупреждений.
- **Архитектурное допущение:** использование мостов `@unchecked Sendable` (`TunnelState`), `nonisolated(unsafe)` и `@preconcurrency` для Objective-C фреймворков Apple является необходимым обходом на границе системных API. Фактическая потокобезопасность этих мостов остаётся архитектурным допущением до подтверждения в runtime на этапе Gate B.

---

## Сборка и верификация спайка

### 1. Сборка `.app` и встроенного `.systemextension` через `xcodebuild`:
```bash
cd spikes/macos-networkextension-spike
xcodebuild -project NovaRaySpike.xcodeproj -target NovaRaySpikeApp -configuration Debug CODE_SIGNING_ALLOWED=NO build
```

Сборка должна создать `NovaRaySpikeApp.app/Contents/Resources/AppIcon.icns` и добавить
`CFBundleIconName = AppIcon` в итоговый bundle `Info.plist`. CI проверяет оба условия после unsigned
arm64 build.

### 2. Проверка строгой конкурентности Swift 6 через SwiftPM:
```bash
cd spikes/macos-networkextension-spike
swift build --triple arm64-apple-macosx14.0 -Xswiftc -swift-version -Xswiftc 6 -Xswiftc -strict-concurrency=complete
```
