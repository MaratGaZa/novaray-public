---
name: add-rest-endpoint
description: Спроектировать явно одобренный локальный HTTP control API NovaRay с authentication, bounded schemas и безопасной границей к Rust core. Не использовать для обычного Swift-Rust FFI или IPC.
---

# Skill: add-rest-endpoint

NovaRay сейчас не имеет REST server, и HTTP API не входит в утверждённую базовую архитектуру. Этот
skill запускается только по явному запросу на HTTP/REST endpoint.

## Шаги

1. До кода применить `add-spec` и `add-adr`: обосновать, почему FFI/XPC/Unix socket недостаточны,
   кто клиент, каков threat model и должен ли API существовать в release.
2. Зафиксировать bind address (по умолчанию только loopback), authentication, authorization,
   CSRF/origin policy для browser-клиента, lifecycle, port conflicts и shutdown.
3. Определить versioned request/response schemas с size/count/time bounds. Не принимать shell-команды,
   пути к произвольным файлам или необработанную privileged configuration.
4. Route handler должен быть тонким adapter к application core. Не возвращать raw errors, secrets,
   server UUID/IP, filesystem paths или diagnostic internals.
5. Добавить tests: auth required, malformed/oversized input, forbidden operation, safe error,
   concurrency/rate bound и clean shutdown.
6. Выполнить security review и проверки `AGENTS.md`; не открывать LAN listener без отдельного решения.

## Checklist

- [ ] REST действительно утверждён SPEC и ADR.
- [ ] Loopback/auth/CSRF и limits определены.
- [ ] Endpoint не расширяет privileged API.
- [ ] Ошибки и логи redacted.
- [ ] Негативные security tests существуют.
