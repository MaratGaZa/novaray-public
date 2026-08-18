# Security Policy

NovaRay is a pre-alpha network-security project. This policy applies to the public source repository
and its current `main` branch.

## Supported versions

NovaRay has no production release yet.

| Version | Security support |
|---|---|
| Current public `main` branch | Best-effort security fixes |
| Older commits, branches and experimental builds | Not supported |

## Reporting a vulnerability

Do not publish credentials, exploit details, private infrastructure data or an unpatched
vulnerability in a GitHub issue, discussion or pull request.

Use GitHub **Security → Report a vulnerability**. Private Vulnerability Reporting is a mandatory
publication control. If that control is unavailable, contact the repository owner through an
already established private channel without including vulnerability details in a public message.

Include only the minimum information needed to reproduce the problem:

- affected revision and platform;
- impact and required attacker capabilities;
- bounded reproduction steps or proof of concept;
- whether credentials, routes, DNS, firewall state or privileged components are involved;
- suggested mitigation, if known.

Never attach live VPN profiles, tokens, certificates, provisioning profiles, private keys, personal
IP addresses or unsanitized diagnostic bundles.

## Response process

The maintainer will attempt to acknowledge a report within five business days. Validation,
remediation and disclosure timing depend on severity and reproducibility. A coordinated disclosure
date must be agreed before public details are released.

For a confirmed credential exposure, response order is:

1. revoke or rotate the credential;
2. contain access and preserve minimal redacted evidence;
3. remove the value from the current tree and applicable history;
4. verify remote caches, pull-request refs and release artifacts;
5. publish a sanitized incident note when appropriate.

History rewriting or deleting a file is not credential revocation.

## Repository data policy

The following data MUST NOT be committed, even to examples, tests, logs, generated build output or
documentation:

- live API keys, access tokens, cookies or passwords;
- live VLESS/VPN UUIDs, Reality keys, short IDs or subscription links;
- personal VPN endpoints, private domains or infrastructure addresses;
- private SSH configuration, keys or local host inventory;
- signing certificates, provisioning profiles or signing keychain exports;
- `.env` files other than a value-free `.env.example`;
- generated Xcode/Cargo build metadata that captures the developer environment;
- unsanitized absolute paths, usernames or diagnostic bundles.

Public fixtures MUST use documentation-only values such as `example.com`, RFC 5737 IPv4 ranges,
`2001:db8::/32`, and credentials generated exclusively for tests. A syntactically valid UUID is not
automatically safe: it must be demonstrably non-production. See
[`docs/TEST_FIXTURES.md`](./docs/TEST_FIXTURES.md).

## Pull requests and CI

- Pull-request workflows use least-privilege `GITHUB_TOKEN` permissions.
- Workflows for fork pull requests MUST NOT expose repository or environment secrets; the effective
  workflow permissions and triggers are reviewed before publication.
- `pull_request_target` must not execute or checkout untrusted contributor code.
- Third-party actions are pinned to immutable full commit SHAs.
- Build, cache and artifact retention is bounded.
- Secret and public-surface scans run before publication and for security-sensitive changes.
- Signing and privileged-runner credentials are absent from ordinary pull-request CI.

## Scope and safe research

Good-faith testing must avoid accessing other users' data, persistent disruption, social
engineering, denial of service and modification of real network state outside an isolated test
environment. Stop when sensitive data is encountered and report it privately.

This policy does not promise a bug bounty or authorize testing against infrastructure not owned by
the reporter.
