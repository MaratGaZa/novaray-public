# Public test fixture policy

All network identities in examples and tests are synthetic and MUST NOT be deployed as credentials.

- IPv4 endpoints use RFC 5737 documentation ranges: `192.0.2.0/24`, `198.51.100.0/24` and
  `203.0.113.0/24`; IPv6 examples use `2001:db8::/32`.
- UUIDs use deterministic values from `00000000-0000-4000-8000-000000000001` upward.
- Reality public keys encode deterministic byte sequences (`00..1f` and `20..3f`) solely to exercise
  length and base64url normalization. Short IDs are similarly obvious deterministic hex strings.
- Profile names identify test profiles rather than locations or providers.

## Non-secret Reality SNI allowlist

`gateway.icloud.com` and `dl.google.com` are real public TLS hostnames retained only because Reality
fixtures must exercise syntactically and semantically plausible camouflage destinations. A hostname
in this allowlist is not a NovaRay endpoint, credential, recommendation, ownership claim or statement
of affiliation. Other fixture hostnames use reserved example domains.

Any new fixture value must have documented test-only provenance here. Never copy a live VPN profile,
subscription URI, endpoint, UUID, public key or short ID into the repository.
