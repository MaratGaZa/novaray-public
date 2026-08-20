# Engine artifact checksum evidence

The runtime catalog in `src/engine.rs` supports Xray-core `v26.3.27` and sing-box `v1.13.18` on
macOS arm64/x86_64, Linux arm64/x86_64, and Windows x86_64. Other targets have no automatic binary
pin and fail closed unless the caller deliberately supplies `--expected-sha256`.

| Engine | Target | Archive | Archive SHA-256 | Binary path | Binary SHA-256 |
|---|---|---|---|---|---|
| Xray-core | macOS x86_64 | `Xray-macos-64.zip` | `f5b0471d3459eff1b82e48af0aeac186abcc3298210070afbbbd8437a4e8b203` | `xray` | `afd0eaebb77994a18f29b00c5f50a4f7fbb77da06e24352d43035f3cad3c3786` |
| Xray-core | Windows x86_64 | `Xray-windows-64.zip` | `d004c39288ce9ada487c6f398c7c545f7d749e44bdfdd59dbc9f865afba4e1ad` | `xray.exe` | `15c2d007954ac53ba69b80ec91242786b3c0b71d52649165b4ca1d5cc96ef8f1` |
| sing-box | macOS x86_64 | `sing-box-1.13.18-darwin-amd64.tar.gz` | `500f0decfc21f7cdb2aaa4fe193b7857a41b07c38ee3a0b15bd53e3c7af3671c` | `sing-box-1.13.18-darwin-amd64/sing-box` | `6e9749a4b40821bf07d301f099e75d871ea435861c9f5f0ac5687dc18e81b759` |
| sing-box | Linux x86_64 | `sing-box-1.13.18-linux-amd64.tar.gz` | `d34d987ed6ae39ca3760269264fb502b867e5477db45518c829b07776245c495` | `sing-box-1.13.18-linux-amd64/sing-box` | `8cb29c5b743fbda33502a2b6d49cf66ce13f5d1a41fcd0afc53fff17184ccf8e` |

The Xray archive SHA-256 values above match the release `.dgst` assets. All values were reproduced
on macOS arm64 with:

```bash
curl -fsSL -O <official-release-asset-url>
shasum -a 256 <archive>
unzip -q <xray-archive> -d <directory> # or: tar -xzf <sing-box-archive> -C <directory>
shasum -a 256 <extracted-binary>
```

Upstream release pages: [Xray-core v26.3.27](https://github.com/XTLS/Xray-core/releases/tag/v26.3.27)
and [sing-box v1.13.18](https://github.com/SagerNet/sing-box/releases/tag/v1.13.18).

## Versioned catalog maintenance

`engine_catalog.json` is the checked-in runtime source of truth. It records lifecycle status and
both hashes per declared target; runtime uses only each engine's `recommended` version. Maintainers
use `scripts/update_engine_catalog.py` with an explicit asset manifest containing URLs, expected
archive SHA-256 values, and internal binary paths. The tool writes a separate candidate catalog and
evidence document after checking each downloaded archive and hashing its extracted binary. Reviewers
must independently review that candidate; the tool never performs a runtime update or overwrites the
checked-in catalog.
