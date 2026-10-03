use novaray_core::parser::{VlessParser, MAX_VLESS_URI_BYTES};

#[test]
fn public_import_bounds_original_bytes_before_parsing() {
    let prefix = "vless://test@edge.example:443#";
    let at_limit = format!("{prefix}{}", "x".repeat(MAX_VLESS_URI_BYTES - prefix.len()));
    assert_eq!(at_limit.len(), MAX_VLESS_URI_BYTES);
    VlessParser::parse_uri(&at_limit).expect("exact byte limit remains eligible");

    for oversized in [
        format!("{at_limit}x"),
        format!(
            "{}{}",
            "not a uri PRIVATE-SENTINEL",
            "x".repeat(MAX_VLESS_URI_BYTES)
        ),
        format!(
            "{prefix}{}é",
            "x".repeat(MAX_VLESS_URI_BYTES - prefix.len() - 1)
        ),
    ] {
        let error = VlessParser::parse_uri(&oversized).unwrap_err();
        assert_eq!(error.to_string(), "VLESS URI превышает лимит 16 KiB");
        assert!(error.source().is_none());
    }
}

#[test]
fn public_import_errors_never_echo_uri_controlled_data() {
    let host = "private-host.example";
    let fragment = "PRIVATE-FRAGMENT";
    let uuid = "PRIVATE-UUID";
    let base = format!("vless://{uuid}@{host}:443");
    let cases = [
        format!("not-a-uri-{uuid}@{host}"),
        format!("https://{uuid}@{host}:443#{fragment}"),
        format!("PRIVATE-SCHEME-MARKER://{uuid}@{host}:443#{fragment}"),
        format!("{base}?flow=PRIVATE-FLOW#{fragment}"),
        format!("{base}?security=PRIVATE-SECURITY#{fragment}"),
        format!("{base}?type=PRIVATE-TRANSPORT#{fragment}"),
        format!("{base}?headerType=PRIVATE-HEADER#{fragment}"),
        format!("{base}?type=grpc&serviceName=svc&mode=PRIVATE-MODE#{fragment}"),
        format!("{base}?type=grpc&serviceName=svc&path=PRIVATE-PATH#{fragment}"),
        format!("{base}?security=reality&pbk=PRIVATE-KEY#{fragment}"),
        format!("{base}?security=tls&sni=PRIVATE-SNI?#{fragment}"),
        format!("{base}?Security=PRIVATE-SECURITY#{fragment}"),
    ];
    for uri in cases {
        let error = VlessParser::parse_uri(&uri).unwrap_err();
        let display = error.to_string();
        let alternate = format!("{error:#}");
        let debug = format!("{error:?}");
        assert!(error.source().is_none(), "unexpected source for {display}");
        for rendered in [&display, &alternate, &debug] {
            for marker in [
                "PRIVATE-",
                "private-",
                host,
                uuid,
                fragment,
                "private-host",
                "private-uuid",
            ] {
                assert!(
                    !rendered.contains(marker),
                    "URI data in importer error: {rendered}"
                );
            }
        }
    }
}

#[test]
fn public_profile_validation_errors_hide_identity_and_fragment() {
    let base = "vless://PRIVATE-UUID@private-host.example:443";
    let fragment = "PRIVATE-FRAGMENT";
    let valid = VlessParser::parse_uri(&format!("{base}?type=ws&path=%2Fws#{fragment}"))
        .expect("WebSocket fixture reaches profile validation");
    assert_eq!(valid.name, fragment);
    assert!(valid.id.contains("private-host"));

    let error = VlessParser::parse_uri(&format!(
        "{base}?flow=xtls-rprx-vision&type=ws&path=%2Fws#{fragment}"
    ))
    .unwrap_err();
    assert_eq!(error.to_string(), "Ошибка валидации профиля VLESS");
    assert!(error.source().is_none());
    for rendered in [
        error.to_string(),
        format!("{error:#}"),
        format!("{error:?}"),
    ] {
        for marker in ["PRIVATE-", "private-", &valid.id] {
            assert!(
                !rendered.contains(marker),
                "profile data in importer error: {rendered}"
            );
        }
    }
}

#[test]
fn public_import_rejects_invisible_query_names_without_exposing_uri_data() {
    for pad in [
        "%E2%80%8B",
        "%E2%80%8C",
        "%E2%80%8D",
        "%EF%BB%BF",
        "%C2%AD",
        "%00",
        "%E1%A0%8E",
        "%E2%81%A0",
    ] {
        for query in [
            format!("{pad}security=reality&security=none"),
            format!("security=none&security{pad}=reality"),
            format!("security=reality&sec{pad}urity=none"),
        ] {
            for (credential, host) in [("private-a", "one.example"), ("private-b", "two.example")] {
                let error = VlessParser::parse_uri(&format!(
                    "vless://{credential}@{host}:443?{query}#private-name"
                ))
                .unwrap_err();
                assert_eq!(error.to_string(), "Недопустимое имя query-параметра");
                assert!(error.source().is_none());
            }
        }
    }
}

#[test]
fn public_import_rejects_literal_invisible_names_and_preserves_ascii_aliases() {
    for pad in [
        "\u{200b}", "\u{200c}", "\u{200d}", "\u{feff}", "\u{ad}", "\u{180e}", "\u{2060}",
    ] {
        let error = VlessParser::parse_uri(&format!(
            "vless://private@edge.example:443?security=invalid&{pad}security=reality"
        ))
        .unwrap_err();
        assert_eq!(error.to_string(), "Недопустимое имя query-параметра");
    }

    let profile = VlessParser::parse_uri(
        "vless://test@edge.example:443?type=grpc&host=cdn.example&authority=cdn.example&serviceName=svc&path=svc&unknown_1=a&unknown_1=b",
    )
    .unwrap();
    assert_eq!(profile.host.as_deref(), Some("cdn.example"));
    assert_eq!(profile.path.as_deref(), Some("svc"));
}

#[test]
fn public_import_rejects_security_overrides_without_exposing_uri_data() {
    for query in [
        "security=reality&security=none",
        "security=none&security=reality",
        "security=reality&%73ecurity=none",
        "security=private-invalid-value&security=none",
        "%20security=reality&security=none",
        "security%20=reality&security=none",
        "security=none&+security=reality",
        "%09%73ecurity%0A=reality&security=none",
    ] {
        let mut errors = Vec::new();
        let mut debug_errors = Vec::new();
        for (credential, host, name) in [
            ("test-one", "one.example", "profile-one"),
            ("test-two", "two.example", "profile-two"),
        ] {
            let error =
                VlessParser::parse_uri(&format!("vless://{credential}@{host}:443?{query}#{name}"))
                    .unwrap_err();
            let rendered = format!("{error:#}");
            // anyhow Debug may append a backtrace; it is not the Display contract.
            let debug = format!("{error:?}");
            assert_eq!(debug.lines().next(), Some(rendered.as_str()));
            debug_errors.push(debug);
            errors.push(rendered);
            assert!(error.source().is_none());
        }
        assert_eq!(errors[0], errors[1]);
        assert_eq!(debug_errors[0], debug_errors[1]);
        assert_eq!(errors[0], "Повтор критичного query-параметра 'security'");
    }
}
