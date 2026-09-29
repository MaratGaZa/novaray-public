use novaray_core::parser::VlessParser;

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
