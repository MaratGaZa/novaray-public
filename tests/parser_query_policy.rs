use novaray_core::parser::VlessParser;

#[test]
fn public_import_rejects_security_overrides_without_exposing_uri_data() {
    for query in [
        "security=reality&security=none",
        "security=none&security=reality",
        "security=reality&%73ecurity=none",
        "security=private-invalid-value&security=none",
    ] {
        let mut errors = Vec::new();
        for (credential, host, name) in [
            ("test-one", "one.example", "profile-one"),
            ("test-two", "two.example", "profile-two"),
        ] {
            let error =
                VlessParser::parse_uri(&format!("vless://{credential}@{host}:443?{query}#{name}"))
                    .unwrap_err();
            let rendered = format!("{error:#}");
            assert_eq!(format!("{error:?}"), rendered);
            errors.push(rendered);
            assert!(error.source().is_none());
        }
        assert_eq!(errors[0], errors[1]);
        assert_eq!(errors[0], "Повтор критичного query-параметра 'security'");
    }
}
