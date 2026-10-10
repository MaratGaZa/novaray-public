//! Bounded, synthetic property evidence, not an exhaustive fuzzing or memory-safety proof.
use novaray_core::parser::VlessParser;
use proptest::prelude::*;
use proptest::test_runner::{Config, RngAlgorithm, RngSeed, TestCaseResult, TestRunner};

const SEEDS: [u64; 3] = [
    0x4e4f_5641_5241_5901,
    0x4e4f_5641_5241_5902,
    0x4e4f_5641_5241_5903,
];
const URI_LIMIT: usize = 16_384;
const USER: &str = "00000000-0000-4000-8000-000000000001";
const KEY: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
// Intentionally independent of the production key list and error construction.
const CRITICAL: [&str; 14] = [
    "flow",
    "security",
    "type",
    "headerType",
    "sni",
    "pbk",
    "sid",
    "fp",
    "encryption",
    "host",
    "path",
    "serviceName",
    "authority",
    "mode",
];

fn check<S: Strategy>(strategy: S, property: impl Fn(S::Value) -> TestCaseResult) {
    for seed in SEEDS {
        let config = Config {
            cases: 128,
            max_shrink_iters: 2048,
            failure_persistence: None,
            rng_algorithm: RngAlgorithm::ChaCha,
            rng_seed: RngSeed::Fixed(seed),
            ..Config::default()
        };
        TestRunner::new(config)
            .run(&strategy, &property)
            .unwrap_or_else(|error| {
                panic!("synthetic parser property failed; seed={seed}: {error}")
            });
    }
}

fn encoded(value: &str) -> String {
    value.bytes().map(|byte| format!("%{byte:02X}")).collect()
}

fn text() -> impl Strategy<Value = String> {
    prop::collection::vec(any::<char>(), 0..128).prop_map(|chars| chars.into_iter().collect())
}

fn allowed_error(message: &str) -> bool {
    const STATIC: [&str; 12] = [
        "VLESS URI превышает лимит 16 KiB",
        "Некорректный формат URI",
        "Ожидалась схема 'vless://'",
        "UUID не может быть пустым",
        "Хост сервера отсутствует в URI",
        "Порт сервера отсутствует в URI",
        "Недопустимое имя query-параметра",
        "Неподдерживаемый параметр 'headerType': поддерживается только 'none'",
        "Ошибка параметра 'flow': Неподдерживаемый тип flow",
        "Ошибка параметра 'security': Неподдерживаемый тип безопасности",
        "Ошибка параметра 'type': неподдерживаемый транспорт VLESS",
        "Ошибка валидации профиля VLESS",
    ];
    STATIC.contains(&message)
        || message == "Неподдерживаемый gRPC mode: поддерживается только 'gun'"
        || ["authority", "serviceName"]
            .iter()
            .any(|key| message == format!("Параметр '{key}' применим только к type=grpc"))
        || ["host", "path"].iter().any(|key| {
            message == format!("Конфликтующие значения transport-параметров для '{key}'")
        })
        || CRITICAL.iter().any(|key| {
            message == format!("Повтор критичного query-параметра '{key}'")
                || message == format!("Пробелы в имени query-параметра: ожидается '{key}'")
                || message == format!("Некорректный регистр query-параметра: ожидается '{key}'")
        })
}

fn safe_error(error: &anyhow::Error) -> TestCaseResult {
    let display = error.to_string();
    prop_assert!(allowed_error(&display));
    prop_assert_eq!(error.chain().count(), 1);
    prop_assert_eq!(&format!("{error:#}"), &display);
    // anyhow Debug may append a backtrace, but its message must stay static.
    let debug = format!("{error:?}");
    prop_assert_eq!(debug.lines().next(), Some(display.as_str()));
    prop_assert!(!debug.to_ascii_lowercase().contains("private-"));
    Ok(())
}

#[test]
fn arbitrary_bounded_utf8_is_total_deterministic_and_errors_are_static() {
    let inputs = prop_oneof![
        text(),
        text().prop_map(|query| format!("vless://{USER}@edge.example:443?{query}")),
        (any::<char>(), 0usize..17_000).prop_map(|(ch, count)| ch.to_string().repeat(count)),
    ];
    check(inputs, |input| {
        let first = VlessParser::parse_uri(&input);
        let second = VlessParser::parse_uri(&input);
        match (first, second) {
            (Ok(a), Ok(b)) => {
                prop_assert!(input.len() <= URI_LIMIT);
                prop_assert!(a.validate().is_ok());
                prop_assert_eq!(a, b);
            }
            (Err(a), Err(b)) => {
                prop_assert_eq!(a.to_string(), b.to_string());
                safe_error(&a)?;
            }
            _ => prop_assert!(false, "same input changed outcome"),
        }
        Ok(())
    });
}

#[test]
fn generated_value_failures_never_reflect_normalized_or_original_data() {
    check("[a-zA-Z0-9]{1,24}", |suffix| {
        let marker = format!("PRIVATE-{suffix}");
        let base = format!("vless://{marker}@private-host.example:443");
        let queries = [
            format!("flow={marker}"),
            format!("security={marker}"),
            format!("type={marker}"),
            format!("headerType={marker}"),
            format!("type=grpc&mode={marker}"),
            format!("type=ws&path={marker}"),
            format!("security=reality&pbk={marker}"),
            format!("type=grpc&host=a&authority={marker}"),
            format!("type=ws&path=%2Fws&flow=xtls-rprx-vision&security=tls&fp={marker}"),
        ];
        for query in queries {
            let error = VlessParser::parse_uri(&format!("{base}?{query}#{marker}")).unwrap_err();
            safe_error(&error)?;
        }
        let error =
            VlessParser::parse_uri(&format!("{marker}://{USER}@edge.example:443")).unwrap_err();
        safe_error(&error)
    });
}

#[test]
fn generated_valid_uris_preserve_identity_under_supported_rewrites() {
    check(
        (any::<u32>(), 1u16..=u16::MAX, "[a-z]{1,16}", any::<bool>()),
        |(tail, port, label, grpc)| {
            let user = format!("00000000-0000-4000-8000-{tail:012x}");
            let server = format!("{label}.example");
            let transport = if grpc { "grpc" } else { "tcp" };
            let mut query = vec![
                ("security", "reality".to_string()),
                ("sni", "front.example".to_string()),
                ("pbk", KEY.to_string()),
                ("sid", "a0b1".to_string()),
                ("fp", "chrome".to_string()),
                ("type", transport.to_string()),
            ];
            if grpc {
                query.push(("serviceName", label.clone()));
                query.push(("authority", "front.example".to_string()));
            }
            let original: Vec<_> = query.iter().map(|(k, v)| format!("{k}={v}")).collect();
            let rewritten: Vec<_> = query
                .iter()
                .rev()
                .map(|(k, v)| {
                    let v = match *k {
                        "sni" | "sid" | "fp" | "authority" => v.to_ascii_uppercase(),
                        _ => v.clone(),
                    };
                    format!("{}={}", encoded(k), encoded(&v))
                })
                .collect();
            let a = VlessParser::parse_uri(&format!(
                "vless://{user}@{server}:{port}?{}#node",
                original.join("&")
            ))
            .unwrap();
            let b = VlessParser::parse_uri(&format!(
                "vless://{}@{}:{port}?{}#node",
                user.to_ascii_uppercase(),
                server.to_ascii_uppercase(),
                rewritten.join("&")
            ))
            .unwrap();
            prop_assert_eq!(&a, &b);
            let renamed = VlessParser::parse_uri(&format!(
                "vless://{user}@{server}:{port}?{}#other",
                original.join("&")
            ))
            .unwrap();
            prop_assert_eq!(&a.id, &renamed.id);
            prop_assert_ne!(&a.name, &renamed.name);
            Ok(())
        },
    );
}

#[test]
fn generated_duplicates_precede_invalid_values_for_every_critical_key() {
    check((text(), text(), any::<bool>()), |(left, right, reverse)| {
        for key in CRITICAL {
            let pairs = [
                format!("{key}={}", encoded(&left)),
                format!("{}={}", encoded(&format!(" {key}\t")), encoded(&right)),
            ];
            let query = if reverse {
                format!("{}&{}", pairs[1], pairs[0])
            } else {
                pairs.join("&")
            };
            // Empty user proves that name validation precedes credential/value interpretation.
            let error =
                VlessParser::parse_uri(&format!("vless://@edge.example:443?{query}")).unwrap_err();
            prop_assert_eq!(
                error.to_string(),
                format!("Повтор критичного query-параметра '{key}'")
            );
            safe_error(&error)?;
        }
        Ok(())
    });
}

#[test]
fn generated_invalid_unknown_names_fail_before_values() {
    let forbidden = prop_oneof![0u32..=31, 127u32..0x11_0000]
        .prop_map(|codepoint| char::from_u32(codepoint).unwrap_or('\0'));
    check(
        ("[a-z0-9_-]{1,12}", forbidden, text()),
        |(label, bad, value)| {
            let label = format!("unknown_{label}");
            // Unknown names cannot be silently ignored merely because they are not critical.
            for name in [
                format!("{bad}{label}"),
                format!("{label}{bad}"),
                format!("a{bad}{label}"),
            ] {
                let error = VlessParser::parse_uri(&format!(
                    "vless://@edge.example:443?{}={}",
                    encoded(&name),
                    encoded(&value)
                ))
                .unwrap_err();
                prop_assert_eq!(error.to_string(), "Недопустимое имя query-параметра");
                safe_error(&error)?;
            }
            Ok(())
        },
    );
}

#[test]
fn generated_utf8_boundaries_use_original_bytes_before_url_parsing() {
    check(
        (
            prop::sample::select(vec!['a', '\u{e9}', '\u{200b}', '\u{1f642}']),
            1usize..64,
        ),
        |(ch, excess)| {
            let prefix = format!("vless://{USER}@edge.example:443?unknown=");
            let available = URI_LIMIT - prefix.len();
            let mut input = prefix;
            input.push_str(&ch.to_string().repeat(available / ch.len_utf8()));
            input.push_str(&"a".repeat(URI_LIMIT - input.len()));
            prop_assert_eq!(input.len(), URI_LIMIT);
            prop_assert!(VlessParser::parse_uri(&input).is_ok());
            input.push_str(&"a".repeat(excess));
            let error = VlessParser::parse_uri(&input).unwrap_err();
            prop_assert_eq!(error.to_string(), "VLESS URI превышает лимит 16 KiB");
            // Same byte budget with invalid syntax must retain the size error's priority.
            input.replace_range(..5, "[bad]");
            let error = VlessParser::parse_uri(&input).unwrap_err();
            prop_assert_eq!(error.to_string(), "VLESS URI превышает лимит 16 KiB");
            Ok(())
        },
    );
}

#[test]
fn generated_field_boundaries_preserve_distinct_tested_identities() {
    check(
        ("[a-z]{1,12}", "[a-z]{1,12}", "[a-z]{1,12}"),
        |(a, b, c)| {
            let base = format!("vless://{USER}@edge.example:443?");
            let left = VlessParser::parse_uri(&format!(
                "{base}type=grpc&authority={a}%7C{b}&serviceName={c}"
            ))
            .unwrap();
            let right = VlessParser::parse_uri(&format!(
                "{base}type=grpc&authority={a}&serviceName={b}%7C{c}"
            ))
            .unwrap();
            prop_assert_ne!(&left.host, &right.host);
            prop_assert_ne!(&left.path, &right.path);
            prop_assert_ne!(&left.id, &right.id);

            let plain = VlessParser::parse_uri(&format!(
            "{base}type=ws&host=front.example&path=%2F{a}%7Ctls%7Ctls%7Cedge.example%7C%7C&security=none")).unwrap();
            let tls = VlessParser::parse_uri(&format!(
            "{base}type=ws&host=front.example&path=%2F{a}&security=tls&sni=edge.example&sid=none"))
            .unwrap();
            prop_assert!(plain.tls.is_none());
            prop_assert!(tls.tls.is_some());
            prop_assert_ne!(plain.id, tls.id);
            Ok(())
        },
    );
}
