pub(crate) fn ensure_openai_v1_base_url(base_url: &str) -> String {
    let base = base_url.trim_end_matches('/');
    if base.ends_with("/v1") {
        base.to_string()
    } else {
        format!("{}/v1", base)
    }
}

pub(crate) fn openai_compatible_models_url(base_url: &str) -> String {
    let base = base_url.trim_end_matches('/');
    let base = base.strip_suffix("/v1").unwrap_or(base);
    format!("{}/v1/models", base)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ensure_openai_v1_base_url_accepts_bare_or_v1_url() {
        let cases = [
            ("http://localhost:8080", "http://localhost:8080/v1"),
            ("http://localhost:8080/", "http://localhost:8080/v1"),
            ("http://localhost:8080/v1", "http://localhost:8080/v1"),
            ("http://localhost:8080/v1/", "http://localhost:8080/v1"),
            ("https://api.openai.com", "https://api.openai.com/v1"),
            (
                "https://api.groq.com/openai",
                "https://api.groq.com/openai/v1",
            ),
            ("https://openrouter.ai/api", "https://openrouter.ai/api/v1"),
        ];

        for (input, expected) in cases {
            assert_eq!(ensure_openai_v1_base_url(input), expected, "input: {input}");
        }
    }

    #[test]
    fn openai_compatible_models_url_accepts_bare_or_v1_url() {
        let cases = [
            ("http://localhost:8080", "http://localhost:8080/v1/models"),
            ("http://localhost:8080/", "http://localhost:8080/v1/models"),
            (
                "http://localhost:8080/v1",
                "http://localhost:8080/v1/models",
            ),
            (
                "http://localhost:8080/v1/",
                "http://localhost:8080/v1/models",
            ),
            (
                "https://api.groq.com/openai",
                "https://api.groq.com/openai/v1/models",
            ),
            (
                "https://openrouter.ai/api/v1",
                "https://openrouter.ai/api/v1/models",
            ),
        ];

        for (input, expected) in cases {
            assert_eq!(
                openai_compatible_models_url(input),
                expected,
                "input: {input}"
            );
        }
    }
}
