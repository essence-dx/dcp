//! Shared redaction helpers for security-sensitive observability paths.

use serde_json::Value;

/// Placeholder used when a sensitive value is removed from logs or receipts.
pub const REDACTED: &str = "[REDACTED]";
const MAX_PERCENT_DECODE_PASSES: usize = 4;

const SENSITIVE_KEYS: &[&str] = &[
    "authorization",
    "cookie",
    "set-cookie",
    "password",
    "passwd",
    "secret",
    "api_key",
    "x-api-key",
    "access_token",
    "refresh_token",
    "private_key",
    "credential",
    "session",
    "token",
];

/// Return true when a structured field key is security-sensitive.
pub fn is_sensitive_key(key: &str) -> bool {
    let decoded = percent_decode_ascii_repeated(key);
    let normalized = normalize_key(&decoded);
    SENSITIVE_KEYS.iter().any(|sensitive| {
        normalized == *sensitive
            || normalized.contains(sensitive)
            || normalized.contains(&sensitive.replace('_', "-"))
    })
}

fn normalize_key(key: &str) -> String {
    let mut normalized = String::with_capacity(key.len());
    let mut previous_was_lower_or_digit = false;

    for ch in key.chars() {
        if ch == '_' || ch == '-' {
            if !normalized.ends_with('-') {
                normalized.push('-');
            }
            previous_was_lower_or_digit = false;
            continue;
        }

        if ch.is_ascii_uppercase() && previous_was_lower_or_digit {
            normalized.push('-');
        }

        normalized.push(ch.to_ascii_lowercase());
        previous_was_lower_or_digit = ch.is_ascii_lowercase() || ch.is_ascii_digit();
    }

    normalized
}

/// Return true when an unstructured value looks like a secret.
pub fn looks_sensitive_value(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    let decoded_lower = percent_decode_ascii_repeated(&lower).to_ascii_lowercase();
    text_looks_sensitive(&lower) || text_looks_sensitive(&decoded_lower)
}

fn text_looks_sensitive(lower: &str) -> bool {
    lower.contains("bearer ")
        || lower.contains("basic ")
        || lower.contains("sk-live")
        || lower.contains("sk-")
        || lower.contains("password")
        || lower.contains("private key")
        || lower.contains("-----begin")
        || lower.contains("secret")
        || lower.contains("access_token")
        || lower.contains("refresh_token")
        || contains_sensitive_assignment(lower)
}

fn contains_sensitive_assignment(lower: &str) -> bool {
    SENSITIVE_KEYS.iter().any(|key| {
        let underscore = key.replace('-', "_");
        let compact = key.replace(['-', '_'], "");
        [*key, underscore.as_str(), compact.as_str()]
            .iter()
            .any(|variant| {
                lower.contains(&format!("{}=", variant))
                    || lower.contains(&format!("{}:", variant))
                    || lower.contains(&format!("?{}=", variant))
                    || lower.contains(&format!("&{}=", variant))
            })
    })
}

fn percent_decode_ascii(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut decoded = String::with_capacity(value.len());
    let mut index = 0;

    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let (Some(high), Some(low)) =
                (hex_value(bytes[index + 1]), hex_value(bytes[index + 2]))
            {
                decoded.push((high << 4 | low) as char);
                index += 3;
                continue;
            }
        }

        decoded.push(bytes[index] as char);
        index += 1;
    }

    decoded
}

fn percent_decode_ascii_repeated(value: &str) -> String {
    let mut current = value.to_string();

    for _ in 0..MAX_PERCENT_DECODE_PASSES {
        let decoded = percent_decode_ascii(&current);
        if decoded == current {
            break;
        }
        current = decoded;
    }

    current
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Sanitize a structured value using its field key.
pub fn sanitize_field_value(key: &str, value: &str) -> String {
    if is_sensitive_key(key) || looks_sensitive_value(value) {
        REDACTED.to_string()
    } else {
        value.to_string()
    }
}

/// Sanitize a structured field key when the key itself contains secret text.
pub fn sanitize_field_key(key: &str) -> String {
    if looks_sensitive_value(key) || is_percent_encoded_sensitive_key(key) {
        REDACTED.to_string()
    } else {
        key.to_string()
    }
}

fn is_percent_encoded_sensitive_key(key: &str) -> bool {
    key.contains('%') && is_sensitive_key(key)
}

/// Sanitize unstructured text by replacing the whole text when it resembles a secret.
pub fn sanitize_text(value: &str) -> String {
    if looks_sensitive_value(value) {
        REDACTED.to_string()
    } else {
        value.to_string()
    }
}

/// Recursively sanitize JSON values while preserving non-sensitive structure.
pub fn sanitize_json_value(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut sanitized = serde_json::Map::new();
            for (key, value) in map {
                let value = if is_sensitive_key(key) {
                    Value::String(REDACTED.to_string())
                } else {
                    sanitize_json_value(value)
                };
                sanitized.insert(sanitize_field_key(key), value);
            }
            Value::Object(sanitized)
        }
        Value::Array(values) => Value::Array(values.iter().map(sanitize_json_value).collect()),
        Value::String(value) => Value::String(sanitize_text(value)),
        other => other.clone(),
    }
}
