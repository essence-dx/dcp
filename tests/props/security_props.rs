//! Property-based tests for security layer.
//!
//! Feature: dcp-protocol, Property 9: Ed25519 Signature Verification
//! Feature: dcp-protocol, Property 10: Replay and Expiration Protection

use dcp::observability::StructuredLogger;
use dcp::security::{
    is_sensitive_key, sanitize_json_value, NonceStore, SecurityAuditAction, SecurityAuditEvent,
    SecurityAuditLog, Signer, Verifier, MAX_SECURITY_AUDIT_TEXT_LEN, REDACTED,
};
use dcp::SecurityError;
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Feature: dcp-protocol, Property 9: Ed25519 Signature Verification
    /// For any SignedToolDef, a valid signature SHALL verify successfully.
    /// **Validates: Requirements 7.2**
    #[test]
    fn prop_tool_def_signature_valid(
        seed in any::<[u8; 32]>(),
        tool_id in any::<u32>(),
        schema_hash in any::<[u8; 32]>(),
        capabilities in any::<u64>(),
    ) {
        let signer = Signer::from_seed(&seed);
        let def = signer.sign_tool_def(tool_id, schema_hash, capabilities);

        // Valid signature should verify
        let result = Verifier::verify_tool_def(&def);
        prop_assert!(result.is_ok(), "Valid signature should verify: {:?}", result);
    }

    /// Feature: dcp-protocol, Property 9: Ed25519 Signature Verification
    /// For any SignedToolDef, any modification to the signed data SHALL cause
    /// verification to fail.
    /// **Validates: Requirements 7.2**
    #[test]
    fn prop_tool_def_tamper_detection(
        seed in any::<[u8; 32]>(),
        tool_id in any::<u32>(),
        schema_hash in any::<[u8; 32]>(),
        capabilities in any::<u64>(),
        tamper_field in 0u8..3,
        tamper_value in any::<u8>(),
    ) {
        let signer = Signer::from_seed(&seed);
        let mut def = signer.sign_tool_def(tool_id, schema_hash, capabilities);

        // Tamper with a field
        match tamper_field {
            0 => {
                // Tamper with tool_id
                let new_id = def.tool_id.wrapping_add(1);
                if new_id != def.tool_id {
                    def.tool_id = new_id;
                } else {
                    return Ok(()); // Skip if no change
                }
            }
            1 => {
                // Tamper with schema_hash
                def.schema_hash[0] = def.schema_hash[0].wrapping_add(1);
            }
            _ => {
                // Tamper with capabilities
                def.capabilities = def.capabilities.wrapping_add(1);
            }
        }

        // Tampered signature should fail verification
        let result = Verifier::verify_tool_def(&def);
        prop_assert!(result.is_err(), "Tampered signature should fail verification");
    }

    /// Feature: dcp-protocol, Property 9: Ed25519 Signature Verification
    /// For any SignedInvocation, a valid signature SHALL verify successfully.
    /// **Validates: Requirements 7.2**
    #[test]
    fn prop_invocation_signature_valid(
        seed in any::<[u8; 32]>(),
        tool_id in any::<u32>(),
        nonce in any::<u64>(),
        timestamp in any::<u64>(),
        args in prop::collection::vec(any::<u8>(), 0..100),
    ) {
        let signer = Signer::from_seed(&seed);
        let inv = signer.sign_invocation(tool_id, nonce, timestamp, &args);
        let public_key = signer.public_key_bytes();

        // Valid signature should verify
        let result = Verifier::verify_invocation(&inv, &public_key);
        prop_assert!(result.is_ok(), "Valid signature should verify: {:?}", result);

        // Args hash should match
        prop_assert!(Verifier::verify_args_hash(&inv, &args));
    }

    /// Feature: dcp-protocol, Property 9: Ed25519 Signature Verification
    /// For any SignedInvocation, any modification SHALL cause verification to fail.
    /// **Validates: Requirements 7.2**
    #[test]
    fn prop_invocation_tamper_detection(
        seed in any::<[u8; 32]>(),
        tool_id in any::<u32>(),
        nonce in any::<u64>(),
        timestamp in any::<u64>(),
        args in prop::collection::vec(any::<u8>(), 0..100),
        tamper_field in 0u8..4,
    ) {
        let signer = Signer::from_seed(&seed);
        let mut inv = signer.sign_invocation(tool_id, nonce, timestamp, &args);
        let public_key = signer.public_key_bytes();

        // Tamper with a field
        match tamper_field {
            0 => inv.tool_id = inv.tool_id.wrapping_add(1),
            1 => inv.nonce = inv.nonce.wrapping_add(1),
            2 => inv.timestamp = inv.timestamp.wrapping_add(1),
            _ => inv.args_hash[0] = inv.args_hash[0].wrapping_add(1),
        }

        // Tampered signature should fail verification
        let result = Verifier::verify_invocation(&inv, &public_key);
        prop_assert!(result.is_err(), "Tampered signature should fail verification");
    }

    /// Feature: dcp-protocol, Property 9: Ed25519 Signature Verification
    /// Wrong public key SHALL cause verification to fail.
    /// **Validates: Requirements 7.2**
    #[test]
    fn prop_wrong_public_key_fails(
        seed1 in any::<[u8; 32]>(),
        seed2 in any::<[u8; 32]>(),
        tool_id in any::<u32>(),
        nonce in any::<u64>(),
        timestamp in any::<u64>(),
        args in prop::collection::vec(any::<u8>(), 0..50),
    ) {
        prop_assume!(seed1 != seed2);

        let signer1 = Signer::from_seed(&seed1);
        let signer2 = Signer::from_seed(&seed2);

        let inv = signer1.sign_invocation(tool_id, nonce, timestamp, &args);
        let wrong_key = signer2.public_key_bytes();

        // Verification with wrong key should fail
        let result = Verifier::verify_invocation(&inv, &wrong_key);
        prop_assert!(result.is_err(), "Wrong public key should fail verification");
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Feature: dcp-protocol, Property 10: Replay and Expiration Protection
    /// For any SignedInvocation, reusing the same nonce SHALL be rejected.
    /// **Validates: Requirements 7.4**
    #[test]
    fn prop_nonce_reuse_rejected(
        nonce in any::<u64>(),
        timestamp_offset in 0u64..60, // Within valid window
    ) {
        let mut store = NonceStore::with_config(1000, 300);
        let now = NonceStore::current_timestamp();
        let timestamp = now.saturating_sub(timestamp_offset);

        // First use should succeed
        let result1 = store.check_nonce(nonce, timestamp);
        prop_assert!(result1.is_ok(), "First nonce use should succeed");

        // Second use should fail as replay
        let result2 = store.check_nonce(nonce, timestamp);
        prop_assert!(result2.is_err(), "Nonce reuse should be rejected");
        prop_assert!(matches!(result2, Err(dcp::SecurityError::ReplayAttack)));
    }

    /// Feature: dcp-security, Replay capacity is bounded.
    /// A full replay store with no expired entries SHALL deny new nonces instead
    /// of growing past its configured capacity.
    #[test]
    fn prop_nonce_store_rejects_when_capacity_full(
        first_nonce in any::<u64>(),
        second_nonce in any::<u64>(),
    ) {
        prop_assume!(first_nonce != second_nonce);

        let mut store = NonceStore::with_config(1, 300);
        let now = NonceStore::current_timestamp();

        prop_assert!(store.check_nonce(first_nonce, now).is_ok());
        let result = store.check_nonce(second_nonce, now);

        prop_assert_eq!(result, Err(SecurityError::CapacityExceeded));
        prop_assert_eq!(store.len(), 1);
    }

    /// Feature: dcp-protocol, Property 10: Replay and Expiration Protection
    /// Timestamps older than the expiration window SHALL be rejected.
    /// **Validates: Requirements 7.5**
    #[test]
    fn prop_expired_timestamp_rejected(
        nonce in any::<u64>(),
        expiration_secs in 60u64..300,
        extra_age in 1u64..100,
    ) {
        let mut store = NonceStore::with_config(1000, expiration_secs);
        let now = NonceStore::current_timestamp();

        // Timestamp older than expiration window
        let old_timestamp = now.saturating_sub(expiration_secs + extra_age);

        let result = store.check_nonce(nonce, old_timestamp);
        prop_assert!(result.is_err(), "Expired timestamp should be rejected");
        prop_assert!(matches!(result, Err(dcp::SecurityError::ExpiredTimestamp)));
    }

    /// Feature: dcp-protocol, Property 10: Replay and Expiration Protection
    /// Valid timestamps within the window SHALL be accepted.
    /// **Validates: Requirements 7.5**
    #[test]
    fn prop_valid_timestamp_accepted(
        nonce in any::<u64>(),
        expiration_secs in 60u64..300,
        age in 0u64..60, // Within valid window
    ) {
        let mut store = NonceStore::with_config(1000, expiration_secs);
        let now = NonceStore::current_timestamp();
        let timestamp = now.saturating_sub(age.min(expiration_secs - 1));

        let result = store.check_nonce(nonce, timestamp);
        prop_assert!(result.is_ok(), "Valid timestamp should be accepted: {:?}", result);
    }

    /// Feature: dcp-protocol, Property 10: Replay and Expiration Protection
    /// Different nonces SHALL be accepted independently.
    /// **Validates: Requirements 7.4**
    #[test]
    fn prop_different_nonces_independent(
        nonces in prop::collection::vec(any::<u64>(), 1..50),
    ) {
        let mut store = NonceStore::with_config(1000, 300);
        let now = NonceStore::current_timestamp();

        // Deduplicate nonces for this test
        let unique_nonces: std::collections::HashSet<_> = nonces.into_iter().collect();

        for nonce in unique_nonces {
            let result = store.check_nonce(nonce, now);
            prop_assert!(result.is_ok(), "Unique nonce {} should be accepted", nonce);
        }
    }

    /// Feature: dcp-protocol, Property 10: Replay and Expiration Protection
    /// Cleanup SHALL remove only expired nonces.
    /// **Validates: Requirements 7.4, 7.5**
    #[test]
    fn prop_cleanup_preserves_valid_nonces(
        valid_nonces in prop::collection::vec(any::<u64>(), 1..20),
    ) {
        let expiration_secs = 300u64;
        let mut store = NonceStore::with_config(1000, expiration_secs);
        let now = NonceStore::current_timestamp();

        // Add valid nonces
        let unique_valid: std::collections::HashSet<_> = valid_nonces.into_iter().collect();
        for &nonce in &unique_valid {
            store.check_nonce(nonce, now).ok();
        }

        let count_before = store.len();

        // Cleanup should not remove valid nonces
        store.cleanup_expired();

        prop_assert_eq!(store.len(), count_before, "Valid nonces should be preserved after cleanup");

        // Valid nonces should still be rejected as replays
        for &nonce in &unique_valid {
            let result = store.check_nonce(nonce, now);
            prop_assert!(result.is_err(), "Valid nonce should still be tracked after cleanup");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn security_redacts_camel_case_secret_assignments() {
        let sanitized = dcp::security::sanitize_text("apiKey=abc123");

        assert_eq!(sanitized, dcp::security::REDACTED);
    }

    #[test]
    fn security_redacts_url_encoded_secret_assignments() {
        for secret_text in [
            "api%5Fkey=abc123",
            "access%5ftoken=abc123",
            "x%2Dapi%2Dkey=abc123",
            "redirect=https://example.invalid/callback?access%5Ftoken=abc123",
        ] {
            let sanitized = dcp::security::sanitize_text(secret_text);

            assert_eq!(sanitized, dcp::security::REDACTED);
        }

        let value = serde_json::json!({
            "api%5Fkey": "abc123",
            "safe": "visible"
        });
        let rendered = sanitize_json_value(&value).to_string();

        assert!(rendered.contains(REDACTED));
        assert!(rendered.contains("\"safe\":\"visible\""));
        assert!(!rendered.contains("api%5Fkey"));
        assert!(!rendered.contains("abc123"));
    }

    #[test]
    fn security_redacts_double_url_encoded_secret_assignments() {
        for secret_text in [
            "api%255Fkey=abc123",
            "access%255ftoken=abc123",
            "x%252Dapi%252Dkey=abc123",
            "redirect=https://example.invalid/callback?access%255Ftoken=abc123",
        ] {
            let sanitized = dcp::security::sanitize_text(secret_text);

            assert_eq!(sanitized, dcp::security::REDACTED);
        }

        let value = serde_json::json!({
            "api%255Fkey": "abc123",
            "safe": "visible"
        });
        let rendered = sanitize_json_value(&value).to_string();

        assert!(rendered.contains(REDACTED));
        assert!(rendered.contains("\"safe\":\"visible\""));
        assert!(!rendered.contains("api%255Fkey"));
        assert!(!rendered.contains("abc123"));
    }

    #[test]
    fn security_audit_event_redacts_sensitive_fields() {
        let event =
            SecurityAuditEvent::new(SecurityAuditAction::RequestRejected, "validation_failed")
                .with_field("authorization", "Bearer super-secret-token")
                .with_field("api_key", "sk-live-secret")
                .with_field("method", "tools/call");

        let rendered = event.to_json();

        assert!(rendered.contains("\"authorization\":\"[REDACTED]\""));
        assert!(rendered.contains("\"api_key\":\"[REDACTED]\""));
        assert!(rendered.contains("\"method\":\"tools/call\""));
        assert!(!rendered.contains("super-secret-token"));
        assert!(!rendered.contains("sk-live-secret"));
    }

    #[test]
    fn security_audit_event_redacts_top_level_method_request_id_and_reason() {
        let event = SecurityAuditEvent::new(
            SecurityAuditAction::RequestRejected,
            "authorization=Bearer audit-secret",
        )
        .with_method("tools/call?api_key=plain-secret")
        .with_request_id("Bearer request-secret");

        let rendered = event.to_json();

        assert!(!rendered.contains("audit-secret"));
        assert!(!rendered.contains("plain-secret"));
        assert!(!rendered.contains("request-secret"));
    }

    #[test]
    fn security_audit_event_redacts_unstructured_key_value_secrets() {
        for secret_text in [
            "api_key=abc123",
            "token: abc123",
            "authorization=abc123",
            "redirect=/callback?access_token=abc123",
        ] {
            let event = SecurityAuditEvent::new(SecurityAuditAction::RequestRejected, secret_text)
                .with_method(format!("tools/call?{}", secret_text))
                .with_request_id(format!("req {}", secret_text));

            let rendered = event.to_json();

            assert!(rendered.contains("[REDACTED]"));
            assert!(!rendered.contains("abc123"));
        }
    }

    #[test]
    fn security_audit_event_redacts_secret_bearing_field_keys() {
        let event = SecurityAuditEvent::new(SecurityAuditAction::RequestRejected, "invalid")
            .with_field("sk-live-key-in-field-name", "safe-value")
            .with_field("access_token=plain-secret", "safe-value");

        let rendered = event.to_json();

        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains("sk-live-key-in-field-name"));
        assert!(!rendered.contains("access_token=plain-secret"));
        assert!(!rendered.contains("plain-secret"));
    }

    #[test]
    fn structured_logger_redacts_secret_bearing_field_keys_before_storage() {
        let logger = StructuredLogger::with_defaults();

        logger
            .info("security event")
            .field("access_token=plain-secret", "safe-value")
            .field("sk-live-key-in-field-name", "safe-value")
            .emit();

        let entries = logger.entries();
        let debug = format!("{entries:?}");
        let stored_keys: Vec<&str> = entries[0].fields.keys().map(String::as_str).collect();

        assert!(stored_keys.iter().all(|key| *key == "[REDACTED]"));
        assert!(!debug.contains("plain-secret"));
        assert!(!debug.contains("access_token"));
        assert!(!debug.contains("sk-live-key-in-field-name"));
    }

    #[test]
    fn sanitize_json_value_redacts_secret_bearing_object_keys() {
        let value = serde_json::json!({
            "sk-live-key-in-object-name": "safe-value",
            "nested": {
                "access_token=plain-secret": "safe-value"
            }
        });

        let rendered = sanitize_json_value(&value).to_string();

        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains("sk-live-key-in-object-name"));
        assert!(!rendered.contains("access_token=plain-secret"));
        assert!(!rendered.contains("plain-secret"));
    }

    proptest! {
        #[test]
        fn prop_sanitize_json_value_redacts_generated_nested_secrets(
            token in "[A-Za-z0-9]{1,24}",
        ) {
            let secret = format!("secret-leak-{token}-end");
            let bearer = format!("Bearer {secret}");
            let secret_key = format!("access_token={secret}");
            let callback = format!("https://example.invalid/callback?access_token={secret}");

            let mut nested = serde_json::Map::new();
            nested.insert("authorization".to_string(), serde_json::Value::String(bearer));
            nested.insert("callback".to_string(), serde_json::Value::String(callback));

            let mut root = serde_json::Map::new();
            root.insert(secret_key, serde_json::Value::String("safe-value".to_string()));
            root.insert(
                "nested".to_string(),
                serde_json::Value::Array(vec![serde_json::Value::Object(nested)]),
            );

            let value = serde_json::Value::Object(root);
            let sanitized = sanitize_json_value(&value);
            let rendered = sanitized.to_string();

            prop_assert!(rendered.contains("[REDACTED]"));
            prop_assert!(!rendered.contains(&secret));
            prop_assert!(!rendered.contains("Bearer"));
            prop_assert!(!rendered.contains("access_token="));
            prop_assert_eq!(sanitize_json_value(&sanitized), sanitized);
        }
    }

    #[test]
    fn redaction_detects_common_camel_case_secret_keys() {
        assert!(is_sensitive_key("apiKey"));
        assert!(is_sensitive_key("accessToken"));
        assert!(is_sensitive_key("refreshToken"));
        assert!(is_sensitive_key("privateKey"));

        let value = serde_json::json!({
            "apiKey": "plain-value",
            "accessToken": "plain-token",
            "safe": "visible"
        });

        let rendered = sanitize_json_value(&value).to_string();

        assert!(rendered.contains("\"apiKey\":\"[REDACTED]\""));
        assert!(rendered.contains("\"accessToken\":\"[REDACTED]\""));
        assert!(rendered.contains("\"safe\":\"visible\""));
        assert!(!rendered.contains("plain-value"));
        assert!(!rendered.contains("plain-token"));
    }

    #[test]
    fn security_audit_log_keeps_structured_receipts() {
        let log = SecurityAuditLog::new();
        log.record(
            SecurityAuditEvent::new(SecurityAuditAction::CapabilityDenied, "capability_denied")
                .with_method("tools/call")
                .with_request_id("req-1"),
        );

        let events = log.events();

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].action, SecurityAuditAction::CapabilityDenied);
        assert_eq!(events[0].method.as_deref(), Some("tools/call"));
        assert_eq!(events[0].request_id.as_deref(), Some("req-1"));
    }

    #[test]
    fn security_audit_log_sanitizes_mutated_events_on_record() {
        let log = SecurityAuditLog::new();
        let mut event = SecurityAuditEvent::new(SecurityAuditAction::RequestRejected, "safe");
        event.reason = "access_token=plain-secret".to_string();
        event.method = Some("tools/call?api_key=plain-secret".to_string());
        event.request_id = Some("Bearer request-secret".to_string());
        event.fields.insert(
            "authorization".to_string(),
            "Bearer field-secret".to_string(),
        );
        event
            .fields
            .insert("safe".to_string(), "access_token=field-secret".to_string());

        log.record(event);
        let events = log.events();
        let rendered = events[0].to_json();

        assert_eq!(events.len(), 1);
        assert!(!rendered.contains("plain-secret"));
        assert!(!rendered.contains("request-secret"));
        assert!(!rendered.contains("field-secret"));
        assert!(rendered.contains(REDACTED));
    }

    #[test]
    fn security_audit_log_bounds_top_level_text_fields_on_record() {
        let log = SecurityAuditLog::new();
        let long_reason = "request-rejected-".repeat(MAX_SECURITY_AUDIT_TEXT_LEN);
        let long_method = "tools/unknown/".repeat(MAX_SECURITY_AUDIT_TEXT_LEN);
        let long_request_id = "request-id-".repeat(MAX_SECURITY_AUDIT_TEXT_LEN);

        log.record(
            SecurityAuditEvent::new(SecurityAuditAction::RequestRejected, long_reason)
                .with_method(long_method)
                .with_request_id(long_request_id),
        );

        let event = log.events().remove(0);

        assert!(event.reason.len() <= MAX_SECURITY_AUDIT_TEXT_LEN);
        assert!(event.method.unwrap().len() <= MAX_SECURITY_AUDIT_TEXT_LEN);
        assert!(event.request_id.unwrap().len() <= MAX_SECURITY_AUDIT_TEXT_LEN);
    }

    #[test]
    fn security_audit_log_bounds_field_keys_and_values_on_record() {
        let log = SecurityAuditLog::new();
        let long_key = "safe-field-name-".repeat(MAX_SECURITY_AUDIT_TEXT_LEN);
        let long_value = "safe-field-value-".repeat(MAX_SECURITY_AUDIT_TEXT_LEN);

        log.record(
            SecurityAuditEvent::new(SecurityAuditAction::RequestRejected, "safe")
                .with_field(long_key, long_value),
        );

        let event = log.events().remove(0);
        let (key, value) = event.fields.iter().next().unwrap();

        assert!(key.len() <= MAX_SECURITY_AUDIT_TEXT_LEN);
        assert!(value.len() <= MAX_SECURITY_AUDIT_TEXT_LEN);
    }

    #[test]
    fn security_audit_log_is_bounded_and_counts_dropped_receipts() {
        let log = SecurityAuditLog::with_capacity(2);

        for index in 0..4 {
            log.record(
                SecurityAuditEvent::new(SecurityAuditAction::ValidationRejected, "invalid")
                    .with_request_id(format!("req-{index}")),
            );
        }

        let events = log.events();

        assert_eq!(events.len(), 2);
        assert_eq!(events[0].request_id.as_deref(), Some("req-2"));
        assert_eq!(events[1].request_id.as_deref(), Some("req-3"));
        assert_eq!(log.dropped_count(), 2);
    }
}
