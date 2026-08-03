use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use std::collections::HashSet;
use tas_verifier::{
    verify_tas_v1, Decision, ErrorCode, VerificationContext, VerificationStage,
    TAS_V1_PREIMAGE_PREFIX,
};

fn sign(mut value: Value) -> Vec<u8> {
    let key = SigningKey::from_bytes(&[42; 32]);
    value["public_key"] = json!(hex::encode(key.verifying_key().as_bytes()));
    value.as_object_mut().unwrap().remove("signature");
    let unsigned = serde_jcs::to_vec(&value).unwrap();
    let signature = key.sign(&[TAS_V1_PREIMAGE_PREFIX, &unsigned].concat());
    value["signature"] = json!(hex::encode(signature.to_bytes()));
    serde_jcs::to_vec(&value).unwrap()
}

fn valid(nonce: &str) -> Vec<u8> {
    sign(json!({
        "external_authority": "statute:50-usc-1501",
        "lineage_chain": ["root:civic-auth-01"],
        "nonce": nonce,
        "origin_type": "statutory_delegation"
    }))
}

fn verify(bytes: &[u8]) -> tas_verifier::VerificationResult {
    verify_tas_v1(
        bytes,
        &VerificationContext {
            seen_nonces: &HashSet::new(),
        },
    )
}

fn assert_failure(bytes: &[u8], stage: VerificationStage, error: ErrorCode) {
    let result = verify(bytes);
    assert_eq!(result.decision, Decision::Refused);
    assert_eq!(result.failure_stage, Some(stage));
    assert_eq!(result.error_code, Some(error));
    assert_eq!(result.receipt.failure_stage, Some(stage));
}

#[test]
fn stages_one_through_four_short_circuit() {
    assert_failure(
        &[0xff],
        VerificationStage::InputDecoding,
        ErrorCode::InvalidUtf8,
    );
    assert_failure(
        b"{no",
        VerificationStage::JsonParsing,
        ErrorCode::MalformedJson,
    );
    assert_failure(
        b"{ }",
        VerificationStage::CanonicalizationCheck,
        ErrorCode::NoncanonicalJson,
    );
    assert_failure(
        b"{}",
        VerificationStage::SchemaValidation,
        ErrorCode::MissingRequiredField("public_key"),
    );
}

#[test]
fn key_signature_and_signature_verification_fail_in_order() {
    let bad_key =
        serde_jcs::to_vec(&json!({"nonce":"n","public_key":"00","signature":"00".repeat(64)}))
            .unwrap();
    assert_failure(
        &bad_key,
        VerificationStage::KeyValidation,
        ErrorCode::InvalidKeyLength,
    );

    let key = SigningKey::from_bytes(&[42; 32]);
    let bad_length = serde_jcs::to_vec(&json!({"nonce":"n","public_key":hex::encode(key.verifying_key().as_bytes()),"signature":"00"})).unwrap();
    assert_failure(
        &bad_length,
        VerificationStage::SignatureLengthCheck,
        ErrorCode::InvalidSignatureLength,
    );

    let bad_signature = serde_jcs::to_vec(&json!({"nonce":"n","public_key":hex::encode(key.verifying_key().as_bytes()),"signature":"00".repeat(64)})).unwrap();
    assert_failure(
        &bad_signature,
        VerificationStage::SignatureVerification,
        ErrorCode::SignatureVerificationFailed,
    );
}

#[test]
fn semantic_checks_and_replay_short_circuit() {
    assert_failure(
        &sign(json!({"lineage_chain":["root"],"nonce":"n","origin_type":"statutory_delegation"})),
        VerificationStage::AuthorityValidation,
        ErrorCode::MissingExternalAuthority,
    );
    assert_failure(
        &sign(
            json!({"external_authority":"law","lineage_chain":[],"nonce":"n","origin_type":"statutory_delegation"}),
        ),
        VerificationStage::LineageValidation,
        ErrorCode::InvalidLineageChain,
    );
    assert_failure(
        &sign(
            json!({"external_authority":"law","lineage_chain":["root"],"nonce":"n","origin_type":"computational_process"}),
        ),
        VerificationStage::InvariantValidation,
        ErrorCode::ConstitutiveAuthorityViolation,
    );

    let mut seen = HashSet::new();
    seen.insert("n".to_owned());
    let result = verify_tas_v1(&valid("n"), &VerificationContext { seen_nonces: &seen });
    assert_eq!(result.failure_stage, Some(VerificationStage::ReplayCheck));
    assert_eq!(result.error_code, Some(ErrorCode::ReplayDetected));
}

#[test]
fn valid_payload_is_admitted_with_deterministic_receipt() {
    let payload = valid("unique");
    let first = verify(&payload);
    let second = verify(&payload);
    assert_eq!(first, second);
    assert_eq!(first.decision, Decision::Admitted);
    assert_eq!(first.failure_stage, None);
    assert_eq!(first.receipt.receipt_digest_hex.len(), 64);
}
