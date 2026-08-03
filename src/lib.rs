//! TAS v1's deterministic, short-circuiting verification pipeline.

use ed25519_dalek::{Signature, VerifyingKey};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashSet;

/// `TAS\0v1\0SIG\0`, the domain separator for TAS v1 signatures.
pub const TAS_V1_PREIMAGE_PREFIX: &[u8] = b"TAS\0v1\0SIG\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[repr(u8)]
pub enum VerificationStage {
    InputDecoding = 1,
    JsonParsing = 2,
    CanonicalizationCheck = 3,
    SchemaValidation = 4,
    PreimageConstruction = 5,
    KeyValidation = 6,
    SignatureLengthCheck = 7,
    SignatureVerification = 8,
    AuthorityValidation = 9,
    LineageValidation = 10,
    InvariantValidation = 11,
    ReplayCheck = 12,
    AdmissionDerivation = 13,
    ReceiptConstruction = 14,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum ErrorCode {
    InvalidUtf8,
    MalformedJson,
    NoncanonicalJson,
    MissingRequiredField(&'static str),
    InvalidFieldType(&'static str),
    InvalidKeyLength,
    InvalidKeyBytes,
    InvalidSignatureLength,
    SignatureVerificationFailed,
    MissingExternalAuthority,
    InvalidLineageChain,
    ConstitutiveAuthorityViolation,
    ReplayDetected,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum Decision {
    Admitted,
    Refused,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Receipt {
    pub decision: Decision,
    pub failure_stage: Option<VerificationStage>,
    pub error_code: Option<ErrorCode>,
    pub canonical_message_digest_hex: String,
    pub signing_preimage_digest_hex: String,
    pub receipt_digest_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VerificationResult {
    pub decision: Decision,
    pub failure_stage: Option<VerificationStage>,
    pub error_code: Option<ErrorCode>,
    pub receipt: Receipt,
}

impl VerificationResult {
    fn refused(
        stage: VerificationStage,
        code: ErrorCode,
        message: String,
        preimage: String,
    ) -> Self {
        let digest = digest_parts(&[
            b"REFUSED",
            &[stage as u8],
            message.as_bytes(),
            preimage.as_bytes(),
        ]);
        let receipt = Receipt {
            decision: Decision::Refused,
            failure_stage: Some(stage),
            error_code: Some(code.clone()),
            canonical_message_digest_hex: message,
            signing_preimage_digest_hex: preimage,
            receipt_digest_hex: digest,
        };
        Self {
            decision: Decision::Refused,
            failure_stage: Some(stage),
            error_code: Some(code),
            receipt,
        }
    }
}

pub struct VerificationContext<'a> {
    pub seen_nonces: &'a HashSet<String>,
}

fn digest_parts(parts: &[&[u8]]) -> String {
    let mut hash = Sha256::new();
    for part in parts {
        hash.update(part);
    }
    hex::encode(hash.finalize())
}

fn refusal(
    stage: VerificationStage,
    code: ErrorCode,
    message: &str,
    preimage: &str,
) -> VerificationResult {
    VerificationResult::refused(stage, code, message.to_owned(), preimage.to_owned())
}

/// Verify canonical envelope bytes without changing replay state.
///
/// The signature is detached logically: its preimage is the canonical envelope
/// with the `signature` member removed. This avoids a self-referential signature
/// while the original, complete envelope must itself still be canonical JSON.
pub fn verify_tas_v1(raw: &[u8], ctx: &VerificationContext<'_>) -> VerificationResult {
    let empty = hex::encode(Sha256::digest([]));
    let text = match std::str::from_utf8(raw) {
        Ok(value) => value,
        Err(_) => {
            return refusal(
                VerificationStage::InputDecoding,
                ErrorCode::InvalidUtf8,
                &empty,
                &empty,
            )
        }
    };
    let parsed: Value = match serde_json::from_str(text) {
        Ok(value) => value,
        Err(_) => {
            return refusal(
                VerificationStage::JsonParsing,
                ErrorCode::MalformedJson,
                &empty,
                &empty,
            )
        }
    };
    let canonical = match serde_jcs::to_vec(&parsed) {
        Ok(value) => value,
        Err(_) => {
            return refusal(
                VerificationStage::CanonicalizationCheck,
                ErrorCode::NoncanonicalJson,
                &empty,
                &empty,
            )
        }
    };
    if raw != canonical {
        return refusal(
            VerificationStage::CanonicalizationCheck,
            ErrorCode::NoncanonicalJson,
            &empty,
            &empty,
        );
    }
    let message_hash = hex::encode(Sha256::digest(&canonical));
    let object = match parsed.as_object() {
        Some(value) => value,
        None => {
            return refusal(
                VerificationStage::SchemaValidation,
                ErrorCode::InvalidFieldType("root object"),
                &message_hash,
                &empty,
            )
        }
    };
    macro_rules! string_field {
        ($name:literal) => {
            match object.get($name) {
                None => {
                    return refusal(
                        VerificationStage::SchemaValidation,
                        ErrorCode::MissingRequiredField($name),
                        &message_hash,
                        &empty,
                    )
                }
                Some(Value::String(value)) => value,
                Some(_) => {
                    return refusal(
                        VerificationStage::SchemaValidation,
                        ErrorCode::InvalidFieldType($name),
                        &message_hash,
                        &empty,
                    )
                }
            }
        };
    }
    let public_key = string_field!("public_key");
    let signature = string_field!("signature");
    let nonce = string_field!("nonce");

    let mut unsigned = parsed.clone();
    unsigned
        .as_object_mut()
        .expect("validated object")
        .remove("signature");
    let unsigned_canonical = serde_jcs::to_vec(&unsigned).expect("JSON Value is JCS serializable");
    let mut preimage = Vec::with_capacity(TAS_V1_PREIMAGE_PREFIX.len() + unsigned_canonical.len());
    preimage.extend_from_slice(TAS_V1_PREIMAGE_PREFIX);
    preimage.extend_from_slice(&unsigned_canonical);
    let preimage_hash = hex::encode(Sha256::digest(&preimage));

    let key_bytes = match hex::decode(public_key) {
        Ok(value) if value.len() == 32 => value,
        Ok(_) => {
            return refusal(
                VerificationStage::KeyValidation,
                ErrorCode::InvalidKeyLength,
                &message_hash,
                &preimage_hash,
            )
        }
        Err(_) => {
            return refusal(
                VerificationStage::KeyValidation,
                ErrorCode::InvalidKeyBytes,
                &message_hash,
                &preimage_hash,
            )
        }
    };
    let key_array: [u8; 32] = key_bytes.try_into().expect("length checked");
    let key = match VerifyingKey::from_bytes(&key_array) {
        Ok(value) => value,
        Err(_) => {
            return refusal(
                VerificationStage::KeyValidation,
                ErrorCode::InvalidKeyBytes,
                &message_hash,
                &preimage_hash,
            )
        }
    };
    let signature_bytes = match hex::decode(signature) {
        Ok(value) if value.len() == 64 => value,
        _ => {
            return refusal(
                VerificationStage::SignatureLengthCheck,
                ErrorCode::InvalidSignatureLength,
                &message_hash,
                &preimage_hash,
            )
        }
    };
    let signature = Signature::from_bytes(&signature_bytes.try_into().expect("length checked"));
    if key.verify_strict(&preimage, &signature).is_err() {
        return refusal(
            VerificationStage::SignatureVerification,
            ErrorCode::SignatureVerificationFailed,
            &message_hash,
            &preimage_hash,
        );
    }
    if object.get("external_authority").is_none_or(Value::is_null) {
        return refusal(
            VerificationStage::AuthorityValidation,
            ErrorCode::MissingExternalAuthority,
            &message_hash,
            &preimage_hash,
        );
    }
    if !matches!(object.get("lineage_chain"), Some(Value::Array(items)) if !items.is_empty()) {
        return refusal(
            VerificationStage::LineageValidation,
            ErrorCode::InvalidLineageChain,
            &message_hash,
            &preimage_hash,
        );
    }
    if object.get("origin_type").and_then(Value::as_str) == Some("computational_process") {
        return refusal(
            VerificationStage::InvariantValidation,
            ErrorCode::ConstitutiveAuthorityViolation,
            &message_hash,
            &preimage_hash,
        );
    }
    if ctx.seen_nonces.contains(nonce) {
        return refusal(
            VerificationStage::ReplayCheck,
            ErrorCode::ReplayDetected,
            &message_hash,
            &preimage_hash,
        );
    }

    let receipt_digest = digest_parts(&[
        b"ADMITTED",
        message_hash.as_bytes(),
        preimage_hash.as_bytes(),
    ]);
    let receipt = Receipt {
        decision: Decision::Admitted,
        failure_stage: None,
        error_code: None,
        canonical_message_digest_hex: message_hash,
        signing_preimage_digest_hex: preimage_hash,
        receipt_digest_hex: receipt_digest,
    };
    VerificationResult {
        decision: Decision::Admitted,
        failure_stage: None,
        error_code: None,
        receipt,
    }
}
