use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::sync::Mutex;
use std::time::{SystemTime, Duration};
use libc::c_char;
use rand::Rng;
use lazy_static::lazy_static;
use ethers::types::{Address, Signature};
use ethers::utils::{to_checksum, keccak256};
use ethers::core::k256::ecdsa::{VerifyingKey, signature::Verifier};
use serde_json::json;
use thiserror::Error;

// Multicodec for secp256k1-pub (compressed)
const SECP256K1_MULTICODEC: &[u8] = &[0xe7, 0x01];

// --- Custom Error Type ---
#[derive(Error, Debug)]
enum ArkenAuthError {
    #[error("Invalid Authorization header format")]
    InvalidHeaderFormat,
    #[error("Missing '{0}' in Authorization header")]
    MissingHeaderPart(&'static str),
    #[error("Invalid or expired nonce")]
    InvalidNonce,
    #[error("Invalid DID format: {0}")]
    InvalidDidFormat(String),
    #[error("Unsupported DID method: {0}")]
    UnsupportedDidMethod(String),
    #[error("Failed to decode did:key: {0}")]
    DidKeyDecodeError(String),
    #[error("Unsupported key type (multicodec): 0x{0:x}")]
    UnsupportedKeyType(u16),
    #[error("Invalid public key")]
    InvalidPublicKey,
    #[error("Invalid signature format")]
    InvalidSignatureFormat,
    #[error("Signature recovery failed")]
    SignatureRecoveryError,
    #[error("Signature is invalid")]
    SignatureMismatch,
}

// --- Thread-Safe Nonce Store ---
lazy_static! {
    static ref NONCE_STORE: Mutex<HashMap<String, SystemTime>> = Mutex::new(HashMap::new());
}

fn add_nonce() -> String {
    let nonce: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();
    
    let mut store = NONCE_STORE.lock().expect("Nonce store mutex poisoned");
    store.insert(nonce.clone(), SystemTime::now());
    nonce
}

fn validate_nonce(nonce: &str) -> bool {
    let mut store = NONCE_STORE.lock().expect("Nonce store mutex poisoned");
    if let Some(timestamp) = store.get(nonce) {
        if SystemTime::now().duration_since(*timestamp).unwrap_or_default() < Duration::from_secs(60) {
            return store.remove(nonce).is_some();
        }
    }
    false
}

// --- DID Key Parsing ---

/// Parse a did:key identifier and extract the public key
/// Supports: did:key:z... (proper multibase format) and did:key:0x... (legacy Ethereum address format)
fn parse_did_key(did: &str) -> Result<Address, ArkenAuthError> {
    // Strip "did:key:" prefix
    let key_part = did.strip_prefix("did:key:")
        .ok_or_else(|| ArkenAuthError::InvalidDidFormat("Missing 'did:key:' prefix".to_string()))?;
    
    // Check format: proper did:key (z-prefix) or legacy address (0x-prefix)
    if key_part.starts_with('z') {
        // Proper did:key format with multibase encoding
        parse_multibase_did_key(key_part)
    } else if key_part.starts_with("0x") {
        // Legacy format: did:key:0xADDRESS (for Phase 1 backward compatibility)
        parse_legacy_address_did(key_part)
    } else {
        Err(ArkenAuthError::InvalidDidFormat(
            "DID key must start with 'z' (multibase) or '0x' (legacy address)".to_string()
        ))
    }
}

/// Parse proper did:key with multibase encoding (base58btc)
fn parse_multibase_did_key(encoded: &str) -> Result<Address, ArkenAuthError> {
    // Decode base58btc (z prefix indicates base58btc in multibase)
    let decoded = bs58::decode(&encoded[1..]) // Skip 'z' prefix
        .into_vec()
        .map_err(|e| ArkenAuthError::DidKeyDecodeError(format!("Base58 decode failed: {}", e)))?;
    
    // Check minimum length (multicodec + at least some key data)
    if decoded.len() < 3 {
        return Err(ArkenAuthError::DidKeyDecodeError("Decoded data too short".to_string()));
    }
    
    // Verify multicodec (0xe7 0x01 for secp256k1-pub compressed)
    if decoded.len() < SECP256K1_MULTICODEC.len() || &decoded[..SECP256K1_MULTICODEC.len()] != SECP256K1_MULTICODEC {
        let codec = if decoded.len() >= 2 {
            ((decoded[0] as u16) << 8) | (decoded[1] as u16)
        } else {
            decoded[0] as u16
        };
        return Err(ArkenAuthError::UnsupportedKeyType(codec));
    }
    
    // Extract public key bytes (33 bytes for compressed secp256k1)
    let key_bytes = &decoded[SECP256K1_MULTICODEC.len()..];
    if key_bytes.len() != 33 {
        return Err(ArkenAuthError::InvalidPublicKey);
    }
    
    // Convert compressed public key to Ethereum address
    // Ethereum address = last 20 bytes of keccak256(uncompressed_public_key)
    let verifying_key = VerifyingKey::from_sec1_bytes(key_bytes)
        .map_err(|_| ArkenAuthError::InvalidPublicKey)?;
    
    // Get uncompressed public key (64 bytes, no prefix)
    let uncompressed = verifying_key.to_encoded_point(false);
    let uncompressed_bytes = &uncompressed.as_bytes()[1..]; // Skip 0x04 prefix
    
    // Hash and take last 20 bytes for Ethereum address
    let hash = keccak256(uncompressed_bytes);
    let address_bytes: [u8; 20] = hash[12..].try_into().unwrap();
    
    Ok(Address::from(address_bytes))
}

/// Parse legacy format: did:key:0xADDRESS (Phase 1 backward compatibility)
fn parse_legacy_address_did(address_str: &str) -> Result<Address, ArkenAuthError> {
    address_str.parse::<Address>()
        .map_err(|_| ArkenAuthError::InvalidDidFormat("Invalid Ethereum address".to_string()))
}

// --- Signature Verification ---

async fn verify_logic(auth_header: &str) -> Result<String, ArkenAuthError> {
    if !auth_header.starts_with("Signature ") {
        return Err(ArkenAuthError::InvalidHeaderFormat);
    }

    // Parse Authorization header
    let parts: HashMap<&str, &str> = auth_header[10..].split(',')
        .filter_map(|s| {
            let mut split = s.trim().splitn(2, '=');
            let key = split.next()?;
            let value = split.next()?;
            Some((key, value.trim_matches('"')))
        })
        .collect();

    let did = *parts.get("did").ok_or(ArkenAuthError::MissingHeaderPart("did"))?;
    let nonce = *parts.get("nonce").ok_or(ArkenAuthError::MissingHeaderPart("nonce"))?;
    let signature_hex = *parts.get("signature").ok_or(ArkenAuthError::MissingHeaderPart("signature"))?;

    // Validate nonce
    if !validate_nonce(nonce) {
        return Err(ArkenAuthError::InvalidNonce);
    }

    // Parse DID and extract public key address
    let expected_address = parse_did_key(did)?;

    // Parse signature
    let sig: Signature = signature_hex.parse()
        .map_err(|_| ArkenAuthError::InvalidSignatureFormat)?;
    
    // Recover address from signature
    let recovered_address = sig.recover(nonce.as_bytes())
        .map_err(|_| ArkenAuthError::SignatureRecoveryError)?;

    // Verify recovered address matches DID's address
    if to_checksum(&recovered_address, None) != to_checksum(&expected_address, None) {
        return Err(ArkenAuthError::SignatureMismatch);
    }

    Ok(did.to_string())
}

// --- FFI Layer ---
//
// Buffer-based API: caller provides an output buffer; we write the JSON result
// into it and return the byte count. Returns -1 if the buffer is too small.
// No heap allocation returned to the caller — no free_string needed.

unsafe fn write_to_buf(s: &str, out: *mut c_char, cap: usize) -> i32 {
    let bytes = s.as_bytes();
    if bytes.len() >= cap {
        return -1;
    }
    std::ptr::copy_nonoverlapping(bytes.as_ptr() as *const c_char, out, bytes.len());
    *out.add(bytes.len()) = 0;
    bytes.len() as i32
}

#[no_mangle]
pub extern "C" fn generate_challenge_into(
    statement_ptr: *const c_char,
    out: *mut c_char,
    cap: usize,
) -> i32 {
    let statement = unsafe { CStr::from_ptr(statement_ptr).to_str().unwrap_or("") };
    let nonce = add_nonce();
    let response = json!({ "challenge": { "nonce": nonce, "statement": statement } });
    unsafe { write_to_buf(&response.to_string(), out, cap) }
}

#[no_mangle]
pub extern "C" fn verify_request_into(
    auth_header_ptr: *const c_char,
    out: *mut c_char,
    cap: usize,
) -> i32 {
    let auth_header = match unsafe { CStr::from_ptr(auth_header_ptr).to_str() } {
        Ok(s) => s,
        Err(_) => {
            let msg = json!({"status": "error", "message": "Invalid UTF-8 in header"}).to_string();
            return unsafe { write_to_buf(&msg, out, cap) };
        }
    };

    let result = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(verify_logic(auth_header));

    let response = match result {
        Ok(did) => json!({"status": "success", "did": did}),
        Err(e) => json!({"status": "error", "message": e.to_string()}),
    };

    unsafe { write_to_buf(&response.to_string(), out, cap) }
}
