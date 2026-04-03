// SPDX-License-Identifier: GPL-3.0-only
//
// G10 — Stateful hash-based signatures: LMS (single-level) and HSS (multi-level)
//
// Uses hbs-lms 0.1.1 (Fraunhofer IIS, RFC 8554 conformant).
// hbs-lms uses a callback-based state model: after each sign() call the library
// invokes `update_private_key_fn(&new_state)` to persist the updated state.
// If the callback returns Err(()), the signature is NOT returned → atomicity guaranteed.
//
// LMS single-level: CKM_LMS_KEY_PAIR_GEN / CKM_LMS (vendor CKMs)
// HSS multi-level: CKM_HSS_KEY_PAIR_GEN / CKM_HSS (standard PKCS#11 v3.2 §6.14)
//
// Key storage layout (CKA_STATEFUL_KEY_STATE):
//   Public key  → hbs-lms raw public key bytes (via VerifyingKey::as_slice())
//   Private key → hbs-lms raw signing key bytes (via SigningKey::as_slice())
//
// Exhaustion detection:
//   LMS single-level: pre-check via CKA_LEAF_INDEX >= 2^H before calling sign()
//   HSS multi-level:  callback_fired flag — if sign() fails AND callback never fired → exhausted

use hbs_lms::{
    self as lms,
    HssParameter, LmsAlgorithm, LmotsAlgorithm,
    Sha256_256,
};

use crate::constants::{
    CKP_LMS_SHA256_M32_H5, CKP_LMS_SHA256_M32_H10, CKP_LMS_SHA256_M32_H15,
    CKP_LMS_SHA256_M32_H20, CKP_LMS_SHA256_M32_H25,
    CKP_LMOTS_SHA256_N32_W1, CKP_LMOTS_SHA256_N32_W2,
    CKP_LMOTS_SHA256_N32_W4, CKP_LMOTS_SHA256_N32_W8,
};

// ── Parameter set mapping ────────────────────────────────────────────────────
//
// PKCS#11 CKP_ constants use tree-height values (5, 10, 15, 20, 25).
// hbs-lms LmsAlgorithm enum uses RFC 8554 type IDs:
//   LmsH5  = 5 (type ID matches H5 by coincidence)
//   LmsH10 = 6 (tree height 10, type ID 6)
//   LmsH15 = 7
//   LmsH20 = 8
//   LmsH25 = 9
// These MUST NOT be confused — always go through these mapping functions.

pub fn ckp_to_lms_algo(param: u32) -> Option<LmsAlgorithm> {
    match param {
        CKP_LMS_SHA256_M32_H5  => Some(LmsAlgorithm::LmsH5),
        CKP_LMS_SHA256_M32_H10 => Some(LmsAlgorithm::LmsH10),
        CKP_LMS_SHA256_M32_H15 => Some(LmsAlgorithm::LmsH15),
        CKP_LMS_SHA256_M32_H20 => Some(LmsAlgorithm::LmsH20),
        CKP_LMS_SHA256_M32_H25 => Some(LmsAlgorithm::LmsH25),
        _ => None,
    }
}

pub fn ckp_to_lmots_algo(param: u32) -> Option<LmotsAlgorithm> {
    match param {
        CKP_LMOTS_SHA256_N32_W1 => Some(LmotsAlgorithm::LmotsW1),
        CKP_LMOTS_SHA256_N32_W2 => Some(LmotsAlgorithm::LmotsW2),
        CKP_LMOTS_SHA256_N32_W4 => Some(LmotsAlgorithm::LmotsW4),
        CKP_LMOTS_SHA256_N32_W8 => Some(LmotsAlgorithm::LmotsW8),
        _ => None,
    }
}

/// Return the number of leaf nodes (2^H) for a given CKP_LMS_* param set value.
/// Used for exhaustion pre-check.
pub fn lms_param_max_leaves(lms_param: u32) -> Option<u64> {
    let h = match lms_param {
        CKP_LMS_SHA256_M32_H5  => 5u32,
        CKP_LMS_SHA256_M32_H10 => 10,
        CKP_LMS_SHA256_M32_H15 => 15,
        CKP_LMS_SHA256_M32_H20 => 20,
        CKP_LMS_SHA256_M32_H25 => 25,
        _ => return None,
    };
    Some(1u64 << h)
}

// ── LMS single-level keygen ──────────────────────────────────────────────────

/// Generate a single-level LMS key pair.
///
/// Returns `(public_key_bytes, private_key_bytes)`.
/// Both are raw hbs-lms serialised bytes suitable for storage in CKA_STATEFUL_KEY_STATE.
pub fn lms_keygen(lms_param: u32, lmots_param: u32) -> Result<(Vec<u8>, Vec<u8>), ()> {
    let lms_algo = ckp_to_lms_algo(lms_param).ok_or(())?;
    let lmots_algo = ckp_to_lmots_algo(lmots_param).ok_or(())?;

    let params = [HssParameter::new(lmots_algo, lms_algo)];

    // hbs-lms requires a 32-byte seed — generate via getrandom
    let mut seed_bytes = [0u8; 32];
    getrandom::getrandom(&mut seed_bytes).map_err(|_| ())?;
    let mut seed = lms::Seed::<Sha256_256>::default();
    seed.as_mut_slice().copy_from_slice(&seed_bytes);

    let (signing_key, verifying_key) = lms::keygen::<Sha256_256>(&params, &seed, None)
        .map_err(|_| ())?;

    let pub_bytes = verifying_key.as_slice().to_vec();
    let priv_bytes = signing_key.as_slice().to_vec();

    Ok((pub_bytes, priv_bytes))
}

// ── LMS single-level sign ────────────────────────────────────────────────────

/// Sign a message with a single-level LMS key.
///
/// `leaf_index` — current value of CKA_LEAF_INDEX (for exhaustion pre-check).
/// `max_leaves` — 2^H for this param set (from `lms_param_max_leaves`).
/// `priv_key_bytes` — raw bytes from CKA_STATEFUL_KEY_STATE.
/// `update_fn` — callback that MUST atomically persist updated key state.
///
/// Returns signature bytes on success.
/// Returns `Err(CKR_KEY_EXHAUSTED)` if leaf_index >= max_leaves.
/// Returns `Err(CKR_FUNCTION_FAILED)` on any other error.
pub fn lms_sign(
    leaf_index: u64,
    max_leaves: u64,
    priv_key_bytes: &[u8],
    message: &[u8],
    update_fn: &mut dyn FnMut(&[u8]) -> Result<(), ()>,
) -> Result<Vec<u8>, u32> {
    use crate::constants::{CKR_KEY_EXHAUSTED, CKR_FUNCTION_FAILED};

    // Exhaustion pre-check (single-level LMS: exact leaf count known)
    if leaf_index >= max_leaves {
        return Err(CKR_KEY_EXHAUSTED);
    }

    let sig = lms::sign::<Sha256_256>(message, priv_key_bytes, update_fn, None)
        .map_err(|_| CKR_FUNCTION_FAILED)?;

    Ok(sig.as_ref().to_vec())
}

// ── LMS single-level verify ──────────────────────────────────────────────────

pub fn lms_verify(pub_key_bytes: &[u8], message: &[u8], signature: &[u8]) -> bool {
    lms::verify::<Sha256_256>(message, signature, pub_key_bytes).is_ok()
}

// ── HSS multi-level keygen ───────────────────────────────────────────────────

/// Generate an HSS multi-level key pair.
///
/// `levels` — HSS tree depth (1–8).
/// `lms_params` — slice of CKP_LMS_* values, one per level.
/// `lmots_params` — slice of CKP_LMOTS_* values, one per level.
///
/// Returns `(public_key_bytes, private_key_bytes)`.
pub fn hss_keygen(
    levels: usize,
    lms_params: &[u32],
    lmots_params: &[u32],
) -> Result<(Vec<u8>, Vec<u8>), ()> {
    if levels == 0 || levels > 8 || lms_params.len() != levels || lmots_params.len() != levels {
        return Err(());
    }

    let mut params = Vec::with_capacity(levels);
    for i in 0..levels {
        let lms_algo = ckp_to_lms_algo(lms_params[i]).ok_or(())?;
        let lmots_algo = ckp_to_lmots_algo(lmots_params[i]).ok_or(())?;
        params.push(HssParameter::new(lmots_algo, lms_algo));
    }

    let mut seed_bytes = [0u8; 32];
    getrandom::getrandom(&mut seed_bytes).map_err(|_| ())?;
    let mut seed = lms::Seed::<Sha256_256>::default();
    seed.as_mut_slice().copy_from_slice(&seed_bytes);

    let (signing_key, verifying_key) = lms::keygen::<Sha256_256>(&params, &seed, None)
        .map_err(|_| ())?;

    let pub_bytes = verifying_key.as_slice().to_vec();
    let priv_bytes = signing_key.as_slice().to_vec();

    Ok((pub_bytes, priv_bytes))
}

// ── HSS multi-level sign ─────────────────────────────────────────────────────

/// Sign a message with an HSS multi-level key.
///
/// For HSS the inner tree structure manages exhaustion — we use the `callback_fired`
/// pattern: if sign() returns Err AND the callback was never fired, the outer tree is
/// exhausted → CKR_KEY_EXHAUSTED. Any other error → CKR_FUNCTION_FAILED.
pub fn hss_sign(
    priv_key_bytes: &[u8],
    message: &[u8],
    update_fn: &mut dyn FnMut(&[u8]) -> Result<(), ()>,
) -> Result<Vec<u8>, u32> {
    use crate::constants::{CKR_KEY_EXHAUSTED, CKR_FUNCTION_FAILED};

    let mut callback_fired = false;
    let mut wrapped_update = |new_state: &[u8]| -> Result<(), ()> {
        callback_fired = true;
        update_fn(new_state)
    };

    match lms::sign::<Sha256_256>(message, priv_key_bytes, &mut wrapped_update, None) {
        Ok(sig) => Ok(sig.as_ref().to_vec()),
        Err(_) => {
            if !callback_fired {
                Err(CKR_KEY_EXHAUSTED)
            } else {
                Err(CKR_FUNCTION_FAILED)
            }
        }
    }
}

// ── HSS multi-level verify ───────────────────────────────────────────────────

pub fn hss_verify(pub_key_bytes: &[u8], message: &[u8], signature: &[u8]) -> bool {
    lms::verify::<Sha256_256>(message, signature, pub_key_bytes).is_ok()
}
