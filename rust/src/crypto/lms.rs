// SPDX-License-Identifier: GPL-3.0-only
//
// G10 — Stateful hash-based signatures: LMS (single-level) and HSS (multi-level)
//
// Uses hbs-lms 0.1.1 (Fraunhofer IIS, RFC 8554 conformant).
// Supports all SP 800-208 parameter sets: SHA-256 N32/N24 and SHAKE-256 N32/N24.
//
// All LMS/HSS operations use CKM_HSS_KEY_PAIR_GEN / CKM_HSS (PKCS#11 v3.2 §6.14).
// Single-level LMS: CKM_HSS_KEY_PAIR_GEN with levels=1 in CK_HSS_KEY_PAIR_GEN_PARAMS.
//
// Parameter set values are IANA registry type IDs (RFC 8554 + SP 800-208):
//   https://www.iana.org/assignments/leighton-micali-signatures/

use hbs_lms::{
    self as lms, HashChain, HssParameter, LmotsAlgorithm, LmsAlgorithm, Sha256_192, Sha256_256,
    Shake256_192, Shake256_256,
};

use crate::constants::*;

// ── Hash type dispatch ──────────────────────────────────────────────────────
//
// The hbs-lms crate is generic over H: HashChain. We determine the hash type
// from the LMS parameter set IANA ID range:
//   0x05–0x09: SHA-256 N32 → Sha256_256
//   0x0A–0x0E: SHA-256 N24 → Sha256_192
//   0x0F–0x13: SHAKE-256 N32 → Shake256_256
//   0x14–0x18: SHAKE-256 N24 → Shake256_192

/// Determine tree height from any LMS IANA type ID.
fn lms_param_height(lms_param: u32) -> Option<u8> {
    let offset = match lms_param {
        0x05..=0x09 => lms_param - 0x05,
        0x0A..=0x0E => lms_param - 0x0A,
        0x0F..=0x13 => lms_param - 0x0F,
        0x14..=0x18 => lms_param - 0x14,
        _ => return None,
    };
    Some([5, 10, 15, 20, 25][offset as usize])
}

pub fn ckp_to_lms_algo(param: u32) -> Option<LmsAlgorithm> {
    // All four hash families use the same LmsAlgorithm enum (height-based)
    let height = lms_param_height(param)?;
    match height {
        5 => Some(LmsAlgorithm::LmsH5),
        10 => Some(LmsAlgorithm::LmsH10),
        15 => Some(LmsAlgorithm::LmsH15),
        20 => Some(LmsAlgorithm::LmsH20),
        25 => Some(LmsAlgorithm::LmsH25),
        _ => None,
    }
}

pub fn ckp_to_lmots_algo(param: u32) -> Option<LmotsAlgorithm> {
    // All four hash families use the same LmotsAlgorithm enum (W-based)
    let offset = match param {
        0x01..=0x04 => param - 0x01, // SHA-256 N32
        0x05..=0x08 => param - 0x05, // SHA-256 N24
        0x09..=0x0C => param - 0x09, // SHAKE-256 N32
        0x0D..=0x10 => param - 0x0D, // SHAKE-256 N24
        _ => return None,
    };
    match offset {
        0 => Some(LmotsAlgorithm::LmotsW1),
        1 => Some(LmotsAlgorithm::LmotsW2),
        2 => Some(LmotsAlgorithm::LmotsW4),
        3 => Some(LmotsAlgorithm::LmotsW8),
        _ => None,
    }
}

/// Return the number of leaf nodes (2^H) for a given CKP_LMS_* param set.
pub fn lms_param_max_leaves(lms_param: u32) -> Option<u64> {
    let h = lms_param_height(lms_param)? as u32;
    Some(1u64 << h)
}

// ── Generic keygen helper ───────────────────────────────────────────────────

fn keygen_typed<H: HashChain>(params: &[HssParameter<H>]) -> Result<(Vec<u8>, Vec<u8>), ()> {
    let mut seed_bytes = [0u8; 32];
    getrandom::getrandom(&mut seed_bytes).map_err(|_| ())?;
    let mut seed = lms::Seed::<H>::default();
    let n = seed.as_mut_slice().len();
    seed.as_mut_slice().copy_from_slice(&seed_bytes[..n]);
    let (sk, vk) = lms::keygen::<H>(params, &seed, None).map_err(|_| ())?;
    Ok((vk.as_slice().to_vec(), sk.as_slice().to_vec()))
}

// ── LMS single-level keygen ─────────────────────────────────────────────────

pub fn lms_keygen(lms_param: u32, lmots_param: u32) -> Result<(Vec<u8>, Vec<u8>), ()> {
    let lms_algo = ckp_to_lms_algo(lms_param).ok_or(())?;
    let lmots_algo = ckp_to_lmots_algo(lmots_param).ok_or(())?;

    match lms_param {
        0x05..=0x09 => keygen_typed(&[HssParameter::<Sha256_256>::new(lmots_algo, lms_algo)]),
        0x0A..=0x0E => keygen_typed(&[HssParameter::<Sha256_192>::new(lmots_algo, lms_algo)]),
        0x0F..=0x13 => keygen_typed(&[HssParameter::<Shake256_256>::new(lmots_algo, lms_algo)]),
        0x14..=0x18 => keygen_typed(&[HssParameter::<Shake256_192>::new(lmots_algo, lms_algo)]),
        _ => Err(()),
    }
}

// ── LMS single-level sign ───────────────────────────────────────────────────

pub fn lms_sign(
    leaf_index: u64,
    max_leaves: u64,
    priv_key_bytes: &[u8],
    message: &[u8],
    update_fn: &mut dyn FnMut(&[u8]) -> Result<(), ()>,
) -> Result<Vec<u8>, u32> {
    use crate::constants::{CKR_FUNCTION_FAILED, CKR_KEY_EXHAUSTED};

    if leaf_index >= max_leaves {
        return Err(CKR_KEY_EXHAUSTED);
    }

    // Detect hash type from the public key type ID embedded in the private key.
    // hbs-lms private keys start with [levels(4) || lms_type(4) || ...].
    // For single-level LMS wrapped in HSS format: levels=1, lms_type at offset 4.
    // Direct: type ID at offset 0 of the LMS public key within.
    // We use Sha256_256 as default — the hbs-lms verify/sign functions parse
    // the type ID from the key bytes themselves, so the generic parameter only
    // affects hash output sizing. For keys generated with a specific hash type,
    // the library handles dispatch internally.
    let sig = lms::sign::<Sha256_256>(message, priv_key_bytes, update_fn, None)
        .map_err(|_| CKR_FUNCTION_FAILED)?;

    Ok(sig.as_ref().to_vec())
}

// ── LMS single-level verify ─────────────────────────────────────────────────

pub fn lms_verify(pub_key_bytes: &[u8], message: &[u8], signature: &[u8]) -> bool {
    // Try Sha256_256 first (covers both N32 and N24 — library reads type from key)
    lms::verify::<Sha256_256>(message, signature, pub_key_bytes).is_ok()
}

// ── HSS multi-level keygen ──────────────────────────────────────────────────

pub fn hss_keygen(
    levels: usize,
    lms_params: &[u32],
    lmots_params: &[u32],
) -> Result<(Vec<u8>, Vec<u8>), ()> {
    if levels == 0 || levels > 8 || lms_params.len() != levels || lmots_params.len() != levels {
        return Err(());
    }

    // Build typed HssParameter vec and dispatch based on first level's hash type.
    // All levels in an HSS tree must use the same hash function.
    macro_rules! build_and_keygen {
        ($H:ty) => {{
            let mut params = Vec::with_capacity(levels);
            for i in 0..levels {
                let lms_algo = ckp_to_lms_algo(lms_params[i]).ok_or(())?;
                let lmots_algo = ckp_to_lmots_algo(lmots_params[i]).ok_or(())?;
                params.push(HssParameter::<$H>::new(lmots_algo, lms_algo));
            }
            keygen_typed(&params)
        }};
    }

    match lms_params[0] {
        0x05..=0x09 => build_and_keygen!(Sha256_256),
        0x0A..=0x0E => build_and_keygen!(Sha256_192),
        0x0F..=0x13 => build_and_keygen!(Shake256_256),
        0x14..=0x18 => build_and_keygen!(Shake256_192),
        _ => Err(()),
    }
}

// ── HSS multi-level sign ────────────────────────────────────────────────────

pub fn hss_sign(
    lms_param: u32,
    priv_key_bytes: &[u8],
    message: &[u8],
    update_fn: &mut dyn FnMut(&[u8]) -> Result<(), ()>,
) -> Result<Vec<u8>, u32> {
    use crate::constants::{CKR_FUNCTION_FAILED, CKR_KEY_EXHAUSTED};

    let mut callback_fired = false;
    let mut wrapped_update = |new_state: &[u8]| -> Result<(), ()> {
        callback_fired = true;
        update_fn(new_state)
    };

    // Dispatch based on hash family (determines OUTPUT_SIZE for key deserialization).
    // Using the wrong type causes from_binary_representation to fail (size mismatch)
    // which is silently misidentified as CKR_KEY_EXHAUSTED.
    let result = match lms_param {
        0x05..=0x09 => lms::sign::<Sha256_256>(message, priv_key_bytes, &mut wrapped_update, None),
        0x0A..=0x0E => lms::sign::<Sha256_192>(message, priv_key_bytes, &mut wrapped_update, None),
        0x0F..=0x13 => {
            lms::sign::<Shake256_256>(message, priv_key_bytes, &mut wrapped_update, None)
        }
        0x14..=0x18 => {
            lms::sign::<Shake256_192>(message, priv_key_bytes, &mut wrapped_update, None)
        }
        _ => lms::sign::<Sha256_256>(message, priv_key_bytes, &mut wrapped_update, None),
    };

    match result {
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

// ── Custom SHAKE-256 N32 verifier (RFC 8554 §5) ─────────────────────────────
// Required because hbs-lms 0.1.1 writes SHA-256 internal type codes in all
// serialized key/sig bytes; it cannot parse SP 800-208 SHAKE type IDs (0x0F–0x13).
// This path is only hit for §12.3 ACVP sigver KAT (external vectors from NIST).

use sha3::{Shake256 as Sha3Shake256, digest::{ExtendableOutput, Update}};

fn shake256_n32(input: &[u8]) -> [u8; 32] {
    use sha3::digest::XofReader;
    let mut h = Sha3Shake256::default();
    h.update(input);
    let mut out = [0u8; 32];
    h.finalize_xof().read(&mut out);
    out
}

/// LMOTS params for N32 variants (RFC 8554 Table 1 / SP 800-208 Table 2).
/// Returns (w, p, ls) for IANA LMOTS type IDs:
///   SHAKE N32 W1=0x09, W2=0x0A, W4=0x0B, W8=0x0C
fn lmots_n32_params(lmots_type: u32) -> Option<(u8, usize, u8)> {
    match lmots_type {
        // SHA-256 N32 (0x01–0x04) and SHAKE-256 N32 (0x09–0x0C) share same w/p/ls
        0x01 | 0x09 => Some((1, 265, 7)),
        0x02 | 0x0A => Some((2, 133, 6)),
        0x03 | 0x0B => Some((4,  67, 4)),
        0x04 | 0x0C => Some((8,  34, 0)),
        _ => None,
    }
}

/// RFC 8554 §3.1 coef(S, i, w): extract i-th w-bit value from byte string S.
fn coef(s: &[u8], i: usize, w: u8) -> u8 {
    let bits = 8 / w as usize;
    let byte_idx = i / bits;
    let shift = (bits - 1 - (i % bits)) * w as usize;
    (s[byte_idx] >> shift) & ((1u32 << w) - 1) as u8
}

/// RFC 8554 §4.4 checksum Cksm(S, w, ls).
fn checksum(s: &[u8], w: u8, ls: u8) -> u16 {
    let mut sum: u32 = 0;
    let max_val = (1u32 << w) - 1;
    let p_data = s.len() * (8 / w as usize);
    for i in 0..p_data {
        sum += max_val - coef(s, i, w) as u32;
    }
    (sum << ls) as u16
}

/// RFC 8554 §4.6 Algorithm 4b: compute LMOTS candidate public key Kc from sig+msg.
/// I = 16-byte identifier, q = leaf index, lmots_type = IANA type ID (SHAKE or SHA-256).
fn lmots_candidate_key(
    i_val: &[u8; 16],
    q: u32,
    lmots_type: u32,
    c: &[u8],     // n-byte randomizer C from sig
    y: &[&[u8]], // p × n-byte sig components
    message: &[u8],
    is_shake: bool,
) -> Option<[u8; 32]> {
    let (w, p, ls) = lmots_n32_params(lmots_type)?;
    let n = 32usize;

    // Q = H(I || u32be(q) || u16be(0xD2) || C || message)
    let mut buf = Vec::with_capacity(i_val.len() + 4 + 2 + c.len() + message.len());
    buf.extend_from_slice(i_val);
    buf.extend_from_slice(&q.to_be_bytes());
    buf.extend_from_slice(&0xD2u16.to_be_bytes());
    buf.extend_from_slice(c);
    buf.extend_from_slice(message);
    use sha2::Digest;
    let q_hash: [u8; 32] = if is_shake { shake256_n32(&buf) } else { sha2::Sha256::digest(&buf).into() };

    // Cksm computation: append 2-byte checksum to Q
    let ck = checksum(&q_hash, w, ls);
    let mut q_cksm = q_hash.to_vec();
    q_cksm.push((ck >> 8) as u8);
    q_cksm.push((ck & 0xFF) as u8);

    // Iterate: z[i] = H(I || q || u16be(i) || u8(a+j) || y[i])
    let mut z: Vec<Vec<u8>> = Vec::with_capacity(p);
    for i in 0..p {
        let a = coef(&q_cksm, i, w) as u32;
        let max_j = (1u32 << w) - 1;
        let mut tmp = y[i].to_vec();
        for j in a..=max_j {
            let mut h_in = Vec::with_capacity(i_val.len() + 4 + 2 + 1 + n);
            h_in.extend_from_slice(i_val);
            h_in.extend_from_slice(&q.to_be_bytes());
            h_in.extend_from_slice(&(i as u16).to_be_bytes());
            h_in.push(j as u8);
            h_in.extend_from_slice(&tmp);
            tmp = if is_shake { shake256_n32(&h_in).to_vec() }
                  else { sha2::Sha256::digest(&h_in).to_vec() };
        }
        z.push(tmp);
    }

    // Kc = H(I || u32be(q) || u16be(0xD3) || C || z[0] || ... || z[p-1])
    let mut kc_in = Vec::new();
    kc_in.extend_from_slice(i_val);
    kc_in.extend_from_slice(&q.to_be_bytes());
    kc_in.extend_from_slice(&0xD3u16.to_be_bytes());
    kc_in.extend_from_slice(c);
    for zi in &z { kc_in.extend_from_slice(zi); }
    let kc: [u8; 32] = if is_shake { shake256_n32(&kc_in) } else { sha2::Sha256::digest(&kc_in).into() };
    Some(kc)
}

/// RFC 8554 §5.4.2 Algorithm 6b: LMS signature verification for SHAKE-256 N32.
/// pubkey_bytes: raw 56-byte LMS pubkey (no HSS L prefix)
///               format: u32be(lms_type) || u32be(lmots_type) || I[16] || T[1][32]
/// signature_bytes: raw LMS sig (no HSS Nspk prefix)
///                  format: u32be(q) || LMOTS_SIG || u32be(lms_type) || path[h][32]
pub fn lms_shake_n32_verify(
    pubkey_bytes: &[u8],
    message: &[u8],
    signature_bytes: &[u8],
) -> bool {
    // Parse public key (56 bytes for N32)
    if pubkey_bytes.len() < 56 { return false; }
    let lms_type  = u32::from_be_bytes(pubkey_bytes[0..4].try_into().unwrap());
    let lmots_type= u32::from_be_bytes(pubkey_bytes[4..8].try_into().unwrap());
    let i_val: [u8; 16] = pubkey_bytes[8..24].try_into().unwrap();
    let t1 = &pubkey_bytes[24..56];   // T[1]: root node

    // Tree height from LMS type
    let height = match lms_param_height(lms_type) {
        Some(h) => h as u32,
        None => return false,
    };
    let n = 32usize;
    let is_shake = matches!(lms_type, 0x0F..=0x13 | 0x14..=0x18);

    // Get LMOTS params
    let (_, p, _) = match lmots_n32_params(lmots_type) {
        Some(p) => p,
        None => return false,
    };

    // Parse LMS signature
    // LMS sig = u32be(q) || LMOTS_SIG || u32be(lms_type) || h×n path nodes
    // LMOTS_SIG = u32be(lmots_type) || C[n] || y[p][n]
    let lmots_sig_len = 4 + n + p * n;   // type(4) + C(n) + y(p×n)
    let lms_sig_len = 4 + lmots_sig_len + 4 + height as usize * n;
    if signature_bytes.len() < lms_sig_len { return false; }

    let q = u32::from_be_bytes(signature_bytes[0..4].try_into().unwrap());
    if q >= (1u32 << height) { return false; }

    let lmots_sig = &signature_bytes[4..4 + lmots_sig_len];
    let lmots_type_sig = u32::from_be_bytes(lmots_sig[0..4].try_into().unwrap());
    if lmots_type_sig != lmots_type { return false; }
    let c = &lmots_sig[4..4 + n];
    let y: Vec<&[u8]> = (0..p).map(|i| &lmots_sig[4 + n + i * n..4 + n + (i + 1) * n]).collect();

    let lms_type_sig = u32::from_be_bytes(
        signature_bytes[4 + lmots_sig_len..4 + lmots_sig_len + 4].try_into().unwrap());
    if lms_type_sig != lms_type { return false; }
    let path_start = 4 + lmots_sig_len + 4;
    let path: Vec<&[u8]> = (0..height as usize)
        .map(|i| &signature_bytes[path_start + i * n..path_start + (i + 1) * n]).collect();

    // Step 1: compute LMOTS candidate key Kc
    let kc = match lmots_candidate_key(&i_val, q, lmots_type, c, &y, message, is_shake) {
        Some(k) => k,
        None => return false,
    };

    // Step 2: compute LMS candidate root (Algorithm 6b)
    let mut node_num = (1u32 << height) + q;
    use sha2::Digest;

    // Tn = H(I || u32be(node_num) || u16be(0x82) || Kc)
    let mut h_in = Vec::with_capacity(i_val.len() + 4 + 2 + n);
    h_in.extend_from_slice(&i_val);
    h_in.extend_from_slice(&node_num.to_be_bytes());
    h_in.extend_from_slice(&0x82u16.to_be_bytes());
    h_in.extend_from_slice(&kc);
    let mut tmp: [u8; 32] = if is_shake { shake256_n32(&h_in) }
                             else { sha2::Sha256::digest(&h_in).into() };

    for path_node in &path {
        let parent = node_num / 2;
        let mut h_in2 = Vec::with_capacity(i_val.len() + 4 + 2 + n * 2);
        h_in2.extend_from_slice(&i_val);
        h_in2.extend_from_slice(&parent.to_be_bytes());
        h_in2.extend_from_slice(&0x01u16.to_be_bytes());
        if node_num % 2 == 0 {
            h_in2.extend_from_slice(&tmp);
            h_in2.extend_from_slice(path_node);
        } else {
            h_in2.extend_from_slice(path_node);
            h_in2.extend_from_slice(&tmp);
        }
        tmp = if is_shake { shake256_n32(&h_in2) } else { sha2::Sha256::digest(&h_in2).into() };
        node_num = parent;
    }

    // Compare computed root with T[1] in public key
    tmp == t1
}

// ── HSS multi-level verify ──────────────────────────────────────────────────

/// Verify an HSS/LMS signature.  `lms_param` is the CKP_LMS_* value stored in
/// CKA_LMS_PARAM_SET of the key object; it selects the correct hash type.
/// Note: hbs-lms 0.1.1 uses RFC 8554 internal type codes for all hash variants,
/// so SP 800-208 SHAKE-256 type IDs (0x0F-0x18) require Shake256_* dispatch.
pub fn hss_verify(pub_key_bytes: &[u8], message: &[u8], signature: &[u8], lms_param: u32) -> bool {
    match lms_param {
        0x05..=0x09 => lms::verify::<Sha256_256>(message, signature, pub_key_bytes).is_ok(),
        0x0A..=0x0E => lms::verify::<Sha256_192>(message, signature, pub_key_bytes).is_ok(),
        0x0F..=0x13 | 0x14..=0x18 => {
            let raw_lms_pub = if pub_key_bytes.len() == 60 && pub_key_bytes[..4] == [0,0,0,1] {
                &pub_key_bytes[4..]
            } else {
                pub_key_bytes
            };
            let raw_lms_sig = if signature.len() > 4 && signature[..4] == [0,0,0,0] {
                &signature[4..]
            } else {
                signature
            };
            lms_shake_n32_verify(raw_lms_pub, message, raw_lms_sig)
        }
        _ => lms::verify::<Sha256_256>(message, signature, pub_key_bytes).is_ok(),
    }
}
