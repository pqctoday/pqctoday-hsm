// SPDX-License-Identifier: GPL-3.0-only
//! softhsmrustv3 — Pure Rust PKCS#11 v3.2 WASM implementation.
//!
//! Provides ML-KEM, ML-DSA, SLH-DSA, RSA, ECDSA, EdDSA, ECDH,
//! AES (GCM/CBC/KeyWrap), SHA/HMAC, and session management.

use std::cell::RefCell;
use std::collections::HashMap;
use wasm_bindgen::prelude::*;

// ── PKCS#11 Return Values ────────────────────────────────────────────────────

pub const CKR_OK: u32 = 0x00000000;
pub const CKR_FUNCTION_FAILED: u32 = 0x00000006;
pub const CKR_ARGUMENTS_BAD: u32 = 0x00000007;
pub const CKR_DATA_INVALID: u32 = 0x00000020;
pub const CKR_KEY_TYPE_INCONSISTENT: u32 = 0x00000063;
pub const CKR_MECHANISM_INVALID: u32 = 0x00000070;
pub const CKR_OBJECT_HANDLE_INVALID: u32 = 0x00000082;
pub const CKR_OPERATION_NOT_INITIALIZED: u32 = 0x00000091;
pub const CKR_SIGNATURE_INVALID: u32 = 0x000000C0;
pub const CKR_BUFFER_TOO_SMALL: u32 = 0x00000150;

// ── PKCS#11 Attribute Types ──────────────────────────────────────────────────

pub const CKA_VALUE: u32 = 0x00000011;
pub const CKA_KEY_TYPE: u32 = 0x00000100;
pub const CKA_MODULUS_BITS: u32 = 0x00000121;
pub const CKA_VALUE_LEN: u32 = 0x00000161;
pub const CKA_EC_PARAMS: u32 = 0x00000180;
pub const CKA_PARAMETER_SET: u32 = 0x0000061d;

// Private attribute: stores the parameter set on generated keys
const CKA_PRIV_PARAM_SET: u32 = 0xFFFF0001;
// Private attribute: stores the algorithm family for polymorphic dispatch
const CKA_PRIV_ALGO_FAMILY: u32 = 0xFFFF0002;

// Algorithm family identifiers (stored in CKA_PRIV_ALGO_FAMILY)
const ALGO_ML_KEM: u32 = 1;
const ALGO_ML_DSA: u32 = 2;
const ALGO_SLH_DSA: u32 = 3;
const ALGO_RSA: u32 = 4;
const ALGO_ECDSA: u32 = 5;
const ALGO_EDDSA: u32 = 6;
const ALGO_ECDH_P256: u32 = 7;
const ALGO_ECDH_X25519: u32 = 8;

// ── PKCS#11 Mechanism Types ──────────────────────────────────────────────────

// RSA
pub const CKM_RSA_PKCS_KEY_PAIR_GEN: u32 = 0x00000000;
pub const CKM_RSA_PKCS_OAEP: u32 = 0x00000009;
pub const CKM_SHA256_RSA_PKCS: u32 = 0x00000040;
pub const CKM_SHA256_RSA_PKCS_PSS: u32 = 0x00000043;

// PQC - KEM
pub const CKM_ML_KEM_KEY_PAIR_GEN: u32 = 0x0000000F;
pub const CKM_ML_KEM: u32 = 0x00000017;

// PQC - DSA
pub const CKM_ML_DSA_KEY_PAIR_GEN: u32 = 0x0000001C;
pub const CKM_ML_DSA: u32 = 0x0000001D;
pub const CKM_SLH_DSA_KEY_PAIR_GEN: u32 = 0x0000002D;
pub const CKM_SLH_DSA: u32 = 0x0000002E;

// SHA Digest
pub const CKM_SHA256: u32 = 0x00000250;
pub const CKM_SHA384: u32 = 0x00000260;
pub const CKM_SHA512: u32 = 0x00000270;
pub const CKM_SHA3_256: u32 = 0x000002B0;
pub const CKM_SHA3_512: u32 = 0x000002D0;

// HMAC
pub const CKM_SHA256_HMAC: u32 = 0x00000251;
pub const CKM_SHA384_HMAC: u32 = 0x00000261;
pub const CKM_SHA512_HMAC: u32 = 0x00000271;
pub const CKM_SHA3_256_HMAC: u32 = 0x000002B1;
pub const CKM_SHA3_512_HMAC: u32 = 0x000002D1;

// Generic Secret
pub const CKM_GENERIC_SECRET_KEY_GEN: u32 = 0x00000350;

// EC
pub const CKM_EC_KEY_PAIR_GEN: u32 = 0x00001040;
pub const CKM_ECDSA_SHA256: u32 = 0x00001044;
pub const CKM_ECDSA_SHA384: u32 = 0x00001045;
pub const CKM_ECDH1_DERIVE: u32 = 0x00001050;
pub const CKM_EC_EDWARDS_KEY_PAIR_GEN: u32 = 0x00001055;
pub const CKM_EDDSA: u32 = 0x00001057;

// AES
pub const CKM_AES_KEY_GEN: u32 = 0x00001080;
pub const CKM_AES_CBC_PAD: u32 = 0x00001085;
pub const CKM_AES_GCM: u32 = 0x00001087;
pub const CKM_AES_KEY_WRAP: u32 = 0x00002109;

// ── PKCS#11 Parameter Sets ──────────────────────────────────────────────────

pub const CKP_ML_KEM_512: u32 = 0x1;
pub const CKP_ML_KEM_768: u32 = 0x2;
pub const CKP_ML_KEM_1024: u32 = 0x3;

pub const CKP_ML_DSA_44: u32 = 0x1;
pub const CKP_ML_DSA_65: u32 = 0x2;
pub const CKP_ML_DSA_87: u32 = 0x3;

pub const CKP_SLH_DSA_SHA2_128S: u32 = 0x01;
pub const CKP_SLH_DSA_SHAKE_128S: u32 = 0x02;
pub const CKP_SLH_DSA_SHA2_128F: u32 = 0x03;
pub const CKP_SLH_DSA_SHAKE_128F: u32 = 0x04;
pub const CKP_SLH_DSA_SHA2_192S: u32 = 0x05;
pub const CKP_SLH_DSA_SHAKE_192S: u32 = 0x06;
pub const CKP_SLH_DSA_SHA2_192F: u32 = 0x07;
pub const CKP_SLH_DSA_SHAKE_192F: u32 = 0x08;
pub const CKP_SLH_DSA_SHA2_256S: u32 = 0x09;
pub const CKP_SLH_DSA_SHAKE_256S: u32 = 0x0A;
pub const CKP_SLH_DSA_SHA2_256F: u32 = 0x0B;
pub const CKP_SLH_DSA_SHAKE_256F: u32 = 0x0C;

// ECDSA curve identifiers (stored in CKA_PRIV_PARAM_SET)
const CURVE_P256: u32 = 256;
const CURVE_P384: u32 = 384;

// ── PKCS#11 Session/Token Constants ─────────────────────────────────────────

pub const CKS_RW_USER_FUNCTIONS: u32 = 3;
pub const CKF_SERIAL_SESSION: u32 = 0x00000004;
pub const CKF_RW_SESSION: u32 = 0x00000002;

// ── Object Store ─────────────────────────────────────────────────────────────

type Attributes = HashMap<u32, Vec<u8>>;

enum DigestCtx {
    Sha256(sha2::Sha256),
    Sha384(sha2::Sha384),
    Sha512(sha2::Sha512),
    Sha3_256(sha3::Sha3_256),
    Sha3_512(sha3::Sha3_512),
}

struct FindCtx {
    handles: Vec<u32>,
    cursor: usize,
}

thread_local! {
    static OBJECTS: RefCell<HashMap<u32, Attributes>> = RefCell::new(HashMap::new());
    static NEXT_HANDLE: RefCell<u32> = RefCell::new(100);
    static SIGN_STATE: RefCell<HashMap<u32, (u32, u32)>> = RefCell::new(HashMap::new());
    static VERIFY_STATE: RefCell<HashMap<u32, (u32, u32)>> = RefCell::new(HashMap::new());
    static ENCRYPT_STATE: RefCell<HashMap<u32, EncryptCtx>> = RefCell::new(HashMap::new());
    static DECRYPT_STATE: RefCell<HashMap<u32, EncryptCtx>> = RefCell::new(HashMap::new());
    static DIGEST_STATE: RefCell<HashMap<u32, DigestCtx>> = RefCell::new(HashMap::new());
    static FIND_STATE: RefCell<HashMap<u32, FindCtx>> = RefCell::new(HashMap::new());
}

struct EncryptCtx {
    mech_type: u32,
    key_handle: u32,
    iv: Vec<u8>,
    #[allow(dead_code)]
    aad: Vec<u8>,
    #[allow(dead_code)]
    tag_bits: u32,
}

fn allocate_handle(attrs: Attributes) -> u32 {
    NEXT_HANDLE.with(|h| {
        let mut handle = h.borrow_mut();
        let current = *handle;
        *handle += 1;
        OBJECTS.with(|objs| {
            objs.borrow_mut().insert(current, attrs);
        });
        current
    })
}

fn get_object_value(handle: u32) -> Option<Vec<u8>> {
    OBJECTS.with(|objs| {
        objs.borrow()
            .get(&handle)
            .and_then(|attrs| attrs.get(&CKA_VALUE).cloned())
    })
}

fn get_object_param_set(handle: u32) -> u32 {
    OBJECTS.with(|objs| {
        objs.borrow()
            .get(&handle)
            .and_then(|attrs| attrs.get(&CKA_PRIV_PARAM_SET))
            .map(|v| {
                if v.len() >= 4 {
                    u32::from_le_bytes([v[0], v[1], v[2], v[3]])
                } else {
                    0
                }
            })
            .unwrap_or(0)
    })
}

fn get_object_algo_family(handle: u32) -> u32 {
    OBJECTS.with(|objs| {
        objs.borrow()
            .get(&handle)
            .and_then(|attrs| attrs.get(&CKA_PRIV_ALGO_FAMILY))
            .map(|v| {
                if v.len() >= 4 {
                    u32::from_le_bytes([v[0], v[1], v[2], v[3]])
                } else {
                    0
                }
            })
            .unwrap_or(0)
    })
}

// ── Template Parsing ─────────────────────────────────────────────────────────

/// Read a CK_ULONG attribute from a CK_ATTRIBUTE template array.
/// Each CK_ATTRIBUTE is 12 bytes: type(4) + pValue(4) + ulValueLen(4).
unsafe fn get_attr_ulong(template: *mut u8, count: u32, attr_type: u32) -> Option<u32> {
    if template.is_null() {
        return None;
    }
    let ptr = template as *mut u32;
    for i in 0..count {
        let t = *ptr.add((i * 3) as usize);
        if t == attr_type {
            let val_ptr = *ptr.add((i * 3 + 1) as usize) as usize as *const u32;
            if !val_ptr.is_null() {
                return Some(*val_ptr);
            }
        }
    }
    None
}

/// Read a byte-array attribute from a CK_ATTRIBUTE template array.
unsafe fn get_attr_bytes(template: *mut u8, count: u32, attr_type: u32) -> Option<Vec<u8>> {
    if template.is_null() {
        return None;
    }
    let ptr = template as *mut u32;
    for i in 0..count {
        let t = *ptr.add((i * 3) as usize);
        if t == attr_type {
            let val_ptr = *ptr.add((i * 3 + 1) as usize) as usize as *const u8;
            let val_len = *ptr.add((i * 3 + 2) as usize) as usize;
            if !val_ptr.is_null() && val_len > 0 {
                return Some(std::slice::from_raw_parts(val_ptr, val_len).to_vec());
            }
        }
    }
    None
}

/// Store parameter set as a 4-byte LE value in the attributes map.
fn store_param_set(attrs: &mut Attributes, ps: u32) {
    attrs.insert(CKA_PRIV_PARAM_SET, ps.to_le_bytes().to_vec());
}

/// Store algorithm family identifier in the attributes map.
fn store_algo_family(attrs: &mut Attributes, algo: u32) {
    attrs.insert(CKA_PRIV_ALGO_FAMILY, algo.to_le_bytes().to_vec());
}

// ── Memory Management ────────────────────────────────────────────────────────

#[wasm_bindgen(js_name = _malloc)]
pub fn malloc(size: usize) -> *mut u8 {
    let mut buf = Vec::with_capacity(size);
    let ptr = buf.as_mut_ptr();
    std::mem::forget(buf);
    ptr
}

#[wasm_bindgen(js_name = _free)]
pub fn free(ptr: *mut u8, size: usize) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        let _ = Vec::from_raw_parts(ptr, 0, if size == 0 { 1 } else { size });
    }
}

// ── Session Management ───────────────────────────────────────────────────────

#[wasm_bindgen(js_name = _C_Initialize)]
pub fn C_Initialize(_p_init_args: *mut u8) -> u32 {
    CKR_OK
}

#[wasm_bindgen(js_name = _C_Finalize)]
pub fn C_Finalize(_p_reserved: *mut u8) -> u32 {
    CKR_OK
}

#[wasm_bindgen(js_name = _C_GetSlotList)]
pub fn C_GetSlotList(_token_present: u8, p_slot_list: *mut u32, pul_count: *mut u32) -> u32 {
    unsafe {
        if p_slot_list.is_null() {
            *pul_count = 1;
        } else {
            *p_slot_list = 0;
            *pul_count = 1;
        }
    }
    CKR_OK
}

#[wasm_bindgen(js_name = _C_InitToken)]
pub fn C_InitToken(_slot_id: u32, _p_pin: *mut u8, _ul_pin_len: u32, _p_label: *mut u8) -> u32 {
    CKR_OK
}

#[wasm_bindgen(js_name = _C_OpenSession)]
pub fn C_OpenSession(
    _slot_id: u32,
    _flags: u32,
    _p_application: *mut u8,
    _notify: *mut u8,
    ph_session: *mut u32,
) -> u32 {
    unsafe {
        *ph_session = 1;
    }
    CKR_OK
}

#[wasm_bindgen(js_name = _C_CloseSession)]
pub fn C_CloseSession(_h_session: u32) -> u32 {
    CKR_OK
}

#[wasm_bindgen(js_name = _C_Login)]
pub fn C_Login(_h_session: u32, _user_type: u32, _p_pin: *mut u8, _ul_pin_len: u32) -> u32 {
    CKR_OK
}

#[wasm_bindgen(js_name = _C_Logout)]
pub fn C_Logout(_h_session: u32) -> u32 {
    CKR_OK
}

#[wasm_bindgen(js_name = _C_InitPIN)]
pub fn C_InitPIN(_h_session: u32, _p_pin: *mut u8, _ul_pin_len: u32) -> u32 {
    CKR_OK
}

// ── Session/Token Info ───────────────────────────────────────────────────────

unsafe fn write_fixed_str(buf: *mut u8, offset: usize, s: &str, max_len: usize) {
    let bytes = s.as_bytes();
    let copy_len = bytes.len().min(max_len);
    std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf.add(offset), copy_len);
}

#[wasm_bindgen(js_name = _C_GetSessionInfo)]
pub fn C_GetSessionInfo(_h_session: u32, p_info: *mut u8) -> u32 {
    if p_info.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    unsafe {
        let ptr = p_info as *mut u32;
        *ptr = 0;
        *ptr.add(1) = CKS_RW_USER_FUNCTIONS;
        *ptr.add(2) = CKF_SERIAL_SESSION | CKF_RW_SESSION;
        *ptr.add(3) = 0;
    }
    CKR_OK
}

#[wasm_bindgen(js_name = _C_GetTokenInfo)]
pub fn C_GetTokenInfo(_slot_id: u32, p_info: *mut u8) -> u32 {
    if p_info.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    unsafe {
        std::ptr::write_bytes(p_info, 0x20, 160);
        write_fixed_str(p_info, 0, "SoftHSM3-Rust", 32);
        write_fixed_str(p_info, 32, "PQC Today", 32);
        write_fixed_str(p_info, 64, "softhsmrustv3", 16);
        write_fixed_str(p_info, 80, "0001", 16);

        let ptr = p_info as *mut u32;
        *ptr.add(24) = 0x0004_040D;
        *ptr.add(25) = 256;
        *ptr.add(26) = 1;
        *ptr.add(27) = 256;
        *ptr.add(28) = 1;
        *ptr.add(29) = 256;
        *ptr.add(30) = 4;
        *p_info.add(140) = 3;
        *p_info.add(141) = 2;
        *p_info.add(142) = 0;
        *p_info.add(143) = 1;
    }
    CKR_OK
}

// ── Mechanism Discovery ──────────────────────────────────────────────────────

const SUPPORTED_MECHS: &[u32] = &[
    CKM_RSA_PKCS_KEY_PAIR_GEN, CKM_RSA_PKCS_OAEP,
    CKM_SHA256_RSA_PKCS, CKM_SHA256_RSA_PKCS_PSS,
    CKM_ML_KEM_KEY_PAIR_GEN, CKM_ML_KEM,
    CKM_ML_DSA_KEY_PAIR_GEN, CKM_ML_DSA,
    CKM_SLH_DSA_KEY_PAIR_GEN, CKM_SLH_DSA,
    CKM_SHA256, CKM_SHA384, CKM_SHA512, CKM_SHA3_256, CKM_SHA3_512,
    CKM_SHA256_HMAC, CKM_SHA384_HMAC, CKM_SHA512_HMAC,
    CKM_SHA3_256_HMAC, CKM_SHA3_512_HMAC,
    CKM_GENERIC_SECRET_KEY_GEN,
    CKM_EC_KEY_PAIR_GEN, CKM_ECDSA_SHA256, CKM_ECDSA_SHA384,
    CKM_ECDH1_DERIVE, CKM_EC_EDWARDS_KEY_PAIR_GEN, CKM_EDDSA,
    CKM_AES_KEY_GEN, CKM_AES_CBC_PAD, CKM_AES_GCM, CKM_AES_KEY_WRAP,
];

#[wasm_bindgen(js_name = _C_GetMechanismList)]
pub fn C_GetMechanismList(
    _slot_id: u32,
    p_mechanism_list: *mut u32,
    pul_count: *mut u32,
) -> u32 {
    unsafe {
        if p_mechanism_list.is_null() {
            *pul_count = SUPPORTED_MECHS.len() as u32;
        } else {
            let avail = *pul_count as usize;
            if avail < SUPPORTED_MECHS.len() {
                *pul_count = SUPPORTED_MECHS.len() as u32;
                return CKR_BUFFER_TOO_SMALL;
            }
            for (i, m) in SUPPORTED_MECHS.iter().enumerate() {
                *p_mechanism_list.add(i) = *m;
            }
            *pul_count = SUPPORTED_MECHS.len() as u32;
        }
    }
    CKR_OK
}

#[wasm_bindgen(js_name = _C_GetMechanismInfo)]
pub fn C_GetMechanismInfo(_slot_id: u32, mech_type: u32, p_info: *mut u8) -> u32 {
    if p_info.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let (min_key, max_key, flags) = match mech_type {
        CKM_RSA_PKCS_KEY_PAIR_GEN => (2048, 4096, 0x00010000u32),
        CKM_SHA256_RSA_PKCS | CKM_SHA256_RSA_PKCS_PSS => (2048, 4096, 0x00000800 | 0x00002000),
        CKM_RSA_PKCS_OAEP => (2048, 4096, 0x00000100 | 0x00000200),
        CKM_ML_KEM_KEY_PAIR_GEN => (512, 1024, 0x00010000),
        CKM_ML_KEM => (512, 1024, 0x10000000 | 0x20000000),
        CKM_ML_DSA_KEY_PAIR_GEN => (44, 87, 0x00010000),
        CKM_ML_DSA => (44, 87, 0x00000800 | 0x00002000),
        CKM_SLH_DSA_KEY_PAIR_GEN => (128, 256, 0x00010000),
        CKM_SLH_DSA => (128, 256, 0x00000800 | 0x00002000),
        CKM_SHA256 | CKM_SHA384 | CKM_SHA512 | CKM_SHA3_256 | CKM_SHA3_512 => (0, 0, 0x00000400),
        CKM_SHA256_HMAC | CKM_SHA384_HMAC | CKM_SHA512_HMAC |
        CKM_SHA3_256_HMAC | CKM_SHA3_512_HMAC => (16, 64, 0x00000800 | 0x00002000),
        CKM_GENERIC_SECRET_KEY_GEN => (1, 512, 0x00008000),
        CKM_EC_KEY_PAIR_GEN => (256, 384, 0x00010000),
        CKM_ECDSA_SHA256 | CKM_ECDSA_SHA384 => (256, 384, 0x00000800 | 0x00002000),
        CKM_ECDH1_DERIVE => (256, 384, 0x00080000),
        CKM_EC_EDWARDS_KEY_PAIR_GEN => (255, 255, 0x00010000),
        CKM_EDDSA => (255, 255, 0x00000800 | 0x00002000),
        CKM_AES_KEY_GEN => (16, 32, 0x00008000),
        CKM_AES_GCM | CKM_AES_CBC_PAD => (16, 32, 0x00000100 | 0x00000200),
        CKM_AES_KEY_WRAP => (16, 32, 0x00040000 | 0x00020000),
        _ => return CKR_MECHANISM_INVALID,
    };
    unsafe {
        let ptr = p_info as *mut u32;
        *ptr = min_key;
        *ptr.add(1) = max_key;
        *ptr.add(2) = flags;
    }
    CKR_OK
}

// ── SLH-DSA Macros ──────────────────────────────────────────────────────────

macro_rules! slh_dsa_keygen {
    ($ps:ty, $pub_attrs:expr, $prv_attrs:expr) => {{
        let mut rng = rand::rngs::OsRng;
        let sk = slh_dsa::SigningKey::<$ps>::new(&mut rng);
        let vk = sk.verifying_key();
        $pub_attrs.insert(CKA_VALUE, vk.to_bytes().as_slice().to_vec());
        $prv_attrs.insert(CKA_VALUE, sk.to_bytes().as_slice().to_vec());
    }};
}

macro_rules! slh_dsa_sign {
    ($ps:ty, $sk_bytes:expr, $msg:expr) => {{
        use signature::Signer;
        let sk = slh_dsa::SigningKey::<$ps>::try_from($sk_bytes)
            .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
        let sig = sk.try_sign($msg).map_err(|_| CKR_FUNCTION_FAILED)?;
        Ok(sig.to_bytes().as_slice().to_vec())
    }};
}

macro_rules! slh_dsa_verify {
    ($ps:ty, $pk_bytes:expr, $msg:expr, $sig_bytes:expr) => {{
        use signature::Verifier;
        let vk = slh_dsa::VerifyingKey::<$ps>::try_from($pk_bytes)
            .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
        let sig = slh_dsa::Signature::<$ps>::try_from($sig_bytes)
            .map_err(|_| CKR_SIGNATURE_INVALID)?;
        vk.verify($msg, &sig).map_err(|_| CKR_SIGNATURE_INVALID)
    }};
}

// ── Key Generation ───────────────────────────────────────────────────────────

#[wasm_bindgen(js_name = _C_GenerateKeyPair)]
pub fn C_GenerateKeyPair(
    _h_session: u32,
    p_mechanism: *mut u8,
    p_public_key_template: *mut u8,
    ul_public_key_attribute_count: u32,
    _p_private_key_template: *mut u8,
    _ul_private_key_attribute_count: u32,
    ph_public_key: *mut u32,
    ph_private_key: *mut u32,
) -> u32 {
    unsafe {
        let mech_type = *(p_mechanism as *const u32);

        match mech_type {
            CKM_ML_KEM_KEY_PAIR_GEN => {
                use ml_kem::{EncodedSizeUser, KemCore};
                use rand::rngs::OsRng;

                let ps = get_attr_ulong(p_public_key_template, ul_public_key_attribute_count, CKA_PARAMETER_SET)
                    .unwrap_or(CKP_ML_KEM_768);
                let mut pub_attrs = HashMap::new();
                let mut prv_attrs = HashMap::new();
                store_param_set(&mut pub_attrs, ps);
                store_param_set(&mut prv_attrs, ps);
                store_algo_family(&mut pub_attrs, ALGO_ML_KEM);
                store_algo_family(&mut prv_attrs, ALGO_ML_KEM);

                let mut rng = OsRng;
                match ps {
                    CKP_ML_KEM_512 => {
                        let (dk, ek) = ml_kem::MlKem512::generate(&mut rng);
                        pub_attrs.insert(CKA_VALUE, ek.as_bytes().as_slice().to_vec());
                        prv_attrs.insert(CKA_VALUE, dk.as_bytes().as_slice().to_vec());
                    }
                    CKP_ML_KEM_768 => {
                        let (dk, ek) = ml_kem::MlKem768::generate(&mut rng);
                        pub_attrs.insert(CKA_VALUE, ek.as_bytes().as_slice().to_vec());
                        prv_attrs.insert(CKA_VALUE, dk.as_bytes().as_slice().to_vec());
                    }
                    CKP_ML_KEM_1024 => {
                        let (dk, ek) = ml_kem::MlKem1024::generate(&mut rng);
                        pub_attrs.insert(CKA_VALUE, ek.as_bytes().as_slice().to_vec());
                        prv_attrs.insert(CKA_VALUE, dk.as_bytes().as_slice().to_vec());
                    }
                    _ => return CKR_ARGUMENTS_BAD,
                }
                *ph_public_key = allocate_handle(pub_attrs);
                *ph_private_key = allocate_handle(prv_attrs);
                CKR_OK
            }

            CKM_ML_DSA_KEY_PAIR_GEN => {
                let ps = get_attr_ulong(p_public_key_template, ul_public_key_attribute_count, CKA_PARAMETER_SET)
                    .unwrap_or(CKP_ML_DSA_65);
                let mut seed_bytes = [0u8; 32];
                if getrandom::getrandom(&mut seed_bytes).is_err() {
                    return CKR_FUNCTION_FAILED;
                }
                let seed: ml_dsa::Seed = seed_bytes.into();
                let mut pub_attrs = HashMap::new();
                let mut prv_attrs = HashMap::new();
                store_param_set(&mut pub_attrs, ps);
                store_param_set(&mut prv_attrs, ps);
                store_algo_family(&mut pub_attrs, ALGO_ML_DSA);
                store_algo_family(&mut prv_attrs, ALGO_ML_DSA);

                match ps {
                    CKP_ML_DSA_44 => {
                        let sk = ml_dsa::SigningKey::<ml_dsa::MlDsa44>::from_seed(&seed);
                        let vk = sk.verifying_key();
                        pub_attrs.insert(CKA_VALUE, vk.encode().as_slice().to_vec());
                        #[allow(deprecated)]
                        prv_attrs.insert(CKA_VALUE, sk.to_expanded().as_slice().to_vec());
                    }
                    CKP_ML_DSA_65 => {
                        let sk = ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_seed(&seed);
                        let vk = sk.verifying_key();
                        pub_attrs.insert(CKA_VALUE, vk.encode().as_slice().to_vec());
                        #[allow(deprecated)]
                        prv_attrs.insert(CKA_VALUE, sk.to_expanded().as_slice().to_vec());
                    }
                    CKP_ML_DSA_87 => {
                        let sk = ml_dsa::SigningKey::<ml_dsa::MlDsa87>::from_seed(&seed);
                        let vk = sk.verifying_key();
                        pub_attrs.insert(CKA_VALUE, vk.encode().as_slice().to_vec());
                        #[allow(deprecated)]
                        prv_attrs.insert(CKA_VALUE, sk.to_expanded().as_slice().to_vec());
                    }
                    _ => return CKR_ARGUMENTS_BAD,
                }
                *ph_public_key = allocate_handle(pub_attrs);
                *ph_private_key = allocate_handle(prv_attrs);
                CKR_OK
            }

            CKM_SLH_DSA_KEY_PAIR_GEN => {
                let ps = get_attr_ulong(p_public_key_template, ul_public_key_attribute_count, CKA_PARAMETER_SET)
                    .unwrap_or(CKP_SLH_DSA_SHA2_128F);
                let mut pub_attrs = HashMap::new();
                let mut prv_attrs = HashMap::new();
                store_param_set(&mut pub_attrs, ps);
                store_param_set(&mut prv_attrs, ps);
                store_algo_family(&mut pub_attrs, ALGO_SLH_DSA);
                store_algo_family(&mut prv_attrs, ALGO_SLH_DSA);

                match ps {
                    CKP_SLH_DSA_SHA2_128S  => slh_dsa_keygen!(slh_dsa::Sha2_128s, pub_attrs, prv_attrs),
                    CKP_SLH_DSA_SHAKE_128S => slh_dsa_keygen!(slh_dsa::Shake128s, pub_attrs, prv_attrs),
                    CKP_SLH_DSA_SHA2_128F  => slh_dsa_keygen!(slh_dsa::Sha2_128f, pub_attrs, prv_attrs),
                    CKP_SLH_DSA_SHAKE_128F => slh_dsa_keygen!(slh_dsa::Shake128f, pub_attrs, prv_attrs),
                    CKP_SLH_DSA_SHA2_192S  => slh_dsa_keygen!(slh_dsa::Sha2_192s, pub_attrs, prv_attrs),
                    CKP_SLH_DSA_SHAKE_192S => slh_dsa_keygen!(slh_dsa::Shake192s, pub_attrs, prv_attrs),
                    CKP_SLH_DSA_SHA2_192F  => slh_dsa_keygen!(slh_dsa::Sha2_192f, pub_attrs, prv_attrs),
                    CKP_SLH_DSA_SHAKE_192F => slh_dsa_keygen!(slh_dsa::Shake192f, pub_attrs, prv_attrs),
                    CKP_SLH_DSA_SHA2_256S  => slh_dsa_keygen!(slh_dsa::Sha2_256s, pub_attrs, prv_attrs),
                    CKP_SLH_DSA_SHAKE_256S => slh_dsa_keygen!(slh_dsa::Shake256s, pub_attrs, prv_attrs),
                    CKP_SLH_DSA_SHA2_256F  => slh_dsa_keygen!(slh_dsa::Sha2_256f, pub_attrs, prv_attrs),
                    CKP_SLH_DSA_SHAKE_256F => slh_dsa_keygen!(slh_dsa::Shake256f, pub_attrs, prv_attrs),
                    _ => return CKR_ARGUMENTS_BAD,
                }
                *ph_public_key = allocate_handle(pub_attrs);
                *ph_private_key = allocate_handle(prv_attrs);
                CKR_OK
            }

            CKM_RSA_PKCS_KEY_PAIR_GEN => {
                let bits = get_attr_ulong(p_public_key_template, ul_public_key_attribute_count, CKA_MODULUS_BITS)
                    .unwrap_or(2048) as usize;
                let mut rng = rand::rngs::OsRng;
                let private_key = match rsa::RsaPrivateKey::new(&mut rng, bits) {
                    Ok(k) => k,
                    Err(_) => return CKR_FUNCTION_FAILED,
                };
                let public_key = rsa::RsaPublicKey::from(&private_key);

                use rsa::pkcs8::EncodePrivateKey;
                let sk_der = match private_key.to_pkcs8_der() {
                    Ok(d) => d,
                    Err(_) => return CKR_FUNCTION_FAILED,
                };

                // Public key: [n_len:4LE][n_bytes][e_bytes]
                use rsa::traits::PublicKeyParts;
                let n_bytes = public_key.n().to_bytes_be();
                let e_bytes = public_key.e().to_bytes_be();
                let mut pk_bytes = Vec::with_capacity(4 + n_bytes.len() + e_bytes.len());
                pk_bytes.extend_from_slice(&(n_bytes.len() as u32).to_le_bytes());
                pk_bytes.extend_from_slice(&n_bytes);
                pk_bytes.extend_from_slice(&e_bytes);

                let mut pub_attrs = HashMap::new();
                let mut prv_attrs = HashMap::new();
                store_algo_family(&mut pub_attrs, ALGO_RSA);
                store_algo_family(&mut prv_attrs, ALGO_RSA);
                pub_attrs.insert(CKA_VALUE, pk_bytes);
                prv_attrs.insert(CKA_VALUE, sk_der.as_bytes().to_vec());

                *ph_public_key = allocate_handle(pub_attrs);
                *ph_private_key = allocate_handle(prv_attrs);
                CKR_OK
            }

            CKM_EC_KEY_PAIR_GEN => {
                let mut rng = rand::rngs::OsRng;
                let ec_params = get_attr_bytes(p_public_key_template, ul_public_key_attribute_count, CKA_EC_PARAMS);
                let is_p384 = ec_params.as_ref().map_or(false, |b| {
                    b.len() >= 7 && b[b.len()-1] == 0x22
                });

                let mut pub_attrs = HashMap::new();
                let mut prv_attrs = HashMap::new();
                store_algo_family(&mut pub_attrs, ALGO_ECDSA);
                store_algo_family(&mut prv_attrs, ALGO_ECDSA);

                if is_p384 {
                    store_param_set(&mut pub_attrs, CURVE_P384);
                    store_param_set(&mut prv_attrs, CURVE_P384);
                    let sk = p384::ecdsa::SigningKey::random(&mut rng);
                    let vk = p384::ecdsa::VerifyingKey::from(&sk);
                    prv_attrs.insert(CKA_VALUE, sk.to_bytes().to_vec());
                    pub_attrs.insert(CKA_VALUE, vk.to_encoded_point(false).as_bytes().to_vec());
                } else {
                    store_param_set(&mut pub_attrs, CURVE_P256);
                    store_param_set(&mut prv_attrs, CURVE_P256);
                    let sk = p256::ecdsa::SigningKey::random(&mut rng);
                    let vk = p256::ecdsa::VerifyingKey::from(&sk);
                    prv_attrs.insert(CKA_VALUE, sk.to_bytes().to_vec());
                    pub_attrs.insert(CKA_VALUE, vk.to_encoded_point(false).as_bytes().to_vec());
                }
                *ph_public_key = allocate_handle(pub_attrs);
                *ph_private_key = allocate_handle(prv_attrs);
                CKR_OK
            }

            CKM_EC_EDWARDS_KEY_PAIR_GEN => {
                let mut rng = rand::rngs::OsRng;
                let sk = ed25519_dalek::SigningKey::generate(&mut rng);
                let vk = sk.verifying_key();

                let mut pub_attrs = HashMap::new();
                let mut prv_attrs = HashMap::new();
                store_algo_family(&mut pub_attrs, ALGO_EDDSA);
                store_algo_family(&mut prv_attrs, ALGO_EDDSA);
                prv_attrs.insert(CKA_VALUE, sk.to_bytes().to_vec());
                pub_attrs.insert(CKA_VALUE, vk.to_bytes().to_vec());

                *ph_public_key = allocate_handle(pub_attrs);
                *ph_private_key = allocate_handle(prv_attrs);
                CKR_OK
            }

            _ => CKR_MECHANISM_INVALID,
        }
    }
}

#[wasm_bindgen(js_name = _C_GenerateKey)]
pub fn C_GenerateKey(
    _h_session: u32,
    p_mechanism: *mut u8,
    p_template: *mut u8,
    ul_count: u32,
    ph_key: *mut u32,
) -> u32 {
    unsafe {
        let mech_type = *(p_mechanism as *const u32);
        match mech_type {
            CKM_AES_KEY_GEN => {
                let key_len = get_attr_ulong(p_template, ul_count, CKA_VALUE_LEN).unwrap_or(16) as usize;
                if key_len != 16 && key_len != 24 && key_len != 32 {
                    return CKR_ARGUMENTS_BAD;
                }
                let mut key = vec![0u8; key_len];
                if getrandom::getrandom(&mut key).is_err() {
                    return CKR_FUNCTION_FAILED;
                }
                let mut attrs = HashMap::new();
                attrs.insert(CKA_VALUE, key);
                *ph_key = allocate_handle(attrs);
                CKR_OK
            }
            CKM_GENERIC_SECRET_KEY_GEN => {
                let key_len = get_attr_ulong(p_template, ul_count, CKA_VALUE_LEN).unwrap_or(32) as usize;
                if key_len == 0 || key_len > 512 {
                    return CKR_ARGUMENTS_BAD;
                }
                let mut key = vec![0u8; key_len];
                if getrandom::getrandom(&mut key).is_err() {
                    return CKR_FUNCTION_FAILED;
                }
                let mut attrs = HashMap::new();
                attrs.insert(CKA_VALUE, key);
                *ph_key = allocate_handle(attrs);
                CKR_OK
            }
            _ => CKR_MECHANISM_INVALID,
        }
    }
}

// ── ML-KEM Encapsulate/Decapsulate ──────────────────────────────────────────

#[wasm_bindgen(js_name = _C_EncapsulateKey)]
pub fn C_EncapsulateKey(
    _h_session: u32, p_mechanism: *mut u8, h_key: u32,
    _p_template: *mut u8, _ul_attribute_count: u32,
    p_ciphertext: *mut u8, pul_ciphertext_len: *mut u32, ph_key: *mut u32,
) -> u32 {
    use ml_kem::{kem::Encapsulate, EncodedSizeUser, KemCore};
    use rand::rngs::OsRng;

    unsafe {
        let mech_type = *(p_mechanism as *const u32);
        if mech_type != CKM_ML_KEM { return CKR_MECHANISM_INVALID; }

        let ps = get_object_param_set(h_key);
        let ct_len: u32 = match ps {
            CKP_ML_KEM_512 => 768, CKP_ML_KEM_768 | 0 => 1088, CKP_ML_KEM_1024 => 1568,
            _ => return CKR_ARGUMENTS_BAD,
        };
        if p_ciphertext.is_null() { *pul_ciphertext_len = ct_len; return CKR_OK; }

        let pub_key_bytes = match get_object_value(h_key) { Some(v) => v, None => return CKR_ARGUMENTS_BAD };
        let mut rng = OsRng;

        macro_rules! encap {
            ($kem:ty) => {{
                let ek_enc = match ml_kem::array::Array::try_from(pub_key_bytes.as_slice()) {
                    Ok(a) => a, Err(_) => return CKR_KEY_TYPE_INCONSISTENT,
                };
                let ek = <$kem as KemCore>::EncapsulationKey::from_bytes(&ek_enc);
                let (ct, ss) = Encapsulate::encapsulate(&ek, &mut rng).unwrap();
                std::ptr::copy_nonoverlapping(ct.as_slice().as_ptr(), p_ciphertext, ct_len as usize);
                *pul_ciphertext_len = ct_len;
                let mut ss_attrs = HashMap::new();
                ss_attrs.insert(CKA_VALUE, ss.as_slice().to_vec());
                *ph_key = allocate_handle(ss_attrs);
            }};
        }

        match ps {
            CKP_ML_KEM_512 => encap!(ml_kem::MlKem512),
            CKP_ML_KEM_768 | 0 => encap!(ml_kem::MlKem768),
            CKP_ML_KEM_1024 => encap!(ml_kem::MlKem1024),
            _ => return CKR_ARGUMENTS_BAD,
        }
    }
    CKR_OK
}

#[wasm_bindgen(js_name = _C_DecapsulateKey)]
pub fn C_DecapsulateKey(
    _h_session: u32, p_mechanism: *mut u8, h_private_key: u32,
    _p_template: *mut u8, _ul_attribute_count: u32,
    p_ciphertext: *mut u8, ul_ciphertext_len: u32, ph_key: *mut u32,
) -> u32 {
    use ml_kem::{kem::Decapsulate, EncodedSizeUser, KemCore};

    unsafe {
        let mech_type = *(p_mechanism as *const u32);
        if mech_type != CKM_ML_KEM { return CKR_MECHANISM_INVALID; }

        let ps = get_object_param_set(h_private_key);
        let expected_ct: u32 = match ps {
            CKP_ML_KEM_512 => 768, CKP_ML_KEM_768 | 0 => 1088, CKP_ML_KEM_1024 => 1568,
            _ => return CKR_ARGUMENTS_BAD,
        };
        if ul_ciphertext_len != expected_ct { return CKR_ARGUMENTS_BAD; }

        let prv_key_bytes = match get_object_value(h_private_key) { Some(v) => v, None => return CKR_ARGUMENTS_BAD };
        let ct_bytes = std::slice::from_raw_parts(p_ciphertext, ul_ciphertext_len as usize).to_vec();

        macro_rules! decap {
            ($kem:ty) => {{
                let dk_enc = match ml_kem::array::Array::try_from(prv_key_bytes.as_slice()) {
                    Ok(a) => a, Err(_) => return CKR_KEY_TYPE_INCONSISTENT,
                };
                let dk = <$kem as KemCore>::DecapsulationKey::from_bytes(&dk_enc);
                let ct_enc = match ml_kem::array::Array::try_from(ct_bytes.as_slice()) {
                    Ok(a) => a, Err(_) => return CKR_ARGUMENTS_BAD,
                };
                let ss = Decapsulate::decapsulate(&dk, &ct_enc).unwrap();
                let mut ss_attrs = HashMap::new();
                ss_attrs.insert(CKA_VALUE, ss.as_slice().to_vec());
                *ph_key = allocate_handle(ss_attrs);
            }};
        }

        match ps {
            CKP_ML_KEM_512 => decap!(ml_kem::MlKem512),
            CKP_ML_KEM_768 | 0 => decap!(ml_kem::MlKem768),
            CKP_ML_KEM_1024 => decap!(ml_kem::MlKem1024),
            _ => return CKR_ARGUMENTS_BAD,
        }
    }
    CKR_OK
}

// ── Object Operations ────────────────────────────────────────────────────────

#[wasm_bindgen(js_name = _C_GetAttributeValue)]
pub fn C_GetAttributeValue(_h_session: u32, h_object: u32, p_template: *mut u8, count: u32) -> u32 {
    let attrs = OBJECTS.with(|o| o.borrow().get(&h_object).cloned());
    if let Some(obj_attrs) = attrs {
        unsafe {
            let tmpl_ptr = p_template as *mut u32;
            for i in 0..count {
                let attr_type = *tmpl_ptr.add((i * 3) as usize);
                let val_ptr = *tmpl_ptr.add((i * 3 + 1) as usize) as usize as *mut u8;
                let val_len_ptr = tmpl_ptr.add((i * 3 + 2) as usize);
                if let Some(val) = obj_attrs.get(&attr_type) {
                    if val_ptr.is_null() {
                        *val_len_ptr = val.len() as u32;
                    } else if *val_len_ptr >= val.len() as u32 {
                        std::ptr::copy_nonoverlapping(val.as_ptr(), val_ptr, val.len());
                        *val_len_ptr = val.len() as u32;
                    } else {
                        return CKR_BUFFER_TOO_SMALL;
                    }
                }
            }
        }
        CKR_OK
    } else {
        CKR_ARGUMENTS_BAD
    }
}

#[wasm_bindgen(js_name = _C_CreateObject)]
pub fn C_CreateObject(_h_session: u32, p_template: *mut u8, count: u32, ph_object: *mut u32) -> u32 {
    unsafe {
        let tmpl_ptr = p_template as *mut u32;
        let mut new_attrs = HashMap::new();
        for i in 0..count {
            let attr_type = *tmpl_ptr.add((i * 3) as usize);
            let val_ptr = *tmpl_ptr.add((i * 3 + 1) as usize) as usize as *const u8;
            let val_len = *tmpl_ptr.add((i * 3 + 2) as usize);
            if !val_ptr.is_null() && val_len > 0 {
                let mut v = vec![0u8; val_len as usize];
                std::ptr::copy_nonoverlapping(val_ptr, v.as_mut_ptr(), val_len as usize);
                new_attrs.insert(attr_type, v);
            }
        }
        if let Some(ps_bytes) = new_attrs.get(&CKA_PARAMETER_SET).cloned() {
            if ps_bytes.len() >= 4 {
                let ps = u32::from_le_bytes([ps_bytes[0], ps_bytes[1], ps_bytes[2], ps_bytes[3]]);
                store_param_set(&mut new_attrs, ps);
            }
        }
        *ph_object = allocate_handle(new_attrs);
    }
    CKR_OK
}

#[wasm_bindgen(js_name = _C_DestroyObject)]
pub fn C_DestroyObject(_h_session: u32, h_object: u32) -> u32 {
    let removed = OBJECTS.with(|objs| objs.borrow_mut().remove(&h_object).is_some());
    if removed { CKR_OK } else { CKR_OBJECT_HANDLE_INVALID }
}

// ── Sign Helpers ────────────────────────────────────────────────────────────

fn sign_ml_dsa(ps: u32, sk_bytes: &[u8], msg: &[u8]) -> Result<Vec<u8>, u32> {
    use signature::Signer;
    match ps {
        CKP_ML_DSA_44 => {
            let sk_enc = ml_dsa::ExpandedSigningKey::<ml_dsa::MlDsa44>::try_from(sk_bytes)
                .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            #[allow(deprecated)]
            let sk = ml_dsa::SigningKey::<ml_dsa::MlDsa44>::from_expanded(&sk_enc);
            Ok(sk.try_sign(msg).map_err(|_| CKR_FUNCTION_FAILED)?.encode().as_slice().to_vec())
        }
        CKP_ML_DSA_65 | 0 => {
            let sk_enc = ml_dsa::ExpandedSigningKey::<ml_dsa::MlDsa65>::try_from(sk_bytes)
                .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            #[allow(deprecated)]
            let sk = ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_expanded(&sk_enc);
            Ok(sk.try_sign(msg).map_err(|_| CKR_FUNCTION_FAILED)?.encode().as_slice().to_vec())
        }
        CKP_ML_DSA_87 => {
            let sk_enc = ml_dsa::ExpandedSigningKey::<ml_dsa::MlDsa87>::try_from(sk_bytes)
                .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            #[allow(deprecated)]
            let sk = ml_dsa::SigningKey::<ml_dsa::MlDsa87>::from_expanded(&sk_enc);
            Ok(sk.try_sign(msg).map_err(|_| CKR_FUNCTION_FAILED)?.encode().as_slice().to_vec())
        }
        _ => Err(CKR_KEY_TYPE_INCONSISTENT),
    }
}

fn sign_slh_dsa(ps: u32, sk_bytes: &[u8], msg: &[u8]) -> Result<Vec<u8>, u32> {
    match ps {
        CKP_SLH_DSA_SHA2_128S  => slh_dsa_sign!(slh_dsa::Sha2_128s, sk_bytes, msg),
        CKP_SLH_DSA_SHAKE_128S => slh_dsa_sign!(slh_dsa::Shake128s, sk_bytes, msg),
        CKP_SLH_DSA_SHA2_128F  => slh_dsa_sign!(slh_dsa::Sha2_128f, sk_bytes, msg),
        CKP_SLH_DSA_SHAKE_128F => slh_dsa_sign!(slh_dsa::Shake128f, sk_bytes, msg),
        CKP_SLH_DSA_SHA2_192S  => slh_dsa_sign!(slh_dsa::Sha2_192s, sk_bytes, msg),
        CKP_SLH_DSA_SHAKE_192S => slh_dsa_sign!(slh_dsa::Shake192s, sk_bytes, msg),
        CKP_SLH_DSA_SHA2_192F  => slh_dsa_sign!(slh_dsa::Sha2_192f, sk_bytes, msg),
        CKP_SLH_DSA_SHAKE_192F => slh_dsa_sign!(slh_dsa::Shake192f, sk_bytes, msg),
        CKP_SLH_DSA_SHA2_256S  => slh_dsa_sign!(slh_dsa::Sha2_256s, sk_bytes, msg),
        CKP_SLH_DSA_SHAKE_256S => slh_dsa_sign!(slh_dsa::Shake256s, sk_bytes, msg),
        CKP_SLH_DSA_SHA2_256F  => slh_dsa_sign!(slh_dsa::Sha2_256f, sk_bytes, msg),
        CKP_SLH_DSA_SHAKE_256F => slh_dsa_sign!(slh_dsa::Shake256f, sk_bytes, msg),
        _ => Err(CKR_KEY_TYPE_INCONSISTENT),
    }
}

fn sign_hmac(mech: u32, key_bytes: &[u8], msg: &[u8]) -> Result<Vec<u8>, u32> {
    use hmac::{Hmac, Mac};
    match mech {
        CKM_SHA256_HMAC => {
            let mut mac = Hmac::<sha2::Sha256>::new_from_slice(key_bytes).map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            mac.update(msg); Ok(mac.finalize().into_bytes().to_vec())
        }
        CKM_SHA384_HMAC => {
            let mut mac = Hmac::<sha2::Sha384>::new_from_slice(key_bytes).map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            mac.update(msg); Ok(mac.finalize().into_bytes().to_vec())
        }
        CKM_SHA512_HMAC => {
            let mut mac = Hmac::<sha2::Sha512>::new_from_slice(key_bytes).map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            mac.update(msg); Ok(mac.finalize().into_bytes().to_vec())
        }
        CKM_SHA3_256_HMAC => {
            let mut mac = Hmac::<sha3::Sha3_256>::new_from_slice(key_bytes).map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            mac.update(msg); Ok(mac.finalize().into_bytes().to_vec())
        }
        CKM_SHA3_512_HMAC => {
            let mut mac = Hmac::<sha3::Sha3_512>::new_from_slice(key_bytes).map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            mac.update(msg); Ok(mac.finalize().into_bytes().to_vec())
        }
        _ => Err(CKR_MECHANISM_INVALID),
    }
}

fn sign_rsa(mech: u32, sk_bytes: &[u8], msg: &[u8]) -> Result<Vec<u8>, u32> {
    use rsa::pkcs8::DecodePrivateKey;
    use sha2::Digest;
    let private_key = rsa::RsaPrivateKey::from_pkcs8_der(sk_bytes).map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
    match mech {
        CKM_SHA256_RSA_PKCS => {
            let hash = sha2::Sha256::digest(msg);
            private_key.sign(rsa::Pkcs1v15Sign::new::<sha2::Sha256>(), &hash).map_err(|_| CKR_FUNCTION_FAILED)
        }
        CKM_SHA256_RSA_PKCS_PSS => {
            use rsa::pss::BlindedSigningKey;
            use rsa::signature::RandomizedSigner;
            let signing_key = BlindedSigningKey::<sha2::Sha256>::new(private_key);
            let mut rng = rand::rngs::OsRng;
            let sig = signing_key.sign_with_rng(&mut rng, msg);
            Ok(sig.into())
        }
        _ => Err(CKR_MECHANISM_INVALID),
    }
}

fn sign_ecdsa(mech: u32, curve: u32, sk_bytes: &[u8], msg: &[u8]) -> Result<Vec<u8>, u32> {
    match (mech, curve) {
        (CKM_ECDSA_SHA256, CURVE_P256) | (CKM_ECDSA_SHA256, 0) => {
            let sk = p256::ecdsa::SigningKey::from_bytes(sk_bytes.into()).map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            use p256::ecdsa::signature::Signer;
            let sig: p256::ecdsa::Signature = sk.sign(msg);
            Ok(sig.to_bytes().to_vec())
        }
        (CKM_ECDSA_SHA384, CURVE_P384) => {
            let sk = p384::ecdsa::SigningKey::from_bytes(sk_bytes.into()).map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            use p384::ecdsa::signature::Signer;
            let sig: p384::ecdsa::Signature = sk.sign(msg);
            Ok(sig.to_bytes().to_vec())
        }
        _ => Err(CKR_MECHANISM_INVALID),
    }
}

fn sign_eddsa(sk_bytes: &[u8], msg: &[u8]) -> Result<Vec<u8>, u32> {
    if sk_bytes.len() != 32 { return Err(CKR_KEY_TYPE_INCONSISTENT); }
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(sk_bytes);
    let sk = ed25519_dalek::SigningKey::from_bytes(&key_bytes);
    use ed25519_dalek::Signer;
    Ok(sk.sign(msg).to_bytes().to_vec())
}

fn get_sig_len(mech: u32, hkey: u32) -> u32 {
    let ps = get_object_param_set(hkey);
    match mech {
        CKM_ML_DSA => match ps { CKP_ML_DSA_44 => 2420, CKP_ML_DSA_87 => 4627, _ => 3309 },
        CKM_SLH_DSA => match ps {
            CKP_SLH_DSA_SHA2_128S | CKP_SLH_DSA_SHAKE_128S => 7856,
            CKP_SLH_DSA_SHA2_128F | CKP_SLH_DSA_SHAKE_128F => 17088,
            CKP_SLH_DSA_SHA2_192S | CKP_SLH_DSA_SHAKE_192S => 16224,
            CKP_SLH_DSA_SHA2_192F | CKP_SLH_DSA_SHAKE_192F => 35664,
            CKP_SLH_DSA_SHA2_256S | CKP_SLH_DSA_SHAKE_256S => 29792,
            _ => 49856,
        },
        CKM_SHA256_HMAC | CKM_SHA3_256_HMAC => 32,
        CKM_SHA384_HMAC => 48,
        CKM_SHA512_HMAC | CKM_SHA3_512_HMAC => 64,
        CKM_SHA256_RSA_PKCS | CKM_SHA256_RSA_PKCS_PSS => 512,
        CKM_ECDSA_SHA256 => 64,
        CKM_ECDSA_SHA384 => 96,
        CKM_EDDSA => 64,
        _ => 512,
    }
}

// ── Sign/Verify ─────────────────────────────────────────────────────────────

#[wasm_bindgen(js_name = _C_SignInit)]
pub fn C_SignInit(h_session: u32, p_mechanism: *mut u8, h_key: u32) -> u32 {
    unsafe {
        if p_mechanism.is_null() { return CKR_ARGUMENTS_BAD; }
        let mech_type = *(p_mechanism as *const u32);
        SIGN_STATE.with(|s| { s.borrow_mut().insert(h_session, (mech_type, h_key)); });
    }
    CKR_OK
}

#[wasm_bindgen(js_name = _C_Sign)]
pub fn C_Sign(h_session: u32, p_data: *mut u8, ul_data_len: u32, p_signature: *mut u8, pul_signature_len: *mut u32) -> u32 {
    let state = SIGN_STATE.with(|s| s.borrow().get(&h_session).copied());
    let (mech, hkey) = match state { Some(s) => s, None => return CKR_OPERATION_NOT_INITIALIZED };

    unsafe {
        if p_signature.is_null() { *pul_signature_len = get_sig_len(mech, hkey); return CKR_OK; }

        let sk_bytes = match get_object_value(hkey) { Some(v) => v, None => return CKR_ARGUMENTS_BAD };
        let msg = std::slice::from_raw_parts(p_data, ul_data_len as usize);
        let ps = get_object_param_set(hkey);

        let result = match mech {
            CKM_ML_DSA => sign_ml_dsa(ps, &sk_bytes, msg),
            CKM_SLH_DSA => sign_slh_dsa(ps, &sk_bytes, msg),
            CKM_SHA256_HMAC | CKM_SHA384_HMAC | CKM_SHA512_HMAC |
            CKM_SHA3_256_HMAC | CKM_SHA3_512_HMAC => sign_hmac(mech, &sk_bytes, msg),
            CKM_SHA256_RSA_PKCS | CKM_SHA256_RSA_PKCS_PSS => sign_rsa(mech, &sk_bytes, msg),
            CKM_ECDSA_SHA256 | CKM_ECDSA_SHA384 => sign_ecdsa(mech, ps, &sk_bytes, msg),
            CKM_EDDSA => sign_eddsa(&sk_bytes, msg),
            _ => Err(CKR_MECHANISM_INVALID),
        };

        match result {
            Ok(sig) => {
                if (*pul_signature_len as usize) < sig.len() { *pul_signature_len = sig.len() as u32; return CKR_BUFFER_TOO_SMALL; }
                std::ptr::copy_nonoverlapping(sig.as_ptr(), p_signature, sig.len());
                *pul_signature_len = sig.len() as u32;
                CKR_OK
            }
            Err(e) => e,
        }
    }
}

// ── Verify Helpers ──────────────────────────────────────────────────────────

fn verify_ml_dsa(ps: u32, pk_bytes: &[u8], msg: &[u8], sig_bytes: &[u8]) -> Result<(), u32> {
    use signature::Verifier;
    match ps {
        CKP_ML_DSA_44 => {
            let pk_enc = ml_dsa::EncodedVerifyingKey::<ml_dsa::MlDsa44>::try_from(pk_bytes).map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            let vk = ml_dsa::VerifyingKey::<ml_dsa::MlDsa44>::decode(&pk_enc);
            let sig = ml_dsa::Signature::<ml_dsa::MlDsa44>::try_from(sig_bytes).map_err(|_| CKR_SIGNATURE_INVALID)?;
            vk.verify(msg, &sig).map_err(|_| CKR_SIGNATURE_INVALID)
        }
        CKP_ML_DSA_65 | 0 => {
            let pk_enc = ml_dsa::EncodedVerifyingKey::<ml_dsa::MlDsa65>::try_from(pk_bytes).map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            let vk = ml_dsa::VerifyingKey::<ml_dsa::MlDsa65>::decode(&pk_enc);
            let sig = ml_dsa::Signature::<ml_dsa::MlDsa65>::try_from(sig_bytes).map_err(|_| CKR_SIGNATURE_INVALID)?;
            vk.verify(msg, &sig).map_err(|_| CKR_SIGNATURE_INVALID)
        }
        CKP_ML_DSA_87 => {
            let pk_enc = ml_dsa::EncodedVerifyingKey::<ml_dsa::MlDsa87>::try_from(pk_bytes).map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            let vk = ml_dsa::VerifyingKey::<ml_dsa::MlDsa87>::decode(&pk_enc);
            let sig = ml_dsa::Signature::<ml_dsa::MlDsa87>::try_from(sig_bytes).map_err(|_| CKR_SIGNATURE_INVALID)?;
            vk.verify(msg, &sig).map_err(|_| CKR_SIGNATURE_INVALID)
        }
        _ => Err(CKR_KEY_TYPE_INCONSISTENT),
    }
}

fn verify_slh_dsa(ps: u32, pk_bytes: &[u8], msg: &[u8], sig_bytes: &[u8]) -> Result<(), u32> {
    match ps {
        CKP_SLH_DSA_SHA2_128S  => slh_dsa_verify!(slh_dsa::Sha2_128s, pk_bytes, msg, sig_bytes),
        CKP_SLH_DSA_SHAKE_128S => slh_dsa_verify!(slh_dsa::Shake128s, pk_bytes, msg, sig_bytes),
        CKP_SLH_DSA_SHA2_128F  => slh_dsa_verify!(slh_dsa::Sha2_128f, pk_bytes, msg, sig_bytes),
        CKP_SLH_DSA_SHAKE_128F => slh_dsa_verify!(slh_dsa::Shake128f, pk_bytes, msg, sig_bytes),
        CKP_SLH_DSA_SHA2_192S  => slh_dsa_verify!(slh_dsa::Sha2_192s, pk_bytes, msg, sig_bytes),
        CKP_SLH_DSA_SHAKE_192S => slh_dsa_verify!(slh_dsa::Shake192s, pk_bytes, msg, sig_bytes),
        CKP_SLH_DSA_SHA2_192F  => slh_dsa_verify!(slh_dsa::Sha2_192f, pk_bytes, msg, sig_bytes),
        CKP_SLH_DSA_SHAKE_192F => slh_dsa_verify!(slh_dsa::Shake192f, pk_bytes, msg, sig_bytes),
        CKP_SLH_DSA_SHA2_256S  => slh_dsa_verify!(slh_dsa::Sha2_256s, pk_bytes, msg, sig_bytes),
        CKP_SLH_DSA_SHAKE_256S => slh_dsa_verify!(slh_dsa::Shake256s, pk_bytes, msg, sig_bytes),
        CKP_SLH_DSA_SHA2_256F  => slh_dsa_verify!(slh_dsa::Sha2_256f, pk_bytes, msg, sig_bytes),
        CKP_SLH_DSA_SHAKE_256F => slh_dsa_verify!(slh_dsa::Shake256f, pk_bytes, msg, sig_bytes),
        _ => Err(CKR_KEY_TYPE_INCONSISTENT),
    }
}

fn verify_hmac(mech: u32, key_bytes: &[u8], msg: &[u8], sig_bytes: &[u8]) -> Result<(), u32> {
    let expected = sign_hmac(mech, key_bytes, msg)?;
    if expected.len() == sig_bytes.len() && expected == sig_bytes { Ok(()) } else { Err(CKR_SIGNATURE_INVALID) }
}

fn verify_rsa(mech: u32, pk_bytes: &[u8], msg: &[u8], sig_bytes: &[u8]) -> Result<(), u32> {
    use sha2::Digest;
    if pk_bytes.len() < 8 { return Err(CKR_KEY_TYPE_INCONSISTENT); }
    let n_len = u32::from_le_bytes([pk_bytes[0], pk_bytes[1], pk_bytes[2], pk_bytes[3]]) as usize;
    if pk_bytes.len() < 4 + n_len + 1 { return Err(CKR_KEY_TYPE_INCONSISTENT); }
    let n = rsa::BigUint::from_bytes_be(&pk_bytes[4..4+n_len]);
    let e = rsa::BigUint::from_bytes_be(&pk_bytes[4+n_len..]);
    let public_key = rsa::RsaPublicKey::new(n, e).map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;

    match mech {
        CKM_SHA256_RSA_PKCS => {
            let hash = sha2::Sha256::digest(msg);
            public_key.verify(rsa::Pkcs1v15Sign::new::<sha2::Sha256>(), &hash, sig_bytes).map_err(|_| CKR_SIGNATURE_INVALID)
        }
        CKM_SHA256_RSA_PKCS_PSS => {
            use rsa::pss::VerifyingKey;
            use rsa::signature::Verifier as RsaVerifier;
            let verifying_key = VerifyingKey::<sha2::Sha256>::new(public_key);
            let sig = rsa::pss::Signature::try_from(sig_bytes).map_err(|_| CKR_SIGNATURE_INVALID)?;
            verifying_key.verify(msg, &sig).map_err(|_| CKR_SIGNATURE_INVALID)
        }
        _ => Err(CKR_MECHANISM_INVALID),
    }
}

fn verify_ecdsa(mech: u32, curve: u32, pk_bytes: &[u8], msg: &[u8], sig_bytes: &[u8]) -> Result<(), u32> {
    match (mech, curve) {
        (CKM_ECDSA_SHA256, CURVE_P256) | (CKM_ECDSA_SHA256, 0) => {
            let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(pk_bytes).map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            let sig = p256::ecdsa::Signature::from_slice(sig_bytes).map_err(|_| CKR_SIGNATURE_INVALID)?;
            use p256::ecdsa::signature::Verifier;
            vk.verify(msg, &sig).map_err(|_| CKR_SIGNATURE_INVALID)
        }
        (CKM_ECDSA_SHA384, CURVE_P384) => {
            let vk = p384::ecdsa::VerifyingKey::from_sec1_bytes(pk_bytes).map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            let sig = p384::ecdsa::Signature::from_slice(sig_bytes).map_err(|_| CKR_SIGNATURE_INVALID)?;
            use p384::ecdsa::signature::Verifier;
            vk.verify(msg, &sig).map_err(|_| CKR_SIGNATURE_INVALID)
        }
        _ => Err(CKR_MECHANISM_INVALID),
    }
}

fn verify_eddsa(pk_bytes: &[u8], msg: &[u8], sig_bytes: &[u8]) -> Result<(), u32> {
    if pk_bytes.len() != 32 || sig_bytes.len() != 64 { return Err(CKR_KEY_TYPE_INCONSISTENT); }
    let vk = ed25519_dalek::VerifyingKey::from_bytes(pk_bytes.try_into().unwrap()).map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
    let sig = ed25519_dalek::Signature::from_bytes(sig_bytes.try_into().unwrap());
    use ed25519_dalek::Verifier;
    vk.verify(msg, &sig).map_err(|_| CKR_SIGNATURE_INVALID)
}

#[wasm_bindgen(js_name = _C_VerifyInit)]
pub fn C_VerifyInit(h_session: u32, p_mechanism: *mut u8, h_key: u32) -> u32 {
    unsafe {
        if p_mechanism.is_null() { return CKR_ARGUMENTS_BAD; }
        let mech_type = *(p_mechanism as *const u32);
        VERIFY_STATE.with(|s| { s.borrow_mut().insert(h_session, (mech_type, h_key)); });
    }
    CKR_OK
}

#[wasm_bindgen(js_name = _C_Verify)]
pub fn C_Verify(h_session: u32, p_data: *mut u8, ul_data_len: u32, p_signature: *mut u8, ul_signature_len: u32) -> u32 {
    let state = VERIFY_STATE.with(|s| s.borrow().get(&h_session).copied());
    let (mech, hkey) = match state { Some(s) => s, None => return CKR_OPERATION_NOT_INITIALIZED };

    unsafe {
        let pk_bytes = match get_object_value(hkey) { Some(v) => v, None => return CKR_ARGUMENTS_BAD };
        let msg = std::slice::from_raw_parts(p_data, ul_data_len as usize);
        let sig_bytes = std::slice::from_raw_parts(p_signature, ul_signature_len as usize);
        let ps = get_object_param_set(hkey);

        match match mech {
            CKM_ML_DSA => verify_ml_dsa(ps, &pk_bytes, msg, sig_bytes),
            CKM_SLH_DSA => verify_slh_dsa(ps, &pk_bytes, msg, sig_bytes),
            CKM_SHA256_HMAC | CKM_SHA384_HMAC | CKM_SHA512_HMAC |
            CKM_SHA3_256_HMAC | CKM_SHA3_512_HMAC => verify_hmac(mech, &pk_bytes, msg, sig_bytes),
            CKM_SHA256_RSA_PKCS | CKM_SHA256_RSA_PKCS_PSS => verify_rsa(mech, &pk_bytes, msg, sig_bytes),
            CKM_ECDSA_SHA256 | CKM_ECDSA_SHA384 => verify_ecdsa(mech, ps, &pk_bytes, msg, sig_bytes),
            CKM_EDDSA => verify_eddsa(&pk_bytes, msg, sig_bytes),
            _ => Err(CKR_MECHANISM_INVALID),
        } {
            Ok(()) => CKR_OK,
            Err(e) => e,
        }
    }
}

// ── Message-based Sign/Verify API ───────────────────────────────────────────

#[wasm_bindgen(js_name = _C_MessageSignInit)]
pub fn C_MessageSignInit(h_session: u32, p_mechanism: *mut u8, h_key: u32) -> u32 {
    C_SignInit(h_session, p_mechanism, h_key)
}

#[wasm_bindgen(js_name = _C_SignMessage)]
pub fn C_SignMessage(h_session: u32, _p_param: *mut u8, _ul_param_len: u32, p_data: *mut u8, ul_data_len: u32, p_signature: *mut u8, pul_signature_len: *mut u32) -> u32 {
    let saved = SIGN_STATE.with(|s| s.borrow().get(&h_session).copied());
    let rv = C_Sign(h_session, p_data, ul_data_len, p_signature, pul_signature_len);
    if let Some(st) = saved { SIGN_STATE.with(|s| { s.borrow_mut().insert(h_session, st); }); }
    rv
}

#[wasm_bindgen(js_name = _C_MessageSignFinal)]
pub fn C_MessageSignFinal(h_session: u32, _p_param: *mut u8, _ul_param_len: u32, _p_signature: *mut u8, _pul_signature_len: *mut u32) -> u32 {
    SIGN_STATE.with(|s| { s.borrow_mut().remove(&h_session); });
    CKR_OK
}

#[wasm_bindgen(js_name = _C_MessageVerifyInit)]
pub fn C_MessageVerifyInit(h_session: u32, p_mechanism: *mut u8, h_key: u32) -> u32 {
    C_VerifyInit(h_session, p_mechanism, h_key)
}

#[wasm_bindgen(js_name = _C_VerifyMessage)]
pub fn C_VerifyMessage(h_session: u32, _p_param: *mut u8, _ul_param_len: u32, p_data: *mut u8, ul_data_len: u32, p_signature: *mut u8, ul_signature_len: u32) -> u32 {
    let saved = VERIFY_STATE.with(|s| s.borrow().get(&h_session).copied());
    let rv = C_Verify(h_session, p_data, ul_data_len, p_signature, ul_signature_len);
    if let Some(st) = saved { VERIFY_STATE.with(|s| { s.borrow_mut().insert(h_session, st); }); }
    rv
}

#[wasm_bindgen(js_name = _C_MessageVerifyFinal)]
pub fn C_MessageVerifyFinal(h_session: u32) -> u32 {
    VERIFY_STATE.with(|s| { s.borrow_mut().remove(&h_session); });
    CKR_OK
}

// ── Encrypt/Decrypt ─────────────────────────────────────────────────────────

#[wasm_bindgen(js_name = _C_EncryptInit)]
pub fn C_EncryptInit(h_session: u32, p_mechanism: *mut u8, h_key: u32) -> u32 {
    unsafe {
        if p_mechanism.is_null() { return CKR_ARGUMENTS_BAD; }
        let mech_type = *(p_mechanism as *const u32);
        let p_param = *(p_mechanism.add(4) as *const u32) as usize as *const u8;
        let ul_param_len = *(p_mechanism.add(8) as *const u32);

        let (iv, aad, tag_bits) = match mech_type {
            CKM_AES_GCM => {
                if p_param.is_null() || ul_param_len < 20 { return CKR_ARGUMENTS_BAD; }
                let gcm = p_param as *const u32;
                let iv_ptr = *gcm as usize as *const u8;
                let iv_len = *gcm.add(1) as usize;
                let tag_bits = *gcm.add(4);
                let iv = if !iv_ptr.is_null() && iv_len > 0 { std::slice::from_raw_parts(iv_ptr, iv_len).to_vec() } else { vec![0u8; 12] };
                (iv, Vec::new(), tag_bits)
            }
            CKM_AES_CBC_PAD => {
                if p_param.is_null() || ul_param_len < 16 { return CKR_ARGUMENTS_BAD; }
                (std::slice::from_raw_parts(p_param, 16).to_vec(), Vec::new(), 0)
            }
            CKM_RSA_PKCS_OAEP => (Vec::new(), Vec::new(), 0),
            _ => return CKR_MECHANISM_INVALID,
        };

        ENCRYPT_STATE.with(|s| { s.borrow_mut().insert(h_session, EncryptCtx { mech_type, key_handle: h_key, iv, aad, tag_bits }); });
    }
    CKR_OK
}

#[wasm_bindgen(js_name = _C_Encrypt)]
pub fn C_Encrypt(h_session: u32, p_data: *mut u8, ul_data_len: u32, p_encrypted_data: *mut u8, pul_encrypted_data_len: *mut u32) -> u32 {
    let ctx = ENCRYPT_STATE.with(|s| s.borrow().get(&h_session).map(|c| (c.mech_type, c.key_handle, c.iv.clone())));
    let (mech_type, key_handle, iv) = match ctx { Some(c) => c, None => return CKR_OPERATION_NOT_INITIALIZED };
    let key_bytes = match get_object_value(key_handle) { Some(v) => v, None => return CKR_ARGUMENTS_BAD };

    unsafe {
        let plaintext = std::slice::from_raw_parts(p_data, ul_data_len as usize);
        let ct = match mech_type {
            CKM_AES_GCM => {
                use aes_gcm::{Aes128Gcm, Aes256Gcm, aead::Aead, KeyInit};
                use aes_gcm::aead::generic_array::GenericArray;
                let nonce = GenericArray::from_slice(&iv);
                let result = match key_bytes.len() {
                    16 => Aes128Gcm::new_from_slice(&key_bytes).unwrap().encrypt(nonce, plaintext),
                    32 => Aes256Gcm::new_from_slice(&key_bytes).unwrap().encrypt(nonce, plaintext),
                    _ => return CKR_KEY_TYPE_INCONSISTENT,
                };
                match result { Ok(ct) => ct, Err(_) => return CKR_FUNCTION_FAILED }
            }
            CKM_AES_CBC_PAD => {
                use aes::cipher::{BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
                type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
                type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
                let padded_len = plaintext.len() + 16 - (plaintext.len() % 16);
                let mut buf = vec![0u8; padded_len];
                buf[..plaintext.len()].copy_from_slice(plaintext);
                match key_bytes.len() {
                    16 => match Aes128CbcEnc::new_from_slices(&key_bytes, &iv).unwrap().encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext.len()) { Ok(ct) => ct.to_vec(), Err(_) => return CKR_FUNCTION_FAILED },
                    32 => match Aes256CbcEnc::new_from_slices(&key_bytes, &iv).unwrap().encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext.len()) { Ok(ct) => ct.to_vec(), Err(_) => return CKR_FUNCTION_FAILED },
                    _ => return CKR_KEY_TYPE_INCONSISTENT,
                }
            }
            CKM_RSA_PKCS_OAEP => {
                if key_bytes.len() < 8 { return CKR_KEY_TYPE_INCONSISTENT; }
                let n_len = u32::from_le_bytes([key_bytes[0], key_bytes[1], key_bytes[2], key_bytes[3]]) as usize;
                if key_bytes.len() < 4 + n_len + 1 { return CKR_KEY_TYPE_INCONSISTENT; }
                let n = rsa::BigUint::from_bytes_be(&key_bytes[4..4+n_len]);
                let e = rsa::BigUint::from_bytes_be(&key_bytes[4+n_len..]);
                let pk = match rsa::RsaPublicKey::new(n, e) { Ok(k) => k, Err(_) => return CKR_KEY_TYPE_INCONSISTENT };
                let mut rng = rand::rngs::OsRng;
                match pk.encrypt(&mut rng, rsa::Oaep::new::<sha2::Sha256>(), plaintext) { Ok(ct) => ct, Err(_) => return CKR_FUNCTION_FAILED }
            }
            _ => return CKR_MECHANISM_INVALID,
        };

        if p_encrypted_data.is_null() { *pul_encrypted_data_len = ct.len() as u32; return CKR_OK; }
        if (*pul_encrypted_data_len as usize) < ct.len() { *pul_encrypted_data_len = ct.len() as u32; return CKR_BUFFER_TOO_SMALL; }
        std::ptr::copy_nonoverlapping(ct.as_ptr(), p_encrypted_data, ct.len());
        *pul_encrypted_data_len = ct.len() as u32;
    }
    ENCRYPT_STATE.with(|s| { s.borrow_mut().remove(&h_session); });
    CKR_OK
}

#[wasm_bindgen(js_name = _C_DecryptInit)]
pub fn C_DecryptInit(h_session: u32, p_mechanism: *mut u8, h_key: u32) -> u32 {
    unsafe {
        if p_mechanism.is_null() { return CKR_ARGUMENTS_BAD; }
        let mech_type = *(p_mechanism as *const u32);
        let p_param = *(p_mechanism.add(4) as *const u32) as usize as *const u8;
        let ul_param_len = *(p_mechanism.add(8) as *const u32);

        let (iv, aad, tag_bits) = match mech_type {
            CKM_AES_GCM => {
                if p_param.is_null() || ul_param_len < 20 { return CKR_ARGUMENTS_BAD; }
                let gcm = p_param as *const u32;
                let iv_ptr = *gcm as usize as *const u8;
                let iv_len = *gcm.add(1) as usize;
                let tag_bits = *gcm.add(4);
                let iv = if !iv_ptr.is_null() && iv_len > 0 { std::slice::from_raw_parts(iv_ptr, iv_len).to_vec() } else { vec![0u8; 12] };
                (iv, Vec::new(), tag_bits)
            }
            CKM_AES_CBC_PAD => {
                if p_param.is_null() || ul_param_len < 16 { return CKR_ARGUMENTS_BAD; }
                (std::slice::from_raw_parts(p_param, 16).to_vec(), Vec::new(), 0)
            }
            CKM_RSA_PKCS_OAEP => (Vec::new(), Vec::new(), 0),
            _ => return CKR_MECHANISM_INVALID,
        };

        DECRYPT_STATE.with(|s| { s.borrow_mut().insert(h_session, EncryptCtx { mech_type, key_handle: h_key, iv, aad, tag_bits }); });
    }
    CKR_OK
}

#[wasm_bindgen(js_name = _C_Decrypt)]
pub fn C_Decrypt(h_session: u32, p_encrypted_data: *mut u8, ul_encrypted_data_len: u32, p_data: *mut u8, pul_data_len: *mut u32) -> u32 {
    let ctx = DECRYPT_STATE.with(|s| s.borrow().get(&h_session).map(|c| (c.mech_type, c.key_handle, c.iv.clone())));
    let (mech_type, key_handle, iv) = match ctx { Some(c) => c, None => return CKR_OPERATION_NOT_INITIALIZED };
    let key_bytes = match get_object_value(key_handle) { Some(v) => v, None => return CKR_ARGUMENTS_BAD };

    unsafe {
        let ciphertext = std::slice::from_raw_parts(p_encrypted_data, ul_encrypted_data_len as usize);
        let pt = match mech_type {
            CKM_AES_GCM => {
                use aes_gcm::{Aes128Gcm, Aes256Gcm, aead::Aead, KeyInit};
                use aes_gcm::aead::generic_array::GenericArray;
                let nonce = GenericArray::from_slice(&iv);
                let result = match key_bytes.len() {
                    16 => Aes128Gcm::new_from_slice(&key_bytes).unwrap().decrypt(nonce, ciphertext),
                    32 => Aes256Gcm::new_from_slice(&key_bytes).unwrap().decrypt(nonce, ciphertext),
                    _ => return CKR_KEY_TYPE_INCONSISTENT,
                };
                match result { Ok(pt) => pt, Err(_) => return CKR_FUNCTION_FAILED }
            }
            CKM_AES_CBC_PAD => {
                use aes::cipher::{BlockDecryptMut, KeyIvInit, block_padding::Pkcs7};
                type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
                type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
                let mut buf = ciphertext.to_vec();
                let pt_slice: &[u8] = match key_bytes.len() {
                    16 => match Aes128CbcDec::new_from_slices(&key_bytes, &iv).unwrap().decrypt_padded_mut::<Pkcs7>(&mut buf) { Ok(pt) => pt, Err(_) => return CKR_FUNCTION_FAILED },
                    32 => match Aes256CbcDec::new_from_slices(&key_bytes, &iv).unwrap().decrypt_padded_mut::<Pkcs7>(&mut buf) { Ok(pt) => pt, Err(_) => return CKR_FUNCTION_FAILED },
                    _ => return CKR_KEY_TYPE_INCONSISTENT,
                };
                pt_slice.to_vec()
            }
            CKM_RSA_PKCS_OAEP => {
                use rsa::pkcs8::DecodePrivateKey;
                let sk = match rsa::RsaPrivateKey::from_pkcs8_der(&key_bytes) { Ok(k) => k, Err(_) => return CKR_KEY_TYPE_INCONSISTENT };
                match sk.decrypt(rsa::Oaep::new::<sha2::Sha256>(), ciphertext) { Ok(pt) => pt, Err(_) => return CKR_FUNCTION_FAILED }
            }
            _ => return CKR_MECHANISM_INVALID,
        };

        if p_data.is_null() { *pul_data_len = pt.len() as u32; return CKR_OK; }
        if (*pul_data_len as usize) < pt.len() { *pul_data_len = pt.len() as u32; return CKR_BUFFER_TOO_SMALL; }
        std::ptr::copy_nonoverlapping(pt.as_ptr(), p_data, pt.len());
        *pul_data_len = pt.len() as u32;
    }
    DECRYPT_STATE.with(|s| { s.borrow_mut().remove(&h_session); });
    CKR_OK
}

// ── SHA Digest ──────────────────────────────────────────────────────────────

#[wasm_bindgen(js_name = _C_DigestInit)]
pub fn C_DigestInit(h_session: u32, p_mechanism: *mut u8) -> u32 {
    unsafe {
        if p_mechanism.is_null() { return CKR_ARGUMENTS_BAD; }
        let mech_type = *(p_mechanism as *const u32);
        use sha2::Digest as Sha2Digest;
        use sha3::Digest as Sha3Digest;
        let ctx = match mech_type {
            CKM_SHA256 => DigestCtx::Sha256(sha2::Sha256::new()),
            CKM_SHA384 => DigestCtx::Sha384(sha2::Sha384::new()),
            CKM_SHA512 => DigestCtx::Sha512(sha2::Sha512::new()),
            CKM_SHA3_256 => DigestCtx::Sha3_256(sha3::Sha3_256::new()),
            CKM_SHA3_512 => DigestCtx::Sha3_512(sha3::Sha3_512::new()),
            _ => return CKR_MECHANISM_INVALID,
        };
        DIGEST_STATE.with(|s| { s.borrow_mut().insert(h_session, ctx); });
    }
    CKR_OK
}

#[wasm_bindgen(js_name = _C_DigestUpdate)]
pub fn C_DigestUpdate(h_session: u32, p_part: *mut u8, ul_part_len: u32) -> u32 {
    use sha2::Digest as Sha2Digest;
    use sha3::Digest as Sha3Digest;
    let has_state = DIGEST_STATE.with(|s| s.borrow().contains_key(&h_session));
    if !has_state { return CKR_OPERATION_NOT_INITIALIZED; }
    unsafe {
        let data = std::slice::from_raw_parts(p_part, ul_part_len as usize);
        DIGEST_STATE.with(|s| {
            let mut map = s.borrow_mut();
            if let Some(ctx) = map.get_mut(&h_session) {
                match ctx {
                    DigestCtx::Sha256(h) => h.update(data),
                    DigestCtx::Sha384(h) => h.update(data),
                    DigestCtx::Sha512(h) => h.update(data),
                    DigestCtx::Sha3_256(h) => h.update(data),
                    DigestCtx::Sha3_512(h) => h.update(data),
                }
            }
        });
    }
    CKR_OK
}

#[wasm_bindgen(js_name = _C_DigestFinal)]
pub fn C_DigestFinal(h_session: u32, p_digest: *mut u8, pul_digest_len: *mut u32) -> u32 {
    use sha2::Digest as Sha2Digest;
    use sha3::Digest as Sha3Digest;
    let ctx = DIGEST_STATE.with(|s| s.borrow_mut().remove(&h_session));
    let ctx = match ctx { Some(c) => c, None => return CKR_OPERATION_NOT_INITIALIZED };
    let hash = match ctx {
        DigestCtx::Sha256(h) => h.finalize().to_vec(),
        DigestCtx::Sha384(h) => h.finalize().to_vec(),
        DigestCtx::Sha512(h) => h.finalize().to_vec(),
        DigestCtx::Sha3_256(h) => h.finalize().to_vec(),
        DigestCtx::Sha3_512(h) => h.finalize().to_vec(),
    };
    unsafe {
        if p_digest.is_null() { *pul_digest_len = hash.len() as u32; return CKR_OK; }
        if (*pul_digest_len as usize) < hash.len() { *pul_digest_len = hash.len() as u32; return CKR_BUFFER_TOO_SMALL; }
        std::ptr::copy_nonoverlapping(hash.as_ptr(), p_digest, hash.len());
        *pul_digest_len = hash.len() as u32;
    }
    CKR_OK
}

#[wasm_bindgen(js_name = _C_Digest)]
pub fn C_Digest(h_session: u32, p_data: *mut u8, ul_data_len: u32, p_digest: *mut u8, pul_digest_len: *mut u32) -> u32 {
    let rv = C_DigestUpdate(h_session, p_data, ul_data_len);
    if rv != CKR_OK { return rv; }
    C_DigestFinal(h_session, p_digest, pul_digest_len)
}

// ── FindObjects ─────────────────────────────────────────────────────────────

#[wasm_bindgen(js_name = _C_FindObjectsInit)]
pub fn C_FindObjectsInit(h_session: u32, p_template: *mut u8, ul_count: u32) -> u32 {
    let mut match_attrs: Vec<(u32, Vec<u8>)> = Vec::new();
    unsafe {
        if !p_template.is_null() && ul_count > 0 {
            let tmpl_ptr = p_template as *mut u32;
            for i in 0..ul_count {
                let attr_type = *tmpl_ptr.add((i * 3) as usize);
                let val_ptr = *tmpl_ptr.add((i * 3 + 1) as usize) as usize as *const u8;
                let val_len = *tmpl_ptr.add((i * 3 + 2) as usize) as usize;
                if !val_ptr.is_null() && val_len > 0 {
                    match_attrs.push((attr_type, std::slice::from_raw_parts(val_ptr, val_len).to_vec()));
                }
            }
        }
    }
    let matching = OBJECTS.with(|objs| {
        objs.borrow().iter()
            .filter(|(_, attrs)| match_attrs.iter().all(|(typ, val)| attrs.get(typ).map_or(false, |v| v == val)))
            .map(|(handle, _)| *handle)
            .collect::<Vec<u32>>()
    });
    FIND_STATE.with(|s| { s.borrow_mut().insert(h_session, FindCtx { handles: matching, cursor: 0 }); });
    CKR_OK
}

#[wasm_bindgen(js_name = _C_FindObjects)]
pub fn C_FindObjects(h_session: u32, ph_object: *mut u32, ul_max_object_count: u32, pul_object_count: *mut u32) -> u32 {
    FIND_STATE.with(|s| {
        let mut map = s.borrow_mut();
        if let Some(ctx) = map.get_mut(&h_session) {
            let remaining = ctx.handles.len() - ctx.cursor;
            let count = remaining.min(ul_max_object_count as usize);
            unsafe {
                for i in 0..count { *ph_object.add(i) = ctx.handles[ctx.cursor + i]; }
                *pul_object_count = count as u32;
            }
            ctx.cursor += count;
            CKR_OK
        } else { CKR_OPERATION_NOT_INITIALIZED }
    })
}

#[wasm_bindgen(js_name = _C_FindObjectsFinal)]
pub fn C_FindObjectsFinal(h_session: u32) -> u32 {
    FIND_STATE.with(|s| { s.borrow_mut().remove(&h_session); });
    CKR_OK
}

// ── GenerateRandom ──────────────────────────────────────────────────────────

#[wasm_bindgen(js_name = _C_GenerateRandom)]
pub fn C_GenerateRandom(_h_session: u32, p_random_data: *mut u8, ul_random_len: u32) -> u32 {
    if p_random_data.is_null() { return CKR_ARGUMENTS_BAD; }
    unsafe {
        let buf = std::slice::from_raw_parts_mut(p_random_data, ul_random_len as usize);
        match getrandom::getrandom(buf) { Ok(_) => CKR_OK, Err(_) => CKR_FUNCTION_FAILED }
    }
}

// ── DeriveKey (ECDH) ────────────────────────────────────────────────────────

#[wasm_bindgen(js_name = _C_DeriveKey)]
pub fn C_DeriveKey(_h_session: u32, p_mechanism: *mut u8, h_base_key: u32, p_template: *mut u8, ul_attribute_count: u32, ph_key: *mut u32) -> u32 {
    unsafe {
        if p_mechanism.is_null() { return CKR_ARGUMENTS_BAD; }
        let mech_type = *(p_mechanism as *const u32);
        if mech_type != CKM_ECDH1_DERIVE { return CKR_MECHANISM_INVALID; }

        let p_param = *(p_mechanism.add(4) as *const u32) as usize as *const u32;
        if p_param.is_null() { return CKR_ARGUMENTS_BAD; }

        let peer_pk_ptr = *p_param.add(3) as usize as *const u8;
        let peer_pk_len = *p_param.add(4) as usize;
        if peer_pk_ptr.is_null() || peer_pk_len == 0 { return CKR_ARGUMENTS_BAD; }

        let peer_pk_bytes = std::slice::from_raw_parts(peer_pk_ptr, peer_pk_len);
        let our_sk_bytes = match get_object_value(h_base_key) { Some(v) => v, None => return CKR_ARGUMENTS_BAD };

        let algo = get_object_algo_family(h_base_key);
        let curve = get_object_param_set(h_base_key);

        let shared_secret = match (algo, curve) {
            (ALGO_ECDSA, CURVE_P256) | (ALGO_ECDH_P256, _) | (0, CURVE_P256) => {
                let sk = match p256::NonZeroScalar::try_from(our_sk_bytes.as_slice()) { Ok(s) => s, Err(_) => return CKR_KEY_TYPE_INCONSISTENT };
                let peer_pk = match p256::PublicKey::from_sec1_bytes(peer_pk_bytes) { Ok(pk) => pk, Err(_) => return CKR_ARGUMENTS_BAD };
                p256::ecdh::diffie_hellman(&sk, peer_pk.as_affine()).raw_secret_bytes().to_vec()
            }
            (ALGO_ECDH_X25519, _) => {
                if our_sk_bytes.len() != 32 || peer_pk_bytes.len() != 32 { return CKR_KEY_TYPE_INCONSISTENT; }
                let mut sk_arr = [0u8; 32]; sk_arr.copy_from_slice(&our_sk_bytes);
                let sk = x25519_dalek::StaticSecret::from(sk_arr);
                let mut pk_arr = [0u8; 32]; pk_arr.copy_from_slice(peer_pk_bytes);
                sk.diffie_hellman(&x25519_dalek::PublicKey::from(pk_arr)).as_bytes().to_vec()
            }
            _ => {
                // Default: try P-256 based on key size
                if our_sk_bytes.len() == 32 && peer_pk_bytes.len() == 65 {
                    let sk = match p256::NonZeroScalar::try_from(our_sk_bytes.as_slice()) { Ok(s) => s, Err(_) => return CKR_KEY_TYPE_INCONSISTENT };
                    let peer_pk = match p256::PublicKey::from_sec1_bytes(peer_pk_bytes) { Ok(pk) => pk, Err(_) => return CKR_ARGUMENTS_BAD };
                    p256::ecdh::diffie_hellman(&sk, peer_pk.as_affine()).raw_secret_bytes().to_vec()
                } else { return CKR_KEY_TYPE_INCONSISTENT; }
            }
        };

        let key_len = get_attr_ulong(p_template, ul_attribute_count, CKA_VALUE_LEN).unwrap_or(shared_secret.len() as u32) as usize;
        let key_value = if key_len <= shared_secret.len() { shared_secret[..key_len].to_vec() } else { shared_secret };
        let mut attrs = HashMap::new();
        attrs.insert(CKA_VALUE, key_value);
        *ph_key = allocate_handle(attrs);
    }
    CKR_OK
}

// ── Key Wrap/Unwrap ─────────────────────────────────────────────────────────

#[wasm_bindgen(js_name = _C_WrapKey)]
pub fn C_WrapKey(_h_session: u32, p_mechanism: *mut u8, h_wrapping_key: u32, h_key: u32, p_wrapped_key: *mut u8, pul_wrapped_key_len: *mut u32) -> u32 {
    unsafe {
        if p_mechanism.is_null() { return CKR_ARGUMENTS_BAD; }
        let mech_type = *(p_mechanism as *const u32);
        if mech_type != CKM_AES_KEY_WRAP { return CKR_MECHANISM_INVALID; }

        let wrapping_key = match get_object_value(h_wrapping_key) { Some(v) => v, None => return CKR_ARGUMENTS_BAD };
        let key_to_wrap = match get_object_value(h_key) { Some(v) => v, None => return CKR_ARGUMENTS_BAD };
        if key_to_wrap.len() % 8 != 0 || key_to_wrap.len() < 16 { return CKR_DATA_INVALID; }

        use aes::cipher::generic_array::GenericArray;
        let wrapped = match wrapping_key.len() {
            16 => aes_kw::KekAes128::new(GenericArray::from_slice(&wrapping_key)).wrap_vec(&key_to_wrap).map_err(|_| CKR_FUNCTION_FAILED),
            24 => aes_kw::KekAes192::new(GenericArray::from_slice(&wrapping_key)).wrap_vec(&key_to_wrap).map_err(|_| CKR_FUNCTION_FAILED),
            32 => aes_kw::KekAes256::new(GenericArray::from_slice(&wrapping_key)).wrap_vec(&key_to_wrap).map_err(|_| CKR_FUNCTION_FAILED),
            _ => return CKR_KEY_TYPE_INCONSISTENT,
        };
        let wrapped = match wrapped { Ok(w) => w, Err(e) => return e };

        if p_wrapped_key.is_null() { *pul_wrapped_key_len = wrapped.len() as u32; return CKR_OK; }
        if (*pul_wrapped_key_len as usize) < wrapped.len() { *pul_wrapped_key_len = wrapped.len() as u32; return CKR_BUFFER_TOO_SMALL; }
        std::ptr::copy_nonoverlapping(wrapped.as_ptr(), p_wrapped_key, wrapped.len());
        *pul_wrapped_key_len = wrapped.len() as u32;
    }
    CKR_OK
}

#[wasm_bindgen(js_name = _C_UnwrapKey)]
pub fn C_UnwrapKey(_h_session: u32, p_mechanism: *mut u8, h_unwrapping_key: u32, p_wrapped_key: *mut u8, ul_wrapped_key_len: u32, _p_template: *mut u8, _ul_attribute_count: u32, ph_key: *mut u32) -> u32 {
    unsafe {
        if p_mechanism.is_null() { return CKR_ARGUMENTS_BAD; }
        let mech_type = *(p_mechanism as *const u32);
        if mech_type != CKM_AES_KEY_WRAP { return CKR_MECHANISM_INVALID; }

        let unwrapping_key = match get_object_value(h_unwrapping_key) { Some(v) => v, None => return CKR_ARGUMENTS_BAD };
        let wrapped_data = std::slice::from_raw_parts(p_wrapped_key, ul_wrapped_key_len as usize);

        use aes::cipher::generic_array::GenericArray;
        let unwrapped = match unwrapping_key.len() {
            16 => aes_kw::KekAes128::new(GenericArray::from_slice(&unwrapping_key)).unwrap_vec(wrapped_data).map_err(|_| CKR_FUNCTION_FAILED),
            24 => aes_kw::KekAes192::new(GenericArray::from_slice(&unwrapping_key)).unwrap_vec(wrapped_data).map_err(|_| CKR_FUNCTION_FAILED),
            32 => aes_kw::KekAes256::new(GenericArray::from_slice(&unwrapping_key)).unwrap_vec(wrapped_data).map_err(|_| CKR_FUNCTION_FAILED),
            _ => return CKR_KEY_TYPE_INCONSISTENT,
        };
        let key_value = match unwrapped { Ok(v) => v, Err(e) => return e };

        let mut attrs = HashMap::new();
        attrs.insert(CKA_VALUE, key_value);
        *ph_key = allocate_handle(attrs);
    }
    CKR_OK
}
