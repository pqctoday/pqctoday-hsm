use wasm_bindgen::prelude::*;

// ── PKCS#11 Return Values ────────────────────────────────────────────────────

pub const CKR_OK: u32 = 0x0000_0000;
pub const CKR_HOST_MEMORY: u32 = 0x0000_0002;
pub const CKR_GENERAL_ERROR: u32 = 0x0000_0005;
pub const CKR_FUNCTION_FAILED: u32 = 0x0000_0006;
pub const CKR_ARGUMENTS_BAD: u32 = 0x0000_0007;
pub const CKR_DATA_INVALID: u32 = 0x0000_0020;
pub const CKR_KEY_TYPE_INCONSISTENT: u32 = 0x0000_0063;
pub const CKR_MECHANISM_INVALID: u32 = 0x0000_0070;
pub const CKR_MECHANISM_PARAM_INVALID: u32 = 0x0000_0071;
pub const CKR_OBJECT_HANDLE_INVALID: u32 = 0x0000_0082;
pub const CKR_OPERATION_NOT_INITIALIZED: u32 = 0x0000_0091;
pub const CKR_SIGNATURE_INVALID: u32 = 0x0000_00C0;
pub const CKR_TEMPLATE_INCOMPLETE: u32 = 0x0000_00D0;
pub const CKR_TEMPLATE_INCONSISTENT: u32 = 0x0000_00D1;
pub const CKR_KEY_UNEXTRACTABLE: u32 = 0x0000_006A;
pub const CKR_KEY_FUNCTION_NOT_PERMITTED: u32 = 0x0000_0068;
pub const CKR_BUFFER_TOO_SMALL: u32 = 0x0000_0150;

// ── PKCS#11 Attribute Types ──────────────────────────────────────────────────

pub const CKA_VALUE: u32 = 0x0000_0011;
pub const CKA_KEY_TYPE: u32 = 0x0000_0100;
pub const CKA_MODULUS: u32 = 0x0000_0120; // PKCS#11 v3.2 §2.1.2 — RSA modulus (big-endian)
pub const CKA_MODULUS_BITS: u32 = 0x0000_0121;
pub const CKA_PUBLIC_EXPONENT: u32 = 0x0000_0122; // PKCS#11 v3.2 §2.1.2 — RSA public exponent
pub const CKA_VALUE_LEN: u32 = 0x0000_0161;
pub const CKA_EC_PARAMS: u32 = 0x0000_0180;
pub const CKA_EC_POINT: u32 = 0x0000_0181;
pub const CKA_BIP32_CHAIN_CODE: u32 = 0x0000_1021;
pub const CKA_BIP32_CHILD_INDEX: u32 = 0x0000_1022;
pub const CKA_PUBLIC_KEY_INFO: u32 = 0x0000_0129; // PKCS#11 v3.2 — DER SubjectPublicKeyInfo
pub const CKA_PARAMETER_SET: u32 = 0x0000_061d;

// ── PKCS#11 Object Classes ────────────────────────────────────────────────────

pub const CKO_PUBLIC_KEY: u32 = 0x0000_0002;
pub const CKO_PRIVATE_KEY: u32 = 0x0000_0003;
pub const CKO_SECRET_KEY: u32 = 0x0000_0004;

// ── PKCS#11 Key Types (CKK_*) ────────────────────────────────────────────────

pub const CKK_RSA: u32 = 0x0000_0000;
pub const CKK_EC: u32 = 0x0000_0003; // ECDSA (P-256, P-384)
pub const CKK_GENERIC_SECRET: u32 = 0x0000_0010;
pub const CKK_AES: u32 = 0x0000_001f;
pub const CKK_EC_EDWARDS: u32 = 0x0000_0040; // EdDSA (Ed25519)
pub const CKK_EC_MONTGOMERY: u32 = 0x0000_0041; // X25519 (PKCS#11 v3.2 §6.7)
pub const CKK_ML_KEM: u32 = 0x0000_0049;
pub const CKK_ML_DSA: u32 = 0x0000_004a;
pub const CKK_SLH_DSA: u32 = 0x0000_004b;
// Stateful hash-based signature key types (PKCS#11 v3.2 §6.14)
pub const CKK_HSS: u32 = 0x0000_0046;  // HSS/LMS multi-level (standard)
pub const CKK_XMSS: u32 = 0x0000_0047; // XMSS single-tree (standard)
pub const CKK_XMSSMT: u32 = 0x0000_0048; // XMSS^MT multi-tree (standard)
// Vendor: single-level LMS (not in PKCS#11 v3.2 standard; same numeric space as CKK is separate from CKM)
pub const CKK_LMS: u32 = 0x8000_0001;

// ── PKCS#11 Semantic Attribute Types ─────────────────────────────────────────

pub const CKA_CLASS: u32 = 0x0000_0000;
pub const CKA_TOKEN: u32 = 0x0000_0001;
pub const CKA_PRIVATE: u32 = 0x0000_0002;
pub const CKA_SENSITIVE: u32 = 0x0000_0103;
pub const CKA_ENCRYPT: u32 = 0x0000_0104;
pub const CKA_DECRYPT: u32 = 0x0000_0105;
pub const CKA_WRAP: u32 = 0x0000_0106;
pub const CKA_UNWRAP: u32 = 0x0000_0107;
pub const CKA_SIGN: u32 = 0x0000_0108;
pub const CKA_VERIFY: u32 = 0x0000_010a;
pub const CKA_DERIVE: u32 = 0x0000_010c;
pub const CKA_EXTRACTABLE: u32 = 0x0000_0162;
pub const CKA_LOCAL: u32 = 0x0000_0163;
pub const CKA_NEVER_EXTRACTABLE: u32 = 0x0000_0164;
pub const CKA_ALWAYS_SENSITIVE: u32 = 0x0000_0165;
pub const CKA_KEY_GEN_MECHANISM: u32 = 0x0000_0166;
pub const CKA_CHECK_VALUE: u32 = 0x0000_0090;
pub const CKA_ENCAPSULATE: u32 = 0x0000_0633;
pub const CKA_DECAPSULATE: u32 = 0x0000_0634;
pub const CKA_MODIFIABLE: u32 = 0x0000_0170;        // PKCS#11 v3.2 — mandatory for all objects (default: TRUE)
pub const CKA_COPYABLE: u32 = 0x0000_0171;          // PKCS#11 v3.2 — mandatory for all objects (default: TRUE)
pub const CKA_DESTROYABLE: u32 = 0x0000_0172;       // PKCS#11 v3.2 — mandatory for all objects (default: TRUE)
pub const CKA_TRUSTED: u32 = 0x0000_0086;            // PKCS#11 v3.2 — public/secret keys (default: FALSE)
pub const CKA_WRAP_WITH_TRUSTED: u32 = 0x0000_0210;  // PKCS#11 v3.2 — private/secret keys (default: FALSE)
pub const CKA_ALWAYS_AUTHENTICATE: u32 = 0x0000_0202; // PKCS#11 v3.2 — private keys (default: FALSE)

// Private attribute: stores the parameter set on generated keys
pub const CKA_PRIV_PARAM_SET: u32 = 0xFFFF_0001;
// Private attribute: stores the algorithm family for polymorphic dispatch
pub const CKA_PRIV_ALGO_FAMILY: u32 = 0xFFFF_0002;

// ── PKCS#11 Mechanism Types ──────────────────────────────────────────────────

// RSA
pub const CKM_RSA_PKCS_KEY_PAIR_GEN: u32 = 0x0000_0000;
pub const CKM_RSA_PKCS_OAEP: u32 = 0x0000_0009;
pub const CKM_SHA256_RSA_PKCS: u32 = 0x0000_0040;
pub const CKM_SHA256_RSA_PKCS_PSS: u32 = 0x0000_0043;

// PQC - KEM
pub const CKM_ML_KEM_KEY_PAIR_GEN: u32 = 0x0000_000F;
pub const CKM_ML_KEM: u32 = 0x0000_0017;

// PQC - DSA
pub const CKM_ML_DSA_KEY_PAIR_GEN: u32 = 0x0000_001C;
pub const CKM_ML_DSA: u32 = 0x0000_001D;
pub const CKM_SLH_DSA_KEY_PAIR_GEN: u32 = 0x0000_002D;
pub const CKM_SLH_DSA: u32 = 0x0000_002E;

// CKH_ hedge/determinism constants (PKCS#11 v3.2 §7.3)
pub const CKH_DETERMINISTIC_REQUIRED: u32 = 0x0000_0002;

// SHA Digest
pub const CKM_SHA256: u32 = 0x0000_0250;
pub const CKM_SHA384: u32 = 0x0000_0260;
pub const CKM_SHA512: u32 = 0x0000_0270;
pub const CKM_SHA3_256: u32 = 0x0000_02B0;
pub const CKM_SHA3_512: u32 = 0x0000_02D0;

// HMAC
pub const CKM_SHA256_HMAC: u32 = 0x0000_0251;
pub const CKM_SHA384_HMAC: u32 = 0x0000_0261;
pub const CKM_SHA512_HMAC: u32 = 0x0000_0271;
pub const CKM_SHA3_256_HMAC: u32 = 0x0000_02B1;
pub const CKM_SHA3_512_HMAC: u32 = 0x0000_02D1;

// KMAC
pub const CKM_KMAC_128: u32 = 0x8000_0100;
pub const CKM_KMAC_256: u32 = 0x8000_0101;

// Generic Secret
pub const CKM_GENERIC_SECRET_KEY_GEN: u32 = 0x0000_0350;
pub const CKM_UNAVAILABLE_INFORMATION: u32 = 0xFFFF_FFFF; // PKCS#11 v3.2 §4.3 — CKA_KEY_GEN_MECHANISM on imported keys

// Key Derivation Functions
pub const CKM_PKCS5_PBKD2: u32 = 0x0000_03b0;
pub const CKM_SP800_108_COUNTER_KDF: u32 = 0x0000_03ac;
pub const CKM_SP800_108_FEEDBACK_KDF: u32 = 0x0000_03ad;
pub const CKM_HKDF_DERIVE: u32 = 0x0000_402a;

// ML-DSA pre-hash mechanisms (PKCS#11 v3.2, pkcs11t.h §1221-1231)
pub const CKM_HASH_ML_DSA_SHA224: u32 = 0x0000_0023;
pub const CKM_HASH_ML_DSA_SHA256: u32 = 0x0000_0024;
pub const CKM_HASH_ML_DSA_SHA384: u32 = 0x0000_0025;
pub const CKM_HASH_ML_DSA_SHA512: u32 = 0x0000_0026;
pub const CKM_HASH_ML_DSA_SHA3_224: u32 = 0x0000_0027;
pub const CKM_HASH_ML_DSA_SHA3_256: u32 = 0x0000_0028;
pub const CKM_HASH_ML_DSA_SHA3_384: u32 = 0x0000_0029;
pub const CKM_HASH_ML_DSA_SHA3_512: u32 = 0x0000_002a;
pub const CKM_HASH_ML_DSA_SHAKE128: u32 = 0x0000_002b;
pub const CKM_HASH_ML_DSA_SHAKE256: u32 = 0x0000_002c;

// SLH-DSA pre-hash mechanisms (PKCS#11 v3.2, pkcs11t.h §1235-1245)
pub const CKM_HASH_SLH_DSA_SHA224: u32 = 0x0000_0036;
pub const CKM_HASH_SLH_DSA_SHA256: u32 = 0x0000_0037;
pub const CKM_HASH_SLH_DSA_SHA384: u32 = 0x0000_0038;
pub const CKM_HASH_SLH_DSA_SHA512: u32 = 0x0000_0039;
pub const CKM_HASH_SLH_DSA_SHA3_224: u32 = 0x0000_003a;
pub const CKM_HASH_SLH_DSA_SHA3_256: u32 = 0x0000_003b;
pub const CKM_HASH_SLH_DSA_SHA3_384: u32 = 0x0000_003c;
pub const CKM_HASH_SLH_DSA_SHA3_512: u32 = 0x0000_003d;
pub const CKM_HASH_SLH_DSA_SHAKE128: u32 = 0x0000_003e;
pub const CKM_HASH_SLH_DSA_SHAKE256: u32 = 0x0000_003f;

// PKCS#11 v3.2 §5.2.12 — X9.63 KDF with SHA3
pub const CKD_SHA3_256_KDF: u32 = 0x0000_000B; // PKCS#11 v3.2 §5.2.12 — SHA3-256 X9.63 KDF
pub const CKD_SHA3_512_KDF: u32 = 0x0000_000D; // PKCS#11 v3.2 §5.2.12 — SHA3-512 X9.63 KDF

// PBKDF2 PRF types
pub const CKP_PBKDF2_HMAC_SHA256: u32 = 0x04;
pub const CKP_PBKDF2_HMAC_SHA384: u32 = 0x05;
pub const CKP_PBKDF2_HMAC_SHA512: u32 = 0x06;

// HKDF salt types
pub const CKF_HKDF_SALT_DATA: u32 = 0x0000_0002;

// SP 800-108 data param types
pub const CK_SP800_108_BYTE_ARRAY: u32 = 0x0000_0004;

// EC
// ----- HD Derivation (BIP32 / SLIP10) -----
pub const CKM_BIP32_MASTER_DERIVE: u32 = 0x0000_105B;
pub const CKM_BIP32_CHILD_DERIVE: u32 = 0x0000_105C;
pub const CKF_BIP32_HARDENED: u32 = 0x8000_0000;

pub const CKM_EC_KEY_PAIR_GEN: u32 = 0x0000_1040;
pub const CKM_ECDSA_SHA256: u32 = 0x0000_1044;
pub const CKM_ECDSA_SHA384: u32 = 0x0000_1045;
// ECDSA with SHA-3 prehash (PKCS#11 v3.2 §6.3)
pub const CKM_ECDSA_SHA3_224: u32 = 0x0000_1047;
pub const CKM_ECDSA_SHA3_256: u32 = 0x0000_1048;
pub const CKM_ECDSA_SHA3_384: u32 = 0x0000_1049;
pub const CKM_ECDSA_SHA3_512: u32 = 0x0000_104a;
pub const CKM_ECDH1_DERIVE: u32 = 0x0000_1050;
pub const CKM_ECDH1_COFACTOR_DERIVE: u32 = 0x0000_1051;
pub const CKM_EC_EDWARDS_KEY_PAIR_GEN: u32 = 0x0000_1055;
pub const CKM_EC_MONTGOMERY_KEY_PAIR_GEN: u32 = 0x0000_1056; // PKCS#11 v3.2 §6.7 — X25519 keygen
pub const CKM_EDDSA: u32 = 0x0000_1057;
pub const CKM_EC_MONTGOMERY_KEY_DERIVE: u32 = 0x0000_1058; // Alias: ECDH1_DERIVE for X25519 keys
// Internal-only: Ed25519ph (prehashed) — same PKCS#11 mechanism, dispatched via phFlag in params
pub const CKM_EDDSA_PH: u32 = 0xFFFF_1057;

// AES
pub const CKM_AES_KEY_GEN: u32 = 0x0000_1080;
pub const CKM_AES_CBC_PAD: u32 = 0x0000_1085;
pub const CKM_AES_CTR: u32 = 0x0000_1086;
pub const CKM_AES_GCM: u32 = 0x0000_1087;
pub const CKM_AES_KEY_WRAP: u32 = 0x0000_2109;
pub const CKM_AES_KEY_WRAP_KWP: u32 = 0x0000_210A; // RFC 5649 (PKCS#11 v3.2)
pub const CKM_AES_KEY_WRAP_PAD_LEGACY: u32 = 0x0000_108b; // SoftHSM2 legacy alias

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

// ── PKCS#11 Session/Token Constants ─────────────────────────────────────────

pub const CKS_RW_USER_FUNCTIONS: u32 = 3;
pub const CKF_SERIAL_SESSION: u32 = 0x0000_0004;
pub const CKF_RW_SESSION: u32 = 0x0000_0002;

// ── Mechanism Discovery ──────────────────────────────────────────────────────

pub const SUPPORTED_MECHS: &[u32] = &[
    // RSA
    CKM_RSA_PKCS_KEY_PAIR_GEN,
    CKM_RSA_PKCS_OAEP,
    CKM_SHA256_RSA_PKCS,
    CKM_SHA256_RSA_PKCS_PSS,
    // ML-KEM (FIPS 203)
    CKM_ML_KEM_KEY_PAIR_GEN,
    CKM_ML_KEM,
    // ML-DSA (FIPS 204) — pure + pre-hash
    CKM_ML_DSA_KEY_PAIR_GEN,
    CKM_ML_DSA,
    CKM_HASH_ML_DSA_SHA224,
    CKM_HASH_ML_DSA_SHA256,
    CKM_HASH_ML_DSA_SHA384,
    CKM_HASH_ML_DSA_SHA512,
    CKM_HASH_ML_DSA_SHA3_224,
    CKM_HASH_ML_DSA_SHA3_256,
    CKM_HASH_ML_DSA_SHA3_384,
    CKM_HASH_ML_DSA_SHA3_512,
    CKM_HASH_ML_DSA_SHAKE128,
    CKM_HASH_ML_DSA_SHAKE256,
    // SLH-DSA (FIPS 205) — pure + pre-hash
    CKM_SLH_DSA_KEY_PAIR_GEN,
    CKM_SLH_DSA,
    CKM_HASH_SLH_DSA_SHA224,
    CKM_HASH_SLH_DSA_SHA256,
    CKM_HASH_SLH_DSA_SHA384,
    CKM_HASH_SLH_DSA_SHA512,
    CKM_HASH_SLH_DSA_SHA3_224,
    CKM_HASH_SLH_DSA_SHA3_256,
    CKM_HASH_SLH_DSA_SHA3_384,
    CKM_HASH_SLH_DSA_SHA3_512,
    CKM_HASH_SLH_DSA_SHAKE128,
    CKM_HASH_SLH_DSA_SHAKE256,
    // Digests
    CKM_SHA256,
    CKM_SHA384,
    CKM_SHA512,
    CKM_SHA3_256,
    CKM_SHA3_512,
    // HMAC
    CKM_SHA256_HMAC,
    CKM_SHA384_HMAC,
    CKM_SHA512_HMAC,
    CKM_SHA3_256_HMAC,
    CKM_SHA3_512_HMAC,
    // KMAC
    CKM_KMAC_128,
    CKM_KMAC_256,
    // Secret key generation
    CKM_GENERIC_SECRET_KEY_GEN,
    // EC / ECDSA / EdDSA
    CKM_EC_KEY_PAIR_GEN,
    CKM_ECDSA_SHA256,
    CKM_ECDSA_SHA384,
    CKM_ECDSA_SHA3_224,
    CKM_ECDSA_SHA3_256,
    CKM_ECDSA_SHA3_384,
    CKM_ECDSA_SHA3_512,
    CKM_ECDH1_DERIVE,
    CKM_ECDH1_COFACTOR_DERIVE,
    CKM_EC_EDWARDS_KEY_PAIR_GEN,
    CKM_EC_MONTGOMERY_KEY_PAIR_GEN,
    CKM_EC_MONTGOMERY_KEY_DERIVE,
    CKM_EDDSA,
    // AES
    CKM_AES_KEY_GEN,
    CKM_AES_CBC_PAD,
    CKM_AES_CTR,
    CKM_AES_GCM,
    CKM_AES_KEY_WRAP,
    CKM_AES_KEY_WRAP_KWP,
    // Key derivation
    CKM_PKCS5_PBKD2,
    CKM_HKDF_DERIVE,
    CKM_SP800_108_COUNTER_KDF,
    CKM_SP800_108_FEEDBACK_KDF,
    // Stateful hash-based signatures (G10)
    CKM_HSS_KEY_PAIR_GEN,
    CKM_HSS,
    CKM_XMSS_KEY_PAIR_GEN,
    CKM_XMSS,
    CKM_LMS_KEY_PAIR_GEN,
    CKM_LMS,
    // Keccak-256 digest (G11 — Rust engine only)
    CKM_KECCAK_256,
];

#[wasm_bindgen(js_name = _C_GetMechanismList)]
pub fn C_GetMechanismList(_slot_id: u32, p_mechanism_list: *mut u32, pul_count: *mut u32) -> u32 {
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

// ── Multi-part operation stubs (PKCS#11 v3.2 compliance) ────────────────────
// These return CKR_FUNCTION_NOT_SUPPORTED as the Rust engine only supports
// single-shot operations. DigestUpdate/DigestFinal are fully implemented above.

pub const CKR_FUNCTION_NOT_SUPPORTED: u32 = 0x0000_0054;
pub const CKR_KEY_EXHAUSTED: u32 = 0x0000_0203; // PKCS#11 v3.2 — stateful key has no remaining signatures

// ── Stateful Signature Mechanisms (G10) ─────────────────────────────────────

// HSS/LMS standard mechanisms (PKCS#11 v3.2 §6.14)
pub const CKM_HSS_KEY_PAIR_GEN: u32 = 0x0000_4032;
pub const CKM_HSS: u32 = 0x0000_4033;
pub const CKM_XMSS_KEY_PAIR_GEN: u32 = 0x0000_4034;
pub const CKM_XMSS: u32 = 0x0000_4036;

// Vendor: single-level LMS (not in PKCS#11 v3.2 standard CKM range)
pub const CKM_LMS_KEY_PAIR_GEN: u32 = 0x8000_0001;
pub const CKM_LMS: u32 = 0x8000_0002;

// Vendor: Keccak-256 digest (G11 — Ethereum address derivation, Rust engine only)
pub const CKM_KECCAK_256: u32 = 0x8000_0010;

// ── Stateful Key Attributes (vendor, G10) ────────────────────────────────────
// Range: 0x80000101–0x80000105 (offset from CKM vendor range to avoid confusion)

pub const CKA_STATEFUL_KEY_STATE: u32 = 0x8000_0101; // raw serialised private key blob
pub const CKA_LMS_PARAM_SET: u32 = 0x8000_0102;      // CKP_LMS_SHA256_M32_H* value
pub const CKA_LMOTS_PARAM_SET: u32 = 0x8000_0103;    // CKP_LMOTS_SHA256_N32_W* value
pub const CKA_XMSS_PARAM_SET: u32 = 0x8000_0104;     // CKP_XMSS_* value
pub const CKA_LEAF_INDEX: u32 = 0x8000_0105;          // current leaf index (u64, little-endian)

// Standard multi-level HSS level-type attribute (PKCS#11 v3.2 §6.14)
pub const CKA_HSS_LMS_TYPE: u32 = 0x0000_0618;

// ── LMS / LMOTS Parameter Set Constants ─────────────────────────────────────
// Values match PKCS#11 v3.2 §6.14 table (tree-height based naming)
// NOTE: hbs-lms LmsAlgorithm enum uses RFC 8554 type IDs — use ckp_to_lms_algo() in lms.rs

pub const CKP_LMS_SHA256_M32_H5: u32 = 5;
pub const CKP_LMS_SHA256_M32_H10: u32 = 10;
pub const CKP_LMS_SHA256_M32_H15: u32 = 15;
pub const CKP_LMS_SHA256_M32_H20: u32 = 20;
pub const CKP_LMS_SHA256_M32_H25: u32 = 25;

pub const CKP_LMOTS_SHA256_N32_W1: u32 = 1;
pub const CKP_LMOTS_SHA256_N32_W2: u32 = 2;
pub const CKP_LMOTS_SHA256_N32_W4: u32 = 4;
pub const CKP_LMOTS_SHA256_N32_W8: u32 = 8;

// ── XMSS Parameter Set Constants ─────────────────────────────────────────────

pub const CKP_XMSS_SHA2_10_256: u32 = 0x01;
pub const CKP_XMSS_SHA2_16_256: u32 = 0x02;
pub const CKP_XMSS_SHA2_20_256: u32 = 0x03;
pub const CKP_XMSS_SHAKE_10_256: u32 = 0x11;
pub const CKP_XMSS_SHAKE_16_256: u32 = 0x12;
pub const CKP_XMSS_SHAKE_20_256: u32 = 0x13;
