// SPDX-License-Identifier: GPL-3.0-only
//
// vendor_mechanisms.h — Vendor-defined PKCS#11 mechanism and attribute constants
//
// These values are in the vendor range (0x80000000–0xFFFFFFFF) and extend
// PKCS#11 v3.2 with mechanisms that are not (yet) in the standard.
//
// Rust side: mirrored in rust/src/constants.rs
// TypeScript side: mirrored in src/wasm/softhsm/constants.ts

#pragma once

#include "pkcs11/pkcs11t.h"

// ── Vendor: single-level LMS ──────────────────────────────────────────────────
// (PKCS#11 v3.2 only defines HSS at the multi-level CKM_HSS_KEY_PAIR_GEN / CKM_HSS;
//  CKM_LMS_KEY_PAIR_GEN and CKM_LMS are vendor extensions for single-level keygen.)

#define CKM_LMS_KEY_PAIR_GEN   0x80000001UL  /* vendor */
#define CKM_LMS                0x80000002UL  /* vendor */
#define CKK_LMS                0x80000001UL  /* vendor — same value as CKM_LMS_KEY_PAIR_GEN; separate namespace */

// ── Vendor: Keccak-256 (G11 — Ethereum address derivation) ───────────────────
// Rust engine only. The C++ OpenSSL engine returns CKR_MECHANISM_INVALID for this.

#define CKM_KECCAK_256         0x80000010UL  /* vendor */

// ── Vendor: stateful key attributes ──────────────────────────────────────────
// Range: 0x80000101–0x80000105 (offset from CKM vendor range to avoid confusion)

#define CKA_STATEFUL_KEY_STATE 0x80000101UL  /* raw serialised private key blob */
#define CKA_LMS_PARAM_SET      0x80000102UL  /* CKP_LMS_SHA256_M32_H* value */
#define CKA_LMOTS_PARAM_SET    0x80000103UL  /* CKP_LMOTS_SHA256_N32_W* value */
#define CKA_XMSS_PARAM_SET     0x80000104UL  /* CKP_XMSS_* value */
#define CKA_LEAF_INDEX         0x80000105UL  /* current leaf index (CK_ULONG) */

// ── LMS parameter set values (match RFC 8554 naming) ─────────────────────────
// These match the PKCS#11 v3.2 §6.14 table. Used in CKA_LMS_PARAM_SET.

#define CKP_LMS_SHA256_M32_H5   5UL
#define CKP_LMS_SHA256_M32_H10  10UL
#define CKP_LMS_SHA256_M32_H15  15UL
#define CKP_LMS_SHA256_M32_H20  20UL
#define CKP_LMS_SHA256_M32_H25  25UL

// ── LMOTS parameter set values ────────────────────────────────────────────────

#define CKP_LMOTS_SHA256_N32_W1  1UL
#define CKP_LMOTS_SHA256_N32_W2  2UL
#define CKP_LMOTS_SHA256_N32_W4  4UL
#define CKP_LMOTS_SHA256_N32_W8  8UL

// ── Standard PKCS#11 v3.2 §6.14: HSS/LMS/XMSS mechanisms ────────────────────

#define CKM_HSS_KEY_PAIR_GEN   0x00004032UL
#define CKM_HSS                0x00004033UL
#define CKM_XMSS_KEY_PAIR_GEN  0x00004034UL
#define CKM_XMSS               0x00004036UL

#define CKK_HSS                0x00000046UL
#define CKK_XMSS               0x00000047UL
#define CKK_XMSSMT             0x00000048UL

// Standard CKR extension
#define CKR_KEY_EXHAUSTED      0x00000203UL  /* PKCS#11 v3.2 §6.14 */

// ── HSS key generation parameters (CKM_HSS_KEY_PAIR_GEN mechanism parameter) ─

#define HSS_MAX_LEVELS 8

typedef struct CK_HSS_KEY_PAIR_GEN_PARAMS {
    CK_ULONG ulLevels;
    CK_ULONG ulLmsParamSet[HSS_MAX_LEVELS];
    CK_ULONG ulLmotsParamSet[HSS_MAX_LEVELS];
} CK_HSS_KEY_PAIR_GEN_PARAMS;

typedef CK_HSS_KEY_PAIR_GEN_PARAMS CK_PTR CK_HSS_KEY_PAIR_GEN_PARAMS_PTR;
