/*
 * pqc_validate.cpp — SoftHSMv3 PKCS#11 v3.2 Algorithm Validation Program
 *
 * Validates all mechanisms supported by OpenSSL 3.6.0 through the PKCS#11 v3.2
 * interface of SoftHSMv3. Each test performs a symmetric round-trip
 * (Sign→Verify, Encrypt→Decrypt, Encapsulate→Decapsulate) and includes
 * negative tamper tests where applicable.
 *
 * Outputs a dated JSON result file per run:
 *   pqc_validate_MMDDYYYY.json, pqc_validate_MMDDYYYY_r1.json, ...
 *
 * Build:
 *   curl -L https://raw.githubusercontent.com/nlohmann/json/v3.11.3/single_include/nlohmann/json.hpp \
 *        -o tests/json.hpp
 *   g++ -o pqc_validate tests/pqc_validate.cpp -ldl -std=c++17 \
 *       -I src/lib/pkcs11 -I tests/
 *
 * Usage:
 *   ./pqc_validate <library.so> [--so-pin PIN] [--user-pin PIN]
 *                               [--ops-file path] [--output-dir path]
 *                               [--verbose]
 *
 * Copyright (c) 2026 PQC Today. BSD-2-Clause License.
 */

/* ── PKCS#11 platform macros (must precede cryptoki.h) ─────────────────── */
#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name)         returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name)        returnType (* name)
#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#include "cryptoki.h"      /* PKCS#11 v3.2 headers  */
#include "json.hpp"        /* nlohmann/json v3.11.3 */

#include <dlfcn.h>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <cassert>
#include <chrono>
#include <iomanip>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <filesystem>
#include <stdexcept>
#include <algorithm>

namespace fs = std::filesystem;
using json   = nlohmann::json;

/* ─────────────────────────────────────────────────────────────────────────
 *  V3.2 KEM function pointer types
 *  (loaded via dlsym — avoids CK_FUNCTION_LIST_3_2 struct complexity)
 * ───────────────────────────────────────────────────────────────────────── */
typedef CK_RV (*FnEncapsulate)(
    CK_SESSION_HANDLE    hSession,
    CK_MECHANISM_PTR     pMechanism,
    CK_OBJECT_HANDLE     hPublicKey,
    CK_ATTRIBUTE_PTR     pTemplate,
    CK_ULONG             ulAttributeCount,
    CK_BYTE_PTR          pCiphertext,
    CK_ULONG_PTR         pulCiphertextLen,
    CK_OBJECT_HANDLE_PTR phKey);

typedef CK_RV (*FnDecapsulate)(
    CK_SESSION_HANDLE    hSession,
    CK_MECHANISM_PTR     pMechanism,
    CK_OBJECT_HANDLE     hPrivateKey,
    CK_ATTRIBUTE_PTR     pTemplate,
    CK_ULONG             ulAttributeCount,
    CK_BYTE_PTR          pCiphertext,
    CK_ULONG             ulCiphertextLen,
    CK_OBJECT_HANDLE_PTR phKey);

/* ─────────────────────────────────────────────────────────────────────────
 *  EC curve OIDs — DER-encoded for CKA_EC_PARAMS
 * ───────────────────────────────────────────────────────────────────────── */
static const uint8_t OID_P256[]   = { 0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07 };
static const uint8_t OID_P384[]   = { 0x06,0x05,0x2b,0x81,0x04,0x00,0x22 };
static const uint8_t OID_P521[]   = { 0x06,0x05,0x2b,0x81,0x04,0x00,0x23 };
static const uint8_t OID_ED25519[]= { 0x06,0x03,0x2b,0x65,0x70 };
static const uint8_t OID_ED448[]  = { 0x06,0x03,0x2b,0x65,0x71 };
static const uint8_t OID_X25519[] = { 0x06,0x03,0x2b,0x65,0x6e };
static const uint8_t OID_X448[]   = { 0x06,0x03,0x2b,0x65,0x6f };

/* ─────────────────────────────────────────────────────────────────────────
 *  Utility helpers
 * ───────────────────────────────────────────────────────────────────────── */
static std::string toHex(const uint8_t* data, size_t len) {
    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i)
        ss << std::setw(2) << static_cast<unsigned>(data[i]);
    return ss.str();
}

static std::string toHex(const std::vector<uint8_t>& v) {
    return toHex(v.data(), v.size());
}

static std::vector<uint8_t> fromHex(const std::string& h) {
    std::vector<uint8_t> out;
    for (size_t i = 0; i + 1 < h.size(); i += 2) {
        out.push_back(static_cast<uint8_t>(std::stoul(h.substr(i,2), nullptr, 16)));
    }
    return out;
}

static std::string isoNow() {
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                  now.time_since_epoch()) % 1000;
    std::ostringstream ss;
    ss << std::put_time(std::gmtime(&t), "%Y-%m-%dT%H:%M:%S");
    ss << '.' << std::setfill('0') << std::setw(3) << ms.count() << 'Z';
    return ss.str();
}

static std::string datestamp() {     /* MMDDYYYY */
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::ostringstream ss;
    ss << std::put_time(std::localtime(&t), "%m%d%Y");
    return ss.str();
}

/* ─────────────────────────────────────────────────────────────────────────
 *  CK_RV → string
 * ───────────────────────────────────────────────────────────────────────── */
static const char* rvName(CK_RV rv) {
    switch (rv) {
    case CKR_OK:                      return "CKR_OK";
    case CKR_CANCEL:                  return "CKR_CANCEL";
    case CKR_HOST_MEMORY:             return "CKR_HOST_MEMORY";
    case CKR_SLOT_ID_INVALID:         return "CKR_SLOT_ID_INVALID";
    case CKR_GENERAL_ERROR:           return "CKR_GENERAL_ERROR";
    case CKR_FUNCTION_FAILED:         return "CKR_FUNCTION_FAILED";
    case CKR_ARGUMENTS_BAD:           return "CKR_ARGUMENTS_BAD";
    case CKR_ATTRIBUTE_VALUE_INVALID: return "CKR_ATTRIBUTE_VALUE_INVALID";
    case CKR_DATA_INVALID:            return "CKR_DATA_INVALID";
    case CKR_DATA_LEN_RANGE:          return "CKR_DATA_LEN_RANGE";
    case CKR_DEVICE_ERROR:            return "CKR_DEVICE_ERROR";
    case CKR_ENCRYPTED_DATA_INVALID:  return "CKR_ENCRYPTED_DATA_INVALID";
    case CKR_KEY_HANDLE_INVALID:      return "CKR_KEY_HANDLE_INVALID";
    case CKR_KEY_SIZE_RANGE:          return "CKR_KEY_SIZE_RANGE";
    case CKR_KEY_TYPE_INCONSISTENT:   return "CKR_KEY_TYPE_INCONSISTENT";
    case CKR_MECHANISM_INVALID:       return "CKR_MECHANISM_INVALID";
    case CKR_MECHANISM_PARAM_INVALID: return "CKR_MECHANISM_PARAM_INVALID";
    case CKR_OBJECT_HANDLE_INVALID:   return "CKR_OBJECT_HANDLE_INVALID";
    case CKR_OPERATION_ACTIVE:        return "CKR_OPERATION_ACTIVE";
    case CKR_OPERATION_NOT_INITIALIZED:return "CKR_OPERATION_NOT_INITIALIZED";
    case CKR_PIN_INCORRECT:           return "CKR_PIN_INCORRECT";
    case CKR_SESSION_HANDLE_INVALID:  return "CKR_SESSION_HANDLE_INVALID";
    case CKR_SIGNATURE_INVALID:       return "CKR_SIGNATURE_INVALID";
    case CKR_SIGNATURE_LEN_RANGE:     return "CKR_SIGNATURE_LEN_RANGE";
    case CKR_TEMPLATE_INCOMPLETE:     return "CKR_TEMPLATE_INCOMPLETE";
    case CKR_TEMPLATE_INCONSISTENT:   return "CKR_TEMPLATE_INCONSISTENT";
    case CKR_TOKEN_NOT_PRESENT:       return "CKR_TOKEN_NOT_PRESENT";
    case CKR_TOKEN_WRITE_PROTECTED:   return "CKR_TOKEN_WRITE_PROTECTED";
    case CKR_UNWRAPPING_KEY_SIZE_RANGE:return "CKR_UNWRAPPING_KEY_SIZE_RANGE";
    case CKR_USER_NOT_LOGGED_IN:      return "CKR_USER_NOT_LOGGED_IN";
    case CKR_FUNCTION_NOT_SUPPORTED:  return "CKR_FUNCTION_NOT_SUPPORTED";
    default: {
        static char buf[32];
        snprintf(buf, sizeof(buf), "CKR_0x%08lx", (unsigned long)rv);
        return buf;
    }
    }
}

static bool isSkipRv(CK_RV rv) {
    return rv == CKR_MECHANISM_INVALID || rv == CKR_FUNCTION_NOT_SUPPORTED;
}

/* ─────────────────────────────────────────────────────────────────────────
 *  Logger
 * ───────────────────────────────────────────────────────────────────────── */
struct Logger {
    bool verbose;
    explicit Logger(bool v) : verbose(v) {}

    void section(const std::string& title) {
        std::cout << "\n\033[1;36m══ " << title << " ══\033[0m\n";
    }
    void info(const std::string& msg) {
        std::cout << "\033[0;37m  [" << isoNow() << "] " << msg << "\033[0m\n";
    }
    void pass(const std::string& msg) {
        std::cout << "\033[1;32m  ✓ " << msg << "\033[0m\n";
    }
    void fail(const std::string& msg) {
        std::cout << "\033[1;31m  ✗ " << msg << "\033[0m\n";
    }
    void skip(const std::string& msg) {
        std::cout << "\033[0;33m  ⊘ SKIP: " << msg << "\033[0m\n";
    }
    void warn(const std::string& msg) {
        std::cout << "\033[0;33m  ⚠ " << msg << "\033[0m\n";
    }
    void verbose_hex(const std::string& label, const std::vector<uint8_t>& data) {
        if (!verbose) return;
        std::string h = toHex(data);
        if (h.size() > 128) h = h.substr(0,128) + "...";
        std::cout << "    " << label << ": " << h << "\n";
    }
};

/* ─────────────────────────────────────────────────────────────────────────
 *  Context
 * ───────────────────────────────────────────────────────────────────────── */
struct Ctx {
    CK_FUNCTION_LIST_PTR p11   = nullptr;
    FnEncapsulate  encapsulate = nullptr;
    FnDecapsulate  decapsulate = nullptr;
    CK_SESSION_HANDLE session  = CK_INVALID_HANDLE;
    CK_SLOT_ID    slot         = 0;
    bool          verbose      = false;
    int           passed       = 0;
    int           failed       = 0;
    int           skipped      = 0;
    Logger*       log          = nullptr;
};

/* ─────────────────────────────────────────────────────────────────────────
 *  Output JSON path: pqc_validate_MMDDYYYY[_rN].json
 * ───────────────────────────────────────────────────────────────────────── */
static std::string determineOutputPath(const std::string& dir) {
    std::string base = "pqc_validate_" + datestamp();
    // First candidate: no suffix
    auto candidate = [&](int n) -> fs::path {
        std::string name = (n == 0) ? base + ".json"
                                    : base + "_r" + std::to_string(n) + ".json";
        return fs::path(dir) / name;
    };
    for (int n = 0; ; ++n) {
        fs::path p = candidate(n);
        if (!fs::exists(p)) return p.string();
    }
}

/* ─────────────────────────────────────────────────────────────────────────
 *  Token initialization helper
 * ───────────────────────────────────────────────────────────────────────── */
static bool initToken(Ctx& ctx, const std::string& soPin, const std::string& userPin) {
    // Enumerate ALL slots (including those without tokens)
    CK_ULONG allSlotCount = 0;
    ctx.p11->C_GetSlotList(CK_FALSE, nullptr, &allSlotCount);
    if (allSlotCount == 0) {
        std::cerr << "ERROR: no slots available\n";
        return false;
    }
    std::vector<CK_SLOT_ID> allSlots(allSlotCount);
    ctx.p11->C_GetSlotList(CK_FALSE, allSlots.data(), &allSlotCount);

    // Check each slot for an already-initialized token via C_GetTokenInfo
    for (CK_ULONG i = 0; i < allSlotCount; i++) {
        CK_TOKEN_INFO tInfo;
        CK_RV rv = ctx.p11->C_GetTokenInfo(allSlots[i], &tInfo);
        if (rv == CKR_OK && (tInfo.flags & CKF_TOKEN_INITIALIZED)) {
            ctx.slot = allSlots[i];
            return true;
        }
    }

    // No initialized token found — init on the first available slot
    ctx.slot = allSlots[0];
    CK_UTF8CHAR label[32] = {};
    memset(label, ' ', 32);
    const char* lbl = "pqcvalidate     ";
    memcpy(label, lbl, std::min((size_t)32, strlen(lbl)));

    CK_RV rv = ctx.p11->C_InitToken(
        ctx.slot,
        reinterpret_cast<CK_UTF8CHAR_PTR>(const_cast<char*>(soPin.c_str())),
        soPin.size(),
        label);
    if (rv != CKR_OK) {
        std::cerr << "ERROR: C_InitToken failed: 0x" << std::hex << rv << std::dec << "\n";
        return false;
    }

    // Re-enumerate slots — SoftHSM may reassign slot IDs after C_InitToken
    CK_ULONG newSlotCount = 0;
    ctx.p11->C_GetSlotList(CK_TRUE, nullptr, &newSlotCount);
    if (newSlotCount > 0) {
        std::vector<CK_SLOT_ID> newSlots(newSlotCount);
        ctx.p11->C_GetSlotList(CK_TRUE, newSlots.data(), &newSlotCount);
        ctx.slot = newSlots[0];
    }

    // Open SO session to set user PIN
    CK_SESSION_HANDLE soSess = CK_INVALID_HANDLE;
    rv = ctx.p11->C_OpenSession(ctx.slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                nullptr, nullptr, &soSess);
    if (rv != CKR_OK) {
        std::cerr << "ERROR: C_OpenSession (SO) failed: 0x" << std::hex << rv << std::dec << "\n";
        return false;
    }
    ctx.p11->C_Login(soSess, CKU_SO,
                     reinterpret_cast<CK_UTF8CHAR_PTR>(const_cast<char*>(soPin.c_str())),
                     soPin.size());
    ctx.p11->C_InitPIN(soSess,
                       reinterpret_cast<CK_UTF8CHAR_PTR>(const_cast<char*>(userPin.c_str())),
                       userPin.size());
    ctx.p11->C_Logout(soSess);
    ctx.p11->C_CloseSession(soSess);
    return true;
}

/* ─────────────────────────────────────────────────────────────────────────
 *  Destroy object helper
 * ───────────────────────────────────────────────────────────────────────── */
static void destroyObj(Ctx& ctx, CK_OBJECT_HANDLE h) {
    if (h != CK_INVALID_HANDLE) ctx.p11->C_DestroyObject(ctx.session, h);
}

/* ─────────────────────────────────────────────────────────────────────────
 *  Export a CKA_VALUE attribute from a secret key object
 * ───────────────────────────────────────────────────────────────────────── */
static std::vector<uint8_t> exportKeyValue(Ctx& ctx, CK_OBJECT_HANDLE hKey) {
    CK_ULONG len = 0;
    CK_ATTRIBUTE attrLen = { CKA_VALUE, nullptr, 0 };
    if (ctx.p11->C_GetAttributeValue(ctx.session, hKey, &attrLen, 1) != CKR_OK)
        return {};
    len = attrLen.ulValueLen;
    std::vector<uint8_t> buf(len);
    CK_ATTRIBUTE attr = { CKA_VALUE, buf.data(), len };
    if (ctx.p11->C_GetAttributeValue(ctx.session, hKey, &attr, 1) != CKR_OK)
        return {};
    return buf;
}

/* ─────────────────────────────────────────────────────────────────────────
 *  Strip DER OCTET STRING wrapper from CKA_EC_POINT value
 *  Raw uncompressed point has form 04 || x || y.
 *  PKCS#11 wraps it: 04 <len> 04 || x || y
 * ───────────────────────────────────────────────────────────────────────── */
static std::vector<uint8_t> stripEcPointWrapper(const std::vector<uint8_t>& der) {
    if (der.size() < 2 || der[0] != 0x04) return der;
    size_t offset = 2;
    if (der[1] & 0x80) offset += (der[1] & 0x7f);
    if (offset >= der.size()) return der;
    return std::vector<uint8_t>(der.begin() + offset, der.end());
}

/* ═════════════════════════════════════════════════════════════════════════
 *
 *  TEST FUNCTIONS — one per category
 *
 * ═════════════════════════════════════════════════════════════════════════ */

/* ── RNG ─────────────────────────────────────────────────────────────────*/
static json testRNG(Ctx& ctx, const json& op) {
    json res;
    CK_ULONG len = op["params"]["length"].get<CK_ULONG>();
    std::vector<uint8_t> buf(len);

    auto t0 = std::chrono::steady_clock::now();
    CK_RV rv = ctx.p11->C_GenerateRandom(ctx.session, buf.data(), len);
    auto ms  = std::chrono::duration_cast<std::chrono::milliseconds>(
                   std::chrono::steady_clock::now() - t0).count();

    if (rv != CKR_OK) {
        res["status"]   = "FAIL";
        res["error"]    = rvName(rv);
    } else {
        res["status"]   = "PASS";
        res["outputs"]["random_hex"] = toHex(buf);
        res["outputs"]["length"]     = (int)len;
        ctx.log->pass("C_GenerateRandom " + std::to_string(len) + " bytes");
        ctx.log->verbose_hex("  random", buf);
    }
    res["timestamp"]   = isoNow();
    res["duration_ms"] = (int)ms;
    return res;
}

/* ── Hash ────────────────────────────────────────────────────────────────*/
static json testHash(Ctx& ctx, const json& op) {
    json res;
    CK_ULONG mechId = std::stoul(op["mechanism_id"].get<std::string>(), nullptr, 16);
    CK_MECHANISM mech = { mechId, nullptr, 0 };

    std::vector<uint8_t> msg = fromHex(op["params"]["message_hex"].get<std::string>());

    auto t0 = std::chrono::steady_clock::now();
    CK_RV rv = ctx.p11->C_DigestInit(ctx.session, &mech);
    if (isSkipRv(rv)) {
        res["status"] = "SKIP";
        res["reason"] = std::string(rvName(rv)) + " — not implemented";
        ctx.log->skip(op["name"].get<std::string>());
        return res;
    }
    if (rv != CKR_OK) { res["status"]="FAIL"; res["error"]=rvName(rv); return res; }

    rv = ctx.p11->C_DigestUpdate(ctx.session, msg.data(), msg.size());
    if (rv != CKR_OK) { res["status"]="FAIL"; res["error"]=rvName(rv); return res; }

    CK_ULONG digestLen = 0;
    ctx.p11->C_DigestFinal(ctx.session, nullptr, &digestLen);
    std::vector<uint8_t> digest(digestLen);
    rv = ctx.p11->C_DigestFinal(ctx.session, digest.data(), &digestLen);
    digest.resize(digestLen);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                  std::chrono::steady_clock::now() - t0).count();

    std::string gotHex = toHex(digest);
    res["outputs"]["digest_hex"] = gotHex;
    res["outputs"]["digest_len"] = (int)digestLen;

    // Compare against expected if provided
    bool pass = (rv == CKR_OK);
    if (pass && op["expected"].contains("digest_hex")) {
        std::string expHex = op["expected"]["digest_hex"].get<std::string>();
        pass = (gotHex == expHex);
        res["outputs"]["expected_hex"] = expHex;
        res["outputs"]["vectors_match"] = pass;
    }

    res["status"]      = pass ? "PASS" : "FAIL";
    res["error"]       = pass ? json(nullptr) : json(rv == CKR_OK ? "digest mismatch" : rvName(rv));
    res["timestamp"]   = isoNow();
    res["duration_ms"] = (int)ms;

    if (pass) ctx.log->pass(op["name"].get<std::string>());
    else      ctx.log->fail(op["name"].get<std::string>() + " — " + gotHex);
    ctx.log->verbose_hex("  digest", digest);
    return res;
}

/* ── HMAC ────────────────────────────────────────────────────────────────*/
static json testHMAC(Ctx& ctx, const json& op) {
    json res;
    CK_ULONG mechId = std::stoul(op["mechanism_id"].get<std::string>(), nullptr, 16);

    std::vector<uint8_t> keyBytes = fromHex(op["params"]["key_hex"].get<std::string>());
    std::vector<uint8_t> msg      = fromHex(op["params"]["message_hex"].get<std::string>());

    CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
    CK_KEY_TYPE keyType      = CKK_GENERIC_SECRET;
    CK_BBOOL bTrue = CK_TRUE, bFalse = CK_FALSE;

    CK_ATTRIBUTE keyTempl[] = {
        { CKA_CLASS,       &keyClass,     sizeof(keyClass) },
        { CKA_KEY_TYPE,    &keyType,      sizeof(keyType) },
        { CKA_SIGN,        &bTrue,        sizeof(bTrue) },
        { CKA_VERIFY,      &bTrue,        sizeof(bTrue) },
        { CKA_TOKEN,       &bFalse,       sizeof(bFalse) },
        { CKA_VALUE,       keyBytes.data(), keyBytes.size() }
    };

    CK_OBJECT_HANDLE hKey = CK_INVALID_HANDLE;
    auto t0 = std::chrono::steady_clock::now();

    CK_RV rv = ctx.p11->C_CreateObject(ctx.session, keyTempl, 6, &hKey);
    if (rv != CKR_OK) { res["status"]="FAIL"; res["error"]=rvName(rv); return res; }

    CK_MECHANISM mech = { mechId, nullptr, 0 };
    rv = ctx.p11->C_SignInit(ctx.session, &mech, hKey);
    if (isSkipRv(rv)) {
        destroyObj(ctx, hKey);
        res["status"] = "SKIP";
        res["reason"] = std::string(rvName(rv)) + " — not implemented";
        ctx.log->skip(op["name"].get<std::string>());
        return res;
    }
    if (rv != CKR_OK) { destroyObj(ctx, hKey); res["status"]="FAIL"; res["error"]=rvName(rv); return res; }

    CK_ULONG macLen = 0;
    ctx.p11->C_Sign(ctx.session, msg.data(), msg.size(), nullptr, &macLen);
    std::vector<uint8_t> mac(macLen);
    rv = ctx.p11->C_Sign(ctx.session, msg.data(), msg.size(), mac.data(), &macLen);
    mac.resize(macLen);
    destroyObj(ctx, hKey);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                  std::chrono::steady_clock::now() - t0).count();

    std::string gotHex = toHex(mac);
    res["outputs"]["mac_hex"] = gotHex;
    res["outputs"]["mac_len"] = (int)macLen;
    res["inputs"]["key_hex"]  = op["params"]["key_hex"];
    res["inputs"]["msg_hex"]  = op["params"]["message_hex"];

    bool pass = (rv == CKR_OK);
    if (pass && op["expected"].contains("mac_hex")) {
        std::string expHex = op["expected"]["mac_hex"].get<std::string>();
        pass = (gotHex == expHex);
        res["outputs"]["expected_hex"] = expHex;
        res["outputs"]["vectors_match"] = pass;
    }

    res["status"]      = pass ? "PASS" : "FAIL";
    res["error"]       = pass ? json(nullptr) : json(rv == CKR_OK ? "mac mismatch" : rvName(rv));
    res["timestamp"]   = isoNow();
    res["duration_ms"] = (int)ms;

    if (pass) ctx.log->pass(op["name"].get<std::string>());
    else      ctx.log->fail(op["name"].get<std::string>());
    return res;
}

/* ── AES — generic helpers ───────────────────────────────────────────────*/
static CK_OBJECT_HANDLE generateAESKey(Ctx& ctx, int bits, bool wrap = false) {
    CK_MECHANISM mech   = { CKM_AES_KEY_GEN, nullptr, 0 };
    CK_OBJECT_CLASS cls = CKO_SECRET_KEY;
    CK_KEY_TYPE ktype   = CKK_AES;
    CK_ULONG keyLen     = bits / 8;
    CK_BBOOL bTrue = CK_TRUE, bFalse = CK_FALSE;

    CK_ATTRIBUTE templ[] = {
        { CKA_CLASS,     &cls,    sizeof(cls) },
        { CKA_KEY_TYPE,  &ktype,  sizeof(ktype) },
        { CKA_VALUE_LEN, &keyLen, sizeof(keyLen) },
        { CKA_ENCRYPT,   &bTrue,  sizeof(bTrue) },
        { CKA_DECRYPT,   &bTrue,  sizeof(bTrue) },
        { CKA_SIGN,      &bTrue,  sizeof(bTrue) },
        { CKA_VERIFY,    &bTrue,  sizeof(bTrue) },
        { CKA_WRAP,      wrap ? &bTrue : &bFalse, sizeof(CK_BBOOL) },
        { CKA_UNWRAP,    wrap ? &bTrue : &bFalse, sizeof(CK_BBOOL) },
        { CKA_EXTRACTABLE,&bTrue, sizeof(bTrue) },
        { CKA_TOKEN,     &bFalse, sizeof(bFalse) }
    };
    CK_OBJECT_HANDLE hKey = CK_INVALID_HANDLE;
    ctx.p11->C_GenerateKey(ctx.session, &mech, templ, 11, &hKey);
    return hKey;
}

static json testAES_ECB_CBC(Ctx& ctx, const json& op, CK_ULONG mechId) {
    json res;
    int bits = op["params"]["key_bits"].get<int>();
    std::vector<uint8_t> plaintext = fromHex(op["params"]["plaintext_hex"].get<std::string>());
    // Ensure multiple of 16 for ECB/CBC
    while (plaintext.size() % 16 != 0) plaintext.push_back(0);

    std::vector<uint8_t> iv(16, 0x00);  // zero IV for determinism in tests
    CK_MECHANISM mech;
    if (mechId == CKM_AES_ECB) {
        mech = { mechId, nullptr, 0 };
    } else {
        mech = { mechId, iv.data(), iv.size() };
    }

    auto t0 = std::chrono::steady_clock::now();
    CK_OBJECT_HANDLE hKey = generateAESKey(ctx, bits);
    if (hKey == CK_INVALID_HANDLE) { res["status"]="FAIL"; res["error"]="key gen failed"; return res; }

    // Encrypt
    CK_RV rv = ctx.p11->C_EncryptInit(ctx.session, &mech, hKey);
    if (isSkipRv(rv)) {
        destroyObj(ctx, hKey);
        res["status"]="SKIP"; res["reason"]=rvName(rv);
        ctx.log->skip(op["name"].get<std::string>()); return res;
    }
    if (rv != CKR_OK) { destroyObj(ctx, hKey); res["status"]="FAIL"; res["error"]=rvName(rv); return res; }

    CK_ULONG encLen = 0;
    ctx.p11->C_Encrypt(ctx.session, plaintext.data(), plaintext.size(), nullptr, &encLen);
    std::vector<uint8_t> ciphertext(encLen);
    rv = ctx.p11->C_Encrypt(ctx.session, plaintext.data(), plaintext.size(), ciphertext.data(), &encLen);
    ciphertext.resize(encLen);
    if (rv != CKR_OK) { destroyObj(ctx, hKey); res["status"]="FAIL"; res["error"]=rvName(rv); return res; }

    // Reset IV for decrypt
    if (mechId != CKM_AES_ECB) mech.pParameter = iv.data();

    // Decrypt
    rv = ctx.p11->C_DecryptInit(ctx.session, &mech, hKey);
    if (rv != CKR_OK) { destroyObj(ctx, hKey); res["status"]="FAIL"; res["error"]=rvName(rv); return res; }

    CK_ULONG decLen = 0;
    ctx.p11->C_Decrypt(ctx.session, ciphertext.data(), ciphertext.size(), nullptr, &decLen);
    std::vector<uint8_t> recovered(decLen);
    rv = ctx.p11->C_Decrypt(ctx.session, ciphertext.data(), ciphertext.size(), recovered.data(), &decLen);
    recovered.resize(decLen);
    destroyObj(ctx, hKey);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                  std::chrono::steady_clock::now() - t0).count();

    bool match = (rv == CKR_OK) && (recovered == plaintext);
    res["status"]      = match ? "PASS" : "FAIL";
    res["error"]       = match ? json(nullptr) : json(rv==CKR_OK ? "plaintext mismatch after decrypt" : rvName(rv));
    res["timestamp"]   = isoNow();
    res["duration_ms"] = (int)ms;
    res["inputs"]["key_bits"]     = bits;
    res["inputs"]["plaintext_hex"]= toHex(plaintext);
    res["outputs"]["ciphertext_hex"] = toHex(ciphertext);
    res["outputs"]["recovered_hex"]  = toHex(recovered);
    res["outputs"]["round_trip_ok"]  = match;

    if (match) ctx.log->pass(op["name"].get<std::string>());
    else       ctx.log->fail(op["name"].get<std::string>());
    return res;
}

static json testAES_CBC_PAD(Ctx& ctx, const json& op) {
    json res;
    int bits = op["params"]["key_bits"].get<int>();
    std::vector<uint8_t> plaintext = fromHex(op["params"]["plaintext_hex"].get<std::string>());
    std::vector<uint8_t> iv(16, 0x00);
    CK_MECHANISM mech = { CKM_AES_CBC_PAD, iv.data(), iv.size() };

    auto t0 = std::chrono::steady_clock::now();
    CK_OBJECT_HANDLE hKey = generateAESKey(ctx, bits);
    if (hKey == CK_INVALID_HANDLE) { res["status"]="FAIL"; res["error"]="key gen failed"; return res; }

    CK_RV rv = ctx.p11->C_EncryptInit(ctx.session, &mech, hKey);
    if (isSkipRv(rv)) {
        destroyObj(ctx, hKey);
        res["status"]="SKIP"; res["reason"]=rvName(rv);
        ctx.log->skip(op["name"].get<std::string>()); return res;
    }
    if (rv != CKR_OK) { destroyObj(ctx, hKey); res["status"]="FAIL"; res["error"]=rvName(rv); return res; }

    CK_ULONG encLen = 0;
    ctx.p11->C_Encrypt(ctx.session, plaintext.data(), plaintext.size(), nullptr, &encLen);
    std::vector<uint8_t> ciphertext(encLen);
    rv = ctx.p11->C_Encrypt(ctx.session, plaintext.data(), plaintext.size(), ciphertext.data(), &encLen);
    ciphertext.resize(encLen);
    if (rv != CKR_OK) { destroyObj(ctx, hKey); res["status"]="FAIL"; res["error"]=rvName(rv); return res; }

    mech.pParameter = iv.data();
    rv = ctx.p11->C_DecryptInit(ctx.session, &mech, hKey);
    if (rv != CKR_OK) { destroyObj(ctx, hKey); res["status"]="FAIL"; res["error"]=rvName(rv); return res; }

    CK_ULONG decLen = 0;
    ctx.p11->C_Decrypt(ctx.session, ciphertext.data(), ciphertext.size(), nullptr, &decLen);
    std::vector<uint8_t> recovered(decLen);
    rv = ctx.p11->C_Decrypt(ctx.session, ciphertext.data(), ciphertext.size(), recovered.data(), &decLen);
    recovered.resize(decLen);
    destroyObj(ctx, hKey);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                  std::chrono::steady_clock::now() - t0).count();

    bool match = (rv == CKR_OK) && (recovered == plaintext);
    res["status"]      = match ? "PASS" : "FAIL";
    res["error"]       = match ? json(nullptr) : json(rvName(rv));
    res["timestamp"]   = isoNow();
    res["duration_ms"] = (int)ms;
    res["inputs"]["plaintext_hex"]   = toHex(plaintext);
    res["outputs"]["ciphertext_hex"] = toHex(ciphertext);
    res["outputs"]["recovered_hex"]  = toHex(recovered);
    res["outputs"]["round_trip_ok"]  = match;

    if (match) ctx.log->pass(op["name"].get<std::string>());
    else       ctx.log->fail(op["name"].get<std::string>());
    return res;
}

static json testAES_CTR(Ctx& ctx, const json& op) {
    json res;
    int bits = op["params"]["key_bits"].get<int>();
    std::vector<uint8_t> plaintext = fromHex(op["params"]["plaintext_hex"].get<std::string>());

    // CK_AES_CTR_PARAMS: counterBits=128, cb[16]={0}
    struct CK_AES_CTR_PARAMS { CK_ULONG ulCounterBits; CK_BYTE cb[16]; };
    CK_AES_CTR_PARAMS ctrParams;
    ctrParams.ulCounterBits = 128;
    memset(ctrParams.cb, 0, 16);
    CK_MECHANISM mech = { CKM_AES_CTR, &ctrParams, sizeof(ctrParams) };

    auto t0 = std::chrono::steady_clock::now();
    CK_OBJECT_HANDLE hKey = generateAESKey(ctx, bits);
    if (hKey == CK_INVALID_HANDLE) { res["status"]="FAIL"; res["error"]="key gen failed"; return res; }

    CK_RV rv = ctx.p11->C_EncryptInit(ctx.session, &mech, hKey);
    if (isSkipRv(rv)) {
        destroyObj(ctx, hKey);
        res["status"]="SKIP"; res["reason"]=rvName(rv);
        ctx.log->skip(op["name"].get<std::string>()); return res;
    }
    if (rv != CKR_OK) { destroyObj(ctx, hKey); res["status"]="FAIL"; res["error"]=rvName(rv); return res; }

    CK_ULONG encLen = 0;
    ctx.p11->C_Encrypt(ctx.session, plaintext.data(), plaintext.size(), nullptr, &encLen);
    std::vector<uint8_t> ciphertext(encLen);
    rv = ctx.p11->C_Encrypt(ctx.session, plaintext.data(), plaintext.size(), ciphertext.data(), &encLen);
    ciphertext.resize(encLen);
    if (rv != CKR_OK) { destroyObj(ctx, hKey); res["status"]="FAIL"; res["error"]=rvName(rv); return res; }

    // Reset counter for decrypt
    memset(ctrParams.cb, 0, 16);
    rv = ctx.p11->C_DecryptInit(ctx.session, &mech, hKey);
    if (rv != CKR_OK) { destroyObj(ctx, hKey); res["status"]="FAIL"; res["error"]=rvName(rv); return res; }

    CK_ULONG decLen = 0;
    ctx.p11->C_Decrypt(ctx.session, ciphertext.data(), ciphertext.size(), nullptr, &decLen);
    std::vector<uint8_t> recovered(decLen);
    rv = ctx.p11->C_Decrypt(ctx.session, ciphertext.data(), ciphertext.size(), recovered.data(), &decLen);
    recovered.resize(decLen);
    destroyObj(ctx, hKey);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                  std::chrono::steady_clock::now() - t0).count();

    bool match = (rv == CKR_OK) && (recovered == plaintext);
    res["status"]      = match ? "PASS" : "FAIL";
    res["error"]       = match ? json(nullptr) : json(rvName(rv));
    res["timestamp"]   = isoNow();
    res["duration_ms"] = (int)ms;
    res["outputs"]["round_trip_ok"] = match;

    if (match) ctx.log->pass(op["name"].get<std::string>());
    else       ctx.log->fail(op["name"].get<std::string>());
    return res;
}

static json testAES_GCM(Ctx& ctx, const json& op) {
    json res;
    int bits = op["params"]["key_bits"].get<int>();
    std::vector<uint8_t> plaintext = fromHex(op["params"]["plaintext_hex"].get<std::string>());
    std::vector<uint8_t> aad       = fromHex(op["params"]["aad_hex"].get<std::string>());
    std::vector<uint8_t> iv(12, 0x00);  // 96-bit IV

    // CK_GCM_PARAMS
    struct CK_GCM_PARAMS {
        CK_BYTE_PTR pIv;   CK_ULONG ulIvLen;    CK_ULONG ulIvBits;
        CK_BYTE_PTR pAAD;  CK_ULONG ulAADLen;   CK_ULONG ulTagBits;
    };
    CK_GCM_PARAMS gcmParams;
    gcmParams.pIv      = iv.data();   gcmParams.ulIvLen   = iv.size(); gcmParams.ulIvBits = 96;
    gcmParams.pAAD     = aad.data();  gcmParams.ulAADLen  = aad.size(); gcmParams.ulTagBits = 128;
    CK_MECHANISM mech  = { CKM_AES_GCM, &gcmParams, sizeof(gcmParams) };

    auto t0 = std::chrono::steady_clock::now();
    CK_OBJECT_HANDLE hKey = generateAESKey(ctx, bits);
    if (hKey == CK_INVALID_HANDLE) { res["status"]="FAIL"; res["error"]="key gen failed"; return res; }

    CK_RV rv = ctx.p11->C_EncryptInit(ctx.session, &mech, hKey);
    if (isSkipRv(rv)) {
        destroyObj(ctx, hKey);
        res["status"]="SKIP"; res["reason"]=rvName(rv);
        ctx.log->skip(op["name"].get<std::string>()); return res;
    }
    if (rv != CKR_OK) { destroyObj(ctx, hKey); res["status"]="FAIL"; res["error"]=rvName(rv); return res; }

    CK_ULONG encLen = 0;
    ctx.p11->C_Encrypt(ctx.session, plaintext.data(), plaintext.size(), nullptr, &encLen);
    std::vector<uint8_t> ciphertext(encLen);
    rv = ctx.p11->C_Encrypt(ctx.session, plaintext.data(), plaintext.size(), ciphertext.data(), &encLen);
    ciphertext.resize(encLen);
    if (rv != CKR_OK) { destroyObj(ctx, hKey); res["status"]="FAIL"; res["error"]=rvName(rv); return res; }

    // Decrypt — same IV/AAD
    gcmParams.pIv = iv.data(); gcmParams.pAAD = aad.data();
    rv = ctx.p11->C_DecryptInit(ctx.session, &mech, hKey);
    if (rv != CKR_OK) { destroyObj(ctx, hKey); res["status"]="FAIL"; res["error"]=rvName(rv); return res; }

    CK_ULONG decLen = 0;
    ctx.p11->C_Decrypt(ctx.session, ciphertext.data(), ciphertext.size(), nullptr, &decLen);
    std::vector<uint8_t> recovered(decLen);
    rv = ctx.p11->C_Decrypt(ctx.session, ciphertext.data(), ciphertext.size(), recovered.data(), &decLen);
    recovered.resize(decLen);

    bool match = (rv == CKR_OK) && (recovered == plaintext);

    // Negative test: tamper ciphertext → expect decrypt failure
    std::vector<uint8_t> tampered = ciphertext;
    tampered[0] ^= 0xff;
    gcmParams.pIv = iv.data(); gcmParams.pAAD = aad.data();
    ctx.p11->C_DecryptInit(ctx.session, &mech, hKey);
    CK_ULONG badLen = tampered.size() + 16;
    std::vector<uint8_t> badOut(badLen);
    CK_RV tamperedRv = ctx.p11->C_Decrypt(ctx.session, tampered.data(), tampered.size(), badOut.data(), &badLen);
    bool tamperDetected = (tamperedRv != CKR_OK);

    destroyObj(ctx, hKey);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                  std::chrono::steady_clock::now() - t0).count();

    bool pass = match && tamperDetected;
    res["status"]      = pass ? "PASS" : "FAIL";
    res["error"]       = pass ? json(nullptr) : json(!match ? "plaintext mismatch" : "tamper not detected");
    res["timestamp"]   = isoNow();
    res["duration_ms"] = (int)ms;
    res["outputs"]["round_trip_ok"]           = match;
    res["outputs"]["negative_tamper_detected"] = tamperDetected;
    res["outputs"]["tamper_rv"]               = rvName(tamperedRv);

    if (pass) ctx.log->pass(op["name"].get<std::string>());
    else      ctx.log->fail(op["name"].get<std::string>());
    return res;
}

static json testAES_CMAC(Ctx& ctx, const json& op) {
    json res;
    int bits = op["params"]["key_bits"].get<int>();
    std::vector<uint8_t> msg = fromHex(op["params"]["message_hex"].get<std::string>());

    CK_MECHANISM mech = { CKM_AES_CMAC, nullptr, 0 };

    auto t0 = std::chrono::steady_clock::now();
    CK_OBJECT_HANDLE hKey = generateAESKey(ctx, bits);
    if (hKey == CK_INVALID_HANDLE) { res["status"]="FAIL"; res["error"]="key gen failed"; return res; }

    CK_RV rv = ctx.p11->C_SignInit(ctx.session, &mech, hKey);
    if (isSkipRv(rv)) {
        destroyObj(ctx, hKey);
        res["status"]="SKIP"; res["reason"]=rvName(rv);
        ctx.log->skip(op["name"].get<std::string>()); return res;
    }
    if (rv != CKR_OK) { destroyObj(ctx, hKey); res["status"]="FAIL"; res["error"]=rvName(rv); return res; }

    CK_ULONG macLen = 0;
    ctx.p11->C_Sign(ctx.session, msg.data(), msg.size(), nullptr, &macLen);
    std::vector<uint8_t> mac(macLen);
    rv = ctx.p11->C_Sign(ctx.session, msg.data(), msg.size(), mac.data(), &macLen);
    mac.resize(macLen);

    // Verify
    bool verifyOk = false;
    if (rv == CKR_OK) {
        ctx.p11->C_VerifyInit(ctx.session, &mech, hKey);
        verifyOk = (ctx.p11->C_Verify(ctx.session, msg.data(), msg.size(), mac.data(), mac.size()) == CKR_OK);
    }
    destroyObj(ctx, hKey);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                  std::chrono::steady_clock::now() - t0).count();

    bool pass = (rv == CKR_OK) && verifyOk;
    res["status"]      = pass ? "PASS" : "FAIL";
    res["error"]       = pass ? json(nullptr) : json(rvName(rv));
    res["timestamp"]   = isoNow();
    res["duration_ms"] = (int)ms;
    res["outputs"]["mac_hex"]   = toHex(mac);
    res["outputs"]["verify_ok"] = verifyOk;

    if (pass) ctx.log->pass(op["name"].get<std::string>());
    else      ctx.log->fail(op["name"].get<std::string>());
    return res;
}

static json testAES_KeyWrap(Ctx& ctx, const json& op) {
    json res;
    int wrapBits   = op["params"]["wrapping_key_bits"].get<int>();
    int targetBits = op["params"]["target_key_bits"].get<int>();

    auto t0 = std::chrono::steady_clock::now();
    CK_OBJECT_HANDLE hWrap   = generateAESKey(ctx, wrapBits, /*wrap=*/true);
    CK_OBJECT_HANDLE hTarget = generateAESKey(ctx, targetBits);
    if (hWrap == CK_INVALID_HANDLE || hTarget == CK_INVALID_HANDLE) {
        destroyObj(ctx, hWrap); destroyObj(ctx, hTarget);
        res["status"]="FAIL"; res["error"]="key gen failed"; return res;
    }

    CK_MECHANISM mech = { CKM_AES_KEY_WRAP, nullptr, 0 };

    // Wrap
    CK_ULONG wrappedLen = 0;
    CK_RV rv = ctx.p11->C_WrapKey(ctx.session, &mech, hWrap, hTarget, nullptr, &wrappedLen);
    if (isSkipRv(rv)) {
        destroyObj(ctx, hWrap); destroyObj(ctx, hTarget);
        res["status"]="SKIP"; res["reason"]=rvName(rv);
        ctx.log->skip(op["name"].get<std::string>()); return res;
    }
    if (rv != CKR_OK) {
        destroyObj(ctx, hWrap); destroyObj(ctx, hTarget);
        res["status"]="FAIL"; res["error"]=rvName(rv); return res;
    }
    std::vector<uint8_t> wrapped(wrappedLen);
    rv = ctx.p11->C_WrapKey(ctx.session, &mech, hWrap, hTarget, wrapped.data(), &wrappedLen);
    wrapped.resize(wrappedLen);
    if (rv != CKR_OK) {
        destroyObj(ctx, hWrap); destroyObj(ctx, hTarget);
        res["status"]="FAIL"; res["error"]=rvName(rv); return res;
    }

    // Unwrap
    CK_OBJECT_CLASS cls  = CKO_SECRET_KEY;
    CK_KEY_TYPE ktype    = CKK_AES;
    CK_BBOOL bTrue = CK_TRUE, bFalse = CK_FALSE;
    CK_ULONG keyLen      = targetBits / 8;
    CK_ATTRIBUTE unwrapTempl[] = {
        { CKA_CLASS,      &cls,    sizeof(cls) },
        { CKA_KEY_TYPE,   &ktype,  sizeof(ktype) },
        { CKA_ENCRYPT,    &bTrue,  sizeof(bTrue) },
        { CKA_DECRYPT,    &bTrue,  sizeof(bTrue) },
        { CKA_EXTRACTABLE,&bTrue,  sizeof(bTrue) },
        { CKA_TOKEN,      &bFalse, sizeof(bFalse) }
    };

    CK_OBJECT_HANDLE hUnwrapped = CK_INVALID_HANDLE;
    rv = ctx.p11->C_UnwrapKey(ctx.session, &mech, hWrap,
                               wrapped.data(), wrapped.size(),
                               unwrapTempl, 6, &hUnwrapped);

    // Compare key values
    std::vector<uint8_t> origVal    = exportKeyValue(ctx, hTarget);
    std::vector<uint8_t> recovVal   = exportKeyValue(ctx, hUnwrapped);
    bool match = (rv == CKR_OK) && !origVal.empty() && (origVal == recovVal);

    destroyObj(ctx, hWrap); destroyObj(ctx, hTarget); destroyObj(ctx, hUnwrapped);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                  std::chrono::steady_clock::now() - t0).count();

    res["status"]      = match ? "PASS" : "FAIL";
    res["error"]       = match ? json(nullptr) : json(rv==CKR_OK ? "key value mismatch after unwrap" : rvName(rv));
    res["timestamp"]   = isoNow();
    res["duration_ms"] = (int)ms;
    res["outputs"]["wrapped_key_hex"]  = toHex(wrapped);
    res["outputs"]["round_trip_ok"]    = match;

    if (match) ctx.log->pass(op["name"].get<std::string>());
    else       ctx.log->fail(op["name"].get<std::string>());
    return res;
}

/* ── RSA Sign ────────────────────────────────────────────────────────────*/
static json testRSASign(Ctx& ctx, const json& op) {
    json res;
    CK_ULONG mechId = std::stoul(op["mechanism_id"].get<std::string>(), nullptr, 16);
    int bits = op["params"]["key_bits"].get<int>();
    std::vector<uint8_t> msg = fromHex(op["params"]["message_hex"].get<std::string>());

    CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY, privClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE ktype        = CKK_RSA;
    CK_BBOOL bTrue = CK_TRUE, bFalse = CK_FALSE;
    CK_ULONG keyBits         = bits;
    CK_BYTE pubExp[]         = { 0x01, 0x00, 0x01 };

    CK_ATTRIBUTE pubTempl[] = {
        { CKA_CLASS,          &pubClass, sizeof(pubClass) },
        { CKA_KEY_TYPE,       &ktype,    sizeof(ktype) },
        { CKA_VERIFY,         &bTrue,    sizeof(bTrue) },
        { CKA_MODULUS_BITS,   &keyBits,  sizeof(keyBits) },
        { CKA_PUBLIC_EXPONENT, pubExp,   sizeof(pubExp) },
        { CKA_TOKEN,          &bFalse,   sizeof(bFalse) }
    };
    CK_ATTRIBUTE privTempl[] = {
        { CKA_CLASS,    &privClass, sizeof(privClass) },
        { CKA_KEY_TYPE, &ktype,     sizeof(ktype) },
        { CKA_SIGN,     &bTrue,     sizeof(bTrue) },
        { CKA_TOKEN,    &bFalse,    sizeof(bFalse) }
    };

    CK_MECHANISM kgMech      = { CKM_RSA_PKCS_KEY_PAIR_GEN, nullptr, 0 };
    CK_OBJECT_HANDLE hPub    = CK_INVALID_HANDLE, hPriv = CK_INVALID_HANDLE;
    auto t0 = std::chrono::steady_clock::now();

    CK_RV rv = ctx.p11->C_GenerateKeyPair(ctx.session, &kgMech,
        pubTempl, 6, privTempl, 4, &hPub, &hPriv);
    if (rv != CKR_OK) { res["status"]="FAIL"; res["error"]=rvName(rv); return res; }

    // Build PSS params if needed
    struct CK_RSA_PKCS_PSS_PARAMS {
        CK_MECHANISM_TYPE hashAlg;
        CK_RSA_PKCS_MGF_TYPE mgf;
        CK_ULONG sLen;
    };
    CK_RSA_PKCS_PSS_PARAMS pssParams;
    CK_MECHANISM mech;

    std::string mechStr = op["mechanism"].get<std::string>();
    if (mechStr.find("PSS") != std::string::npos) {
        bool isSha512 = (mechStr.find("512") != std::string::npos);
        pssParams.hashAlg = isSha512 ? CKM_SHA512 : CKM_SHA256;
        pssParams.mgf     = isSha512 ? CKG_MGF1_SHA512 : CKG_MGF1_SHA256;
        pssParams.sLen    = isSha512 ? 64 : 32;
        mech = { mechId, &pssParams, sizeof(pssParams) };
    } else {
        mech = { mechId, nullptr, 0 };
    }

    rv = ctx.p11->C_SignInit(ctx.session, &mech, hPriv);
    if (isSkipRv(rv)) {
        destroyObj(ctx, hPub); destroyObj(ctx, hPriv);
        res["status"]="SKIP"; res["reason"]=rvName(rv);
        ctx.log->skip(op["name"].get<std::string>()); return res;
    }
    if (rv != CKR_OK) {
        destroyObj(ctx, hPub); destroyObj(ctx, hPriv);
        res["status"]="FAIL"; res["error"]=rvName(rv); return res;
    }

    CK_ULONG sigLen = 0;
    ctx.p11->C_Sign(ctx.session, msg.data(), msg.size(), nullptr, &sigLen);
    std::vector<uint8_t> sig(sigLen);
    rv = ctx.p11->C_Sign(ctx.session, msg.data(), msg.size(), sig.data(), &sigLen);
    sig.resize(sigLen);
    if (rv != CKR_OK) {
        destroyObj(ctx, hPub); destroyObj(ctx, hPriv);
        res["status"]="FAIL"; res["error"]=rvName(rv); return res;
    }

    // Verify
    ctx.p11->C_VerifyInit(ctx.session, &mech, hPub);
    bool verifyOk = (ctx.p11->C_Verify(ctx.session, msg.data(), msg.size(), sig.data(), sig.size()) == CKR_OK);

    // Negative: tamper signature
    std::vector<uint8_t> badSig = sig;
    badSig[0] ^= 0xff;
    ctx.p11->C_VerifyInit(ctx.session, &mech, hPub);
    bool tamperDetected = (ctx.p11->C_Verify(ctx.session, msg.data(), msg.size(), badSig.data(), badSig.size()) != CKR_OK);

    destroyObj(ctx, hPub); destroyObj(ctx, hPriv);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                  std::chrono::steady_clock::now() - t0).count();

    bool pass = verifyOk && tamperDetected;
    res["status"]      = pass ? "PASS" : "FAIL";
    res["error"]       = pass ? json(nullptr) : json(!verifyOk ? "verify failed" : "tamper not detected");
    res["timestamp"]   = isoNow();
    res["duration_ms"] = (int)ms;
    res["inputs"]["key_bits"] = bits;
    res["outputs"]["sig_len"]            = (int)sigLen;
    res["outputs"]["verify_ok"]          = verifyOk;
    res["outputs"]["negative_tamper_ok"] = tamperDetected;

    if (pass) ctx.log->pass(op["name"].get<std::string>());
    else      ctx.log->fail(op["name"].get<std::string>());
    return res;
}

/* ── RSA Encrypt (OAEP) ──────────────────────────────────────────────────*/
static json testRSAEncrypt(Ctx& ctx, const json& op) {
    json res;
    int bits = op["params"]["key_bits"].get<int>();
    std::vector<uint8_t> plaintext = fromHex(op["params"]["plaintext_hex"].get<std::string>());

    CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY, privClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE ktype        = CKK_RSA;
    CK_BBOOL bTrue = CK_TRUE, bFalse = CK_FALSE;
    CK_ULONG keyBits         = bits;
    CK_BYTE pubExp[]         = { 0x01, 0x00, 0x01 };

    CK_ATTRIBUTE pubTempl[] = {
        { CKA_CLASS,           &pubClass, sizeof(pubClass) },
        { CKA_KEY_TYPE,        &ktype,    sizeof(ktype) },
        { CKA_ENCRYPT,         &bTrue,    sizeof(bTrue) },
        { CKA_MODULUS_BITS,    &keyBits,  sizeof(keyBits) },
        { CKA_PUBLIC_EXPONENT,  pubExp,   sizeof(pubExp) },
        { CKA_TOKEN,           &bFalse,   sizeof(bFalse) }
    };
    CK_ATTRIBUTE privTempl[] = {
        { CKA_CLASS,    &privClass, sizeof(privClass) },
        { CKA_KEY_TYPE, &ktype,     sizeof(ktype) },
        { CKA_DECRYPT,  &bTrue,     sizeof(bTrue) },
        { CKA_TOKEN,    &bFalse,    sizeof(bFalse) }
    };

    CK_MECHANISM kgMech   = { CKM_RSA_PKCS_KEY_PAIR_GEN, nullptr, 0 };
    CK_OBJECT_HANDLE hPub = CK_INVALID_HANDLE, hPriv = CK_INVALID_HANDLE;
    auto t0 = std::chrono::steady_clock::now();

    CK_RV rv = ctx.p11->C_GenerateKeyPair(ctx.session, &kgMech,
        pubTempl, 6, privTempl, 4, &hPub, &hPriv);
    if (rv != CKR_OK) { res["status"]="FAIL"; res["error"]=rvName(rv); return res; }

    struct CK_RSA_PKCS_OAEP_PARAMS {
        CK_MECHANISM_TYPE hashAlg;
        CK_RSA_PKCS_MGF_TYPE mgf;
        CK_RSA_PKCS_OAEP_SOURCE_TYPE source;
        CK_VOID_PTR pSourceData;
        CK_ULONG ulSourceDataLen;
    };
    CK_RSA_PKCS_OAEP_PARAMS oaepParams = {
        CKM_SHA256, CKG_MGF1_SHA256, CKZ_DATA_SPECIFIED, nullptr, 0
    };
    CK_MECHANISM mech = { CKM_RSA_PKCS_OAEP, &oaepParams, sizeof(oaepParams) };

    rv = ctx.p11->C_EncryptInit(ctx.session, &mech, hPub);
    if (isSkipRv(rv)) {
        destroyObj(ctx, hPub); destroyObj(ctx, hPriv);
        res["status"]="SKIP"; res["reason"]=rvName(rv);
        ctx.log->skip(op["name"].get<std::string>()); return res;
    }
    if (rv != CKR_OK) {
        destroyObj(ctx, hPub); destroyObj(ctx, hPriv);
        res["status"]="FAIL"; res["error"]=rvName(rv); return res;
    }

    CK_ULONG encLen = 0;
    ctx.p11->C_Encrypt(ctx.session, plaintext.data(), plaintext.size(), nullptr, &encLen);
    std::vector<uint8_t> ciphertext(encLen);
    rv = ctx.p11->C_Encrypt(ctx.session, plaintext.data(), plaintext.size(), ciphertext.data(), &encLen);
    ciphertext.resize(encLen);
    if (rv != CKR_OK) {
        destroyObj(ctx, hPub); destroyObj(ctx, hPriv);
        res["status"]="FAIL"; res["error"]=rvName(rv); return res;
    }

    ctx.p11->C_DecryptInit(ctx.session, &mech, hPriv);
    CK_ULONG decLen = 0;
    ctx.p11->C_Decrypt(ctx.session, ciphertext.data(), ciphertext.size(), nullptr, &decLen);
    std::vector<uint8_t> recovered(decLen);
    rv = ctx.p11->C_Decrypt(ctx.session, ciphertext.data(), ciphertext.size(), recovered.data(), &decLen);
    recovered.resize(decLen);

    destroyObj(ctx, hPub); destroyObj(ctx, hPriv);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                  std::chrono::steady_clock::now() - t0).count();

    bool match = (rv == CKR_OK) && (recovered == plaintext);
    res["status"]      = match ? "PASS" : "FAIL";
    res["error"]       = match ? json(nullptr) : json(rvName(rv));
    res["timestamp"]   = isoNow();
    res["duration_ms"] = (int)ms;
    res["outputs"]["round_trip_ok"] = match;

    if (match) ctx.log->pass(op["name"].get<std::string>());
    else       ctx.log->fail(op["name"].get<std::string>());
    return res;
}

/* ── ECDSA ───────────────────────────────────────────────────────────────*/
static std::pair<const uint8_t*, size_t> curveOID(const std::string& curve) {
    if (curve == "P-256")   return { OID_P256,   sizeof(OID_P256)   };
    if (curve == "P-384")   return { OID_P384,   sizeof(OID_P384)   };
    if (curve == "P-521")   return { OID_P521,   sizeof(OID_P521)   };
    if (curve == "Ed25519") return { OID_ED25519, sizeof(OID_ED25519) };
    if (curve == "Ed448")   return { OID_ED448,   sizeof(OID_ED448)  };
    if (curve == "X25519")  return { OID_X25519,  sizeof(OID_X25519) };
    if (curve == "X448")    return { OID_X448,    sizeof(OID_X448)  };
    return { nullptr, 0 };
}

static json testECDSA(Ctx& ctx, const json& op) {
    json res;
    CK_ULONG mechId = std::stoul(op["mechanism_id"].get<std::string>(), nullptr, 16);
    std::string curve = op["params"]["curve"].get<std::string>();
    std::vector<uint8_t> msg = fromHex(op["params"]["message_hex"].get<std::string>());

    auto [oidData, oidLen] = curveOID(curve);
    if (!oidData) { res["status"]="FAIL"; res["error"]="unknown curve"; return res; }

    CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY, privClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE ktype = CKK_EC;
    CK_BBOOL bTrue = CK_TRUE, bFalse = CK_FALSE;

    CK_ATTRIBUTE pubTempl[] = {
        { CKA_CLASS,      &pubClass, sizeof(pubClass) },
        { CKA_KEY_TYPE,   &ktype,    sizeof(ktype) },
        { CKA_VERIFY,     &bTrue,    sizeof(bTrue) },
        { CKA_EC_PARAMS,  const_cast<uint8_t*>(oidData), oidLen },
        { CKA_TOKEN,      &bFalse,   sizeof(bFalse) }
    };
    CK_ATTRIBUTE privTempl[] = {
        { CKA_CLASS,      &privClass, sizeof(privClass) },
        { CKA_KEY_TYPE,   &ktype,     sizeof(ktype) },
        { CKA_SIGN,       &bTrue,     sizeof(bTrue) },
        { CKA_TOKEN,      &bFalse,    sizeof(bFalse) }
    };

    CK_MECHANISM kgMech   = { CKM_EC_KEY_PAIR_GEN, nullptr, 0 };
    CK_OBJECT_HANDLE hPub = CK_INVALID_HANDLE, hPriv = CK_INVALID_HANDLE;
    auto t0 = std::chrono::steady_clock::now();

    CK_RV rv = ctx.p11->C_GenerateKeyPair(ctx.session, &kgMech,
        pubTempl, 5, privTempl, 4, &hPub, &hPriv);
    if (rv != CKR_OK) { res["status"]="FAIL"; res["error"]=rvName(rv); return res; }

    CK_MECHANISM mech = { mechId, nullptr, 0 };
    rv = ctx.p11->C_SignInit(ctx.session, &mech, hPriv);
    if (isSkipRv(rv)) {
        destroyObj(ctx, hPub); destroyObj(ctx, hPriv);
        res["status"]="SKIP"; res["reason"]=rvName(rv);
        ctx.log->skip(op["name"].get<std::string>()); return res;
    }
    if (rv != CKR_OK) {
        destroyObj(ctx, hPub); destroyObj(ctx, hPriv);
        res["status"]="FAIL"; res["error"]=rvName(rv); return res;
    }

    CK_ULONG sigLen = 0;
    ctx.p11->C_Sign(ctx.session, msg.data(), msg.size(), nullptr, &sigLen);
    std::vector<uint8_t> sig(sigLen);
    rv = ctx.p11->C_Sign(ctx.session, msg.data(), msg.size(), sig.data(), &sigLen);
    sig.resize(sigLen);
    if (rv != CKR_OK) {
        destroyObj(ctx, hPub); destroyObj(ctx, hPriv);
        res["status"]="FAIL"; res["error"]=rvName(rv); return res;
    }

    ctx.p11->C_VerifyInit(ctx.session, &mech, hPub);
    bool verifyOk = (ctx.p11->C_Verify(ctx.session, msg.data(), msg.size(), sig.data(), sig.size()) == CKR_OK);

    std::vector<uint8_t> badSig = sig;
    badSig[0] ^= 0xff;
    ctx.p11->C_VerifyInit(ctx.session, &mech, hPub);
    bool tamperDetected = (ctx.p11->C_Verify(ctx.session, msg.data(), msg.size(), badSig.data(), badSig.size()) != CKR_OK);

    destroyObj(ctx, hPub); destroyObj(ctx, hPriv);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                  std::chrono::steady_clock::now() - t0).count();

    bool pass = verifyOk && tamperDetected;
    res["status"]      = pass ? "PASS" : "FAIL";
    res["error"]       = pass ? json(nullptr) : json(!verifyOk ? "verify failed" : "tamper not detected");
    res["timestamp"]   = isoNow();
    res["duration_ms"] = (int)ms;
    res["inputs"]["curve"] = curve;
    res["outputs"]["sig_len"]            = (int)sigLen;
    res["outputs"]["verify_ok"]          = verifyOk;
    res["outputs"]["negative_tamper_ok"] = tamperDetected;

    if (pass) ctx.log->pass(op["name"].get<std::string>());
    else      ctx.log->fail(op["name"].get<std::string>());
    return res;
}

/* ── EdDSA (Ed25519, Ed448) ──────────────────────────────────────────────*/
static json testEdDSA(Ctx& ctx, const json& op) {
    json res;
    CK_ULONG mechId = std::stoul(op["mechanism_id"].get<std::string>(), nullptr, 16);
    std::string curve = op["params"]["curve"].get<std::string>();
    std::vector<uint8_t> msg = fromHex(op["params"]["message_hex"].get<std::string>());

    auto [oidData, oidLen] = curveOID(curve);
    if (!oidData) { res["status"]="FAIL"; res["error"]="unknown curve"; return res; }

    CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY, privClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE ktype = CKK_EC_EDWARDS;
    CK_BBOOL bTrue = CK_TRUE, bFalse = CK_FALSE;

    CK_ATTRIBUTE pubTempl[] = {
        { CKA_CLASS,     &pubClass, sizeof(pubClass) },
        { CKA_KEY_TYPE,  &ktype,    sizeof(ktype) },
        { CKA_VERIFY,    &bTrue,    sizeof(bTrue) },
        { CKA_EC_PARAMS, const_cast<uint8_t*>(oidData), oidLen },
        { CKA_TOKEN,     &bFalse,   sizeof(bFalse) }
    };
    CK_ATTRIBUTE privTempl[] = {
        { CKA_CLASS,     &privClass, sizeof(privClass) },
        { CKA_KEY_TYPE,  &ktype,     sizeof(ktype) },
        { CKA_SIGN,      &bTrue,     sizeof(bTrue) },
        { CKA_TOKEN,     &bFalse,    sizeof(bFalse) }
    };

    CK_MECHANISM kgMech   = { CKM_EC_EDWARDS_KEY_PAIR_GEN, nullptr, 0 };
    CK_OBJECT_HANDLE hPub = CK_INVALID_HANDLE, hPriv = CK_INVALID_HANDLE;
    auto t0 = std::chrono::steady_clock::now();

    CK_RV rv = ctx.p11->C_GenerateKeyPair(ctx.session, &kgMech,
        pubTempl, 5, privTempl, 4, &hPub, &hPriv);
    if (isSkipRv(rv)) {
        res["status"]="SKIP"; res["reason"]=rvName(rv);
        ctx.log->skip(op["name"].get<std::string>()); return res;
    }
    if (rv != CKR_OK) { res["status"]="FAIL"; res["error"]=rvName(rv); return res; }

    CK_MECHANISM mech = { mechId, nullptr, 0 };
    rv = ctx.p11->C_SignInit(ctx.session, &mech, hPriv);
    if (isSkipRv(rv)) {
        destroyObj(ctx, hPub); destroyObj(ctx, hPriv);
        res["status"]="SKIP"; res["reason"]=rvName(rv);
        ctx.log->skip(op["name"].get<std::string>()); return res;
    }
    if (rv != CKR_OK) {
        destroyObj(ctx, hPub); destroyObj(ctx, hPriv);
        res["status"]="FAIL"; res["error"]=rvName(rv); return res;
    }

    CK_ULONG sigLen = 0;
    ctx.p11->C_Sign(ctx.session, msg.data(), msg.size(), nullptr, &sigLen);
    std::vector<uint8_t> sig(sigLen);
    rv = ctx.p11->C_Sign(ctx.session, msg.data(), msg.size(), sig.data(), &sigLen);
    sig.resize(sigLen);
    if (rv != CKR_OK) {
        destroyObj(ctx, hPub); destroyObj(ctx, hPriv);
        res["status"]="FAIL"; res["error"]=rvName(rv); return res;
    }

    ctx.p11->C_VerifyInit(ctx.session, &mech, hPub);
    bool verifyOk = (ctx.p11->C_Verify(ctx.session, msg.data(), msg.size(), sig.data(), sig.size()) == CKR_OK);

    std::vector<uint8_t> badSig = sig;
    badSig[0] ^= 0xff;
    ctx.p11->C_VerifyInit(ctx.session, &mech, hPub);
    bool tamperDetected = (ctx.p11->C_Verify(ctx.session, msg.data(), msg.size(), badSig.data(), badSig.size()) != CKR_OK);

    destroyObj(ctx, hPub); destroyObj(ctx, hPriv);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                  std::chrono::steady_clock::now() - t0).count();

    bool pass = verifyOk && tamperDetected;
    res["status"]      = pass ? "PASS" : "FAIL";
    res["error"]       = pass ? json(nullptr) : json(!verifyOk ? "verify failed" : "tamper not detected");
    res["timestamp"]   = isoNow();
    res["duration_ms"] = (int)ms;
    res["outputs"]["sig_len"]            = (int)sigLen;
    res["outputs"]["verify_ok"]          = verifyOk;
    res["outputs"]["negative_tamper_ok"] = tamperDetected;

    if (pass) ctx.log->pass(op["name"].get<std::string>());
    else      ctx.log->fail(op["name"].get<std::string>());
    return res;
}

/* ── ECDH / X25519 / X448 ────────────────────────────────────────────────*/
static json testECDH(Ctx& ctx, const json& op) {
    json res;
    std::string curve = op["params"]["curve"].get<std::string>();

    bool isMontgomery = (curve == "X25519" || curve == "X448");
    auto [oidData, oidLen] = curveOID(curve);
    if (!oidData) { res["status"]="FAIL"; res["error"]="unknown curve"; return res; }

    CK_KEY_TYPE ktype = isMontgomery ? CKK_EC_MONTGOMERY : CKK_EC;
    CK_ULONG kgMechId = isMontgomery ? CKM_EC_MONTGOMERY_KEY_PAIR_GEN : CKM_EC_KEY_PAIR_GEN;

    CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY, privClass = CKO_PRIVATE_KEY;
    CK_BBOOL bTrue = CK_TRUE, bFalse = CK_FALSE;

    auto makeKeyPair = [&](CK_OBJECT_HANDLE& hPub, CK_OBJECT_HANDLE& hPriv) -> CK_RV {
        CK_ATTRIBUTE pubT[] = {
            { CKA_CLASS,     &pubClass, sizeof(pubClass) },
            { CKA_KEY_TYPE,  &ktype,    sizeof(ktype) },
            { CKA_DERIVE,    &bTrue,    sizeof(bTrue) },
            { CKA_EC_PARAMS, const_cast<uint8_t*>(oidData), oidLen },
            { CKA_TOKEN,     &bFalse,   sizeof(bFalse) }
        };
        CK_ATTRIBUTE privT[] = {
            { CKA_CLASS,     &privClass, sizeof(privClass) },
            { CKA_KEY_TYPE,  &ktype,     sizeof(ktype) },
            { CKA_DERIVE,    &bTrue,     sizeof(bTrue) },
            { CKA_TOKEN,     &bFalse,    sizeof(bFalse) }
        };
        CK_MECHANISM kg = { kgMechId, nullptr, 0 };
        return ctx.p11->C_GenerateKeyPair(ctx.session, &kg, pubT, 5, privT, 4, &hPub, &hPriv);
    };

    CK_OBJECT_HANDLE hAlicePub = CK_INVALID_HANDLE, hAlicePriv = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE hBobPub   = CK_INVALID_HANDLE, hBobPriv   = CK_INVALID_HANDLE;
    auto t0 = std::chrono::steady_clock::now();

    CK_RV rv = makeKeyPair(hAlicePub, hAlicePriv);
    if (isSkipRv(rv)) {
        res["status"]="SKIP"; res["reason"]=rvName(rv);
        ctx.log->skip(op["name"].get<std::string>()); return res;
    }
    if (rv != CKR_OK) { res["status"]="FAIL"; res["error"]=rvName(rv); return res; }

    rv = makeKeyPair(hBobPub, hBobPriv);
    if (rv != CKR_OK) {
        destroyObj(ctx, hAlicePub); destroyObj(ctx, hAlicePriv);
        res["status"]="FAIL"; res["error"]=rvName(rv); return res;
    }

    // Export Bob's public EC point
    CK_ULONG bobPtLen = 0;
    CK_ATTRIBUTE getPt = { CKA_EC_POINT, nullptr, 0 };
    ctx.p11->C_GetAttributeValue(ctx.session, hBobPub, &getPt, 1);
    bobPtLen = getPt.ulValueLen;
    std::vector<uint8_t> bobEcPoint(bobPtLen);
    getPt.pValue = bobEcPoint.data();
    ctx.p11->C_GetAttributeValue(ctx.session, hBobPub, &getPt, 1);
    // Strip DER wrapper to get raw point
    std::vector<uint8_t> bobRawPoint = stripEcPointWrapper(bobEcPoint);

    // Derive shared secret — Alice with Bob's public point
    struct CK_ECDH1_DERIVE_PARAMS {
        CK_EC_KDF_TYPE kdf;
        CK_ULONG ulSharedDataLen;
        CK_BYTE_PTR pSharedData;
        CK_ULONG ulPublicDataLen;
        CK_BYTE_PTR pPublicData;
    };
    CK_ECDH1_DERIVE_PARAMS dhParams;
    dhParams.kdf             = CKD_NULL;
    dhParams.ulSharedDataLen = 0;
    dhParams.pSharedData     = nullptr;
    dhParams.ulPublicDataLen = bobRawPoint.size();
    dhParams.pPublicData     = bobRawPoint.data();

    CK_MECHANISM deriveMech = { CKM_ECDH1_DERIVE, &dhParams, sizeof(dhParams) };

    CK_OBJECT_CLASS secClass = CKO_SECRET_KEY;
    CK_KEY_TYPE secType      = CKK_GENERIC_SECRET;
    CK_ULONG secLen          = (curve == "P-521" || curve == "X448") ? 56 :
                               (curve == "P-384") ? 48 : 32;
    CK_ATTRIBUTE deriveTempl[] = {
        { CKA_CLASS,       &secClass, sizeof(secClass) },
        { CKA_KEY_TYPE,    &secType,  sizeof(secType) },
        { CKA_VALUE_LEN,   &secLen,   sizeof(secLen) },
        { CKA_EXTRACTABLE, &bTrue,    sizeof(bTrue) },
        { CKA_TOKEN,       &bFalse,   sizeof(bFalse) }
    };

    CK_OBJECT_HANDLE hAliceSecret = CK_INVALID_HANDLE;
    rv = ctx.p11->C_DeriveKey(ctx.session, &deriveMech, hAlicePriv,
                               deriveTempl, 5, &hAliceSecret);
    if (isSkipRv(rv)) {
        destroyObj(ctx, hAlicePub); destroyObj(ctx, hAlicePriv);
        destroyObj(ctx, hBobPub);   destroyObj(ctx, hBobPriv);
        res["status"]="SKIP"; res["reason"]=rvName(rv);
        ctx.log->skip(op["name"].get<std::string>()); return res;
    }
    if (rv != CKR_OK) {
        destroyObj(ctx, hAlicePub); destroyObj(ctx, hAlicePriv);
        destroyObj(ctx, hBobPub);   destroyObj(ctx, hBobPriv);
        res["status"]="FAIL"; res["error"]=rvName(rv); return res;
    }

    // Export Alice's point for Bob's derivation
    getPt.pValue = nullptr; getPt.ulValueLen = 0;
    ctx.p11->C_GetAttributeValue(ctx.session, hAlicePub, &getPt, 1);
    std::vector<uint8_t> aliceEcPoint(getPt.ulValueLen);
    getPt.pValue = aliceEcPoint.data();
    ctx.p11->C_GetAttributeValue(ctx.session, hAlicePub, &getPt, 1);
    std::vector<uint8_t> aliceRawPoint = stripEcPointWrapper(aliceEcPoint);

    dhParams.ulPublicDataLen = aliceRawPoint.size();
    dhParams.pPublicData     = aliceRawPoint.data();

    CK_OBJECT_HANDLE hBobSecret = CK_INVALID_HANDLE;
    rv = ctx.p11->C_DeriveKey(ctx.session, &deriveMech, hBobPriv,
                               deriveTempl, 5, &hBobSecret);

    std::vector<uint8_t> aliceVal = exportKeyValue(ctx, hAliceSecret);
    std::vector<uint8_t> bobVal   = exportKeyValue(ctx, hBobSecret);
    bool match = (rv == CKR_OK) && !aliceVal.empty() && (aliceVal == bobVal);

    destroyObj(ctx, hAlicePub); destroyObj(ctx, hAlicePriv);
    destroyObj(ctx, hBobPub);   destroyObj(ctx, hBobPriv);
    destroyObj(ctx, hAliceSecret); destroyObj(ctx, hBobSecret);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                  std::chrono::steady_clock::now() - t0).count();

    res["status"]      = match ? "PASS" : "FAIL";
    res["error"]       = match ? json(nullptr) : json(rv==CKR_OK ? "shared secrets differ" : rvName(rv));
    res["timestamp"]   = isoNow();
    res["duration_ms"] = (int)ms;
    res["inputs"]["curve"]  = curve;
    res["outputs"]["alice_secret_hex"] = toHex(aliceVal);
    res["outputs"]["bob_secret_hex"]   = toHex(bobVal);
    res["outputs"]["secrets_match"]    = match;

    if (match) ctx.log->pass(op["name"].get<std::string>());
    else       ctx.log->fail(op["name"].get<std::string>());
    ctx.log->verbose_hex("  shared secret", aliceVal);
    return res;
}

/* ── ML-KEM ──────────────────────────────────────────────────────────────*/
static json testMLKEM(Ctx& ctx, const json& op) {
    json res;
    if (!ctx.encapsulate || !ctx.decapsulate) {
        res["status"] = "SKIP";
        res["reason"] = "C_EncapsulateKey / C_DecapsulateKey not found in library";
        ctx.log->skip(op["name"].get<std::string>());
        return res;
    }

    CK_ULONG paramSet = std::stoul(
        op["params"]["parameter_set_id"].get<std::string>(), nullptr, 16);
    std::string psName = op["params"]["parameter_set"].get<std::string>();

    CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY, privClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE ktype = CKK_ML_KEM;
    CK_BBOOL bTrue = CK_TRUE, bFalse = CK_FALSE;

    CK_ATTRIBUTE pubTempl[] = {
        { CKA_CLASS,         &pubClass, sizeof(pubClass) },
        { CKA_KEY_TYPE,      &ktype,    sizeof(ktype) },
        { CKA_ENCAPSULATE,   &bTrue,    sizeof(bTrue) },
        { CKA_PARAMETER_SET, &paramSet, sizeof(paramSet) },
        { CKA_TOKEN,         &bFalse,   sizeof(bFalse) }
    };
    CK_ATTRIBUTE privTempl[] = {
        { CKA_CLASS,         &privClass, sizeof(privClass) },
        { CKA_KEY_TYPE,      &ktype,     sizeof(ktype) },
        { CKA_DECAPSULATE,   &bTrue,     sizeof(bTrue) },
        { CKA_PARAMETER_SET, &paramSet,  sizeof(paramSet) },
        { CKA_TOKEN,         &bFalse,    sizeof(bFalse) }
    };

    CK_MECHANISM kgMech   = { CKM_ML_KEM_KEY_PAIR_GEN, nullptr, 0 };
    CK_OBJECT_HANDLE hPub = CK_INVALID_HANDLE, hPriv = CK_INVALID_HANDLE;
    auto t0 = std::chrono::steady_clock::now();

    CK_RV rv = ctx.p11->C_GenerateKeyPair(ctx.session, &kgMech,
        pubTempl, 5, privTempl, 5, &hPub, &hPriv);
    if (isSkipRv(rv)) {
        res["status"]="SKIP"; res["reason"]=std::string(rvName(rv))+" — not yet implemented";
        ctx.log->skip(op["name"].get<std::string>()); return res;
    }
    if (rv != CKR_OK) { res["status"]="FAIL"; res["error"]=rvName(rv); return res; }

    // Encapsulate: generate ciphertext + encap shared secret key handle
    CK_MECHANISM kemMech = { CKM_ML_KEM, nullptr, 0 };

    CK_OBJECT_CLASS secClass = CKO_SECRET_KEY;
    CK_KEY_TYPE secType      = CKK_GENERIC_SECRET;
    CK_ULONG secLen          = 32;
    CK_ATTRIBUTE ssTempl[]   = {
        { CKA_CLASS,       &secClass, sizeof(secClass) },
        { CKA_KEY_TYPE,    &secType,  sizeof(secType) },
        { CKA_VALUE_LEN,   &secLen,   sizeof(secLen) },
        { CKA_EXTRACTABLE, &bTrue,    sizeof(bTrue) },
        { CKA_TOKEN,       &bFalse,   sizeof(bFalse) }
    };

    CK_ULONG ctLen = 0;
    CK_OBJECT_HANDLE hEncapSS = CK_INVALID_HANDLE;

    // First call: get ciphertext length
    rv = ctx.encapsulate(ctx.session, &kemMech, hPub,
                         ssTempl, 5, nullptr, &ctLen, &hEncapSS);
    if (isSkipRv(rv)) {
        destroyObj(ctx, hPub); destroyObj(ctx, hPriv);
        res["status"]="SKIP"; res["reason"]=std::string(rvName(rv))+" — not yet implemented";
        ctx.log->skip(op["name"].get<std::string>()); return res;
    }
    if (rv != CKR_OK && rv != CKR_BUFFER_TOO_SMALL) {
        destroyObj(ctx, hPub); destroyObj(ctx, hPriv);
        res["status"]="FAIL"; res["error"]=std::string("encap len query: ")+rvName(rv);
        return res;
    }

    std::vector<uint8_t> ciphertext(ctLen);
    rv = ctx.encapsulate(ctx.session, &kemMech, hPub,
                         ssTempl, 5, ciphertext.data(), &ctLen, &hEncapSS);
    if (rv != CKR_OK) {
        destroyObj(ctx, hPub); destroyObj(ctx, hPriv);
        res["status"]="FAIL"; res["error"]=std::string("encapsulate: ")+rvName(rv);
        return res;
    }
    ciphertext.resize(ctLen);

    // Decapsulate: recover shared secret from ciphertext
    CK_OBJECT_HANDLE hDecapSS = CK_INVALID_HANDLE;
    rv = ctx.decapsulate(ctx.session, &kemMech, hPriv,
                         ssTempl, 5,
                         ciphertext.data(), ciphertext.size(),
                         &hDecapSS);
    if (rv != CKR_OK) {
        destroyObj(ctx, hPub); destroyObj(ctx, hPriv); destroyObj(ctx, hEncapSS);
        res["status"]="FAIL"; res["error"]=std::string("decapsulate: ")+rvName(rv);
        return res;
    }

    std::vector<uint8_t> ssEncap = exportKeyValue(ctx, hEncapSS);
    std::vector<uint8_t> ssDecap = exportKeyValue(ctx, hDecapSS);
    bool match = !ssEncap.empty() && (ssEncap == ssDecap);

    // Negative test: tamper ciphertext → secrets should differ
    std::vector<uint8_t> tamperedCt = ciphertext;
    tamperedCt[0] ^= 0xff;
    CK_OBJECT_HANDLE hBadSS = CK_INVALID_HANDLE;
    ctx.decapsulate(ctx.session, &kemMech, hPriv,
                    ssTempl, 5, tamperedCt.data(), tamperedCt.size(), &hBadSS);
    std::vector<uint8_t> ssBad = exportKeyValue(ctx, hBadSS);
    bool tamperDiffers = (ssBad.empty() || ssBad != ssEncap);

    destroyObj(ctx, hPub); destroyObj(ctx, hPriv);
    destroyObj(ctx, hEncapSS); destroyObj(ctx, hDecapSS); destroyObj(ctx, hBadSS);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                  std::chrono::steady_clock::now() - t0).count();

    bool pass = match && tamperDiffers;
    res["status"]      = pass ? "PASS" : "FAIL";
    res["error"]       = pass ? json(nullptr) : json(!match ? "shared secrets differ" : "tamper not detected");
    res["timestamp"]   = isoNow();
    res["duration_ms"] = (int)ms;
    res["inputs"]["parameter_set"]       = psName;
    res["inputs"]["parameter_set_id"]    = op["params"]["parameter_set_id"];
    res["outputs"]["ciphertext_hex"]     = toHex(ciphertext);
    res["outputs"]["ciphertext_len"]     = (int)ctLen;
    res["outputs"]["shared_secret_encap_hex"] = toHex(ssEncap);
    res["outputs"]["shared_secret_decap_hex"] = toHex(ssDecap);
    res["outputs"]["secrets_match"]      = match;
    res["outputs"]["negative_tamper_ok"] = tamperDiffers;

    if (pass) ctx.log->pass(op["name"].get<std::string>());
    else      ctx.log->fail(op["name"].get<std::string>());
    ctx.log->verbose_hex("  shared secret", ssEncap);
    return res;
}

/* ── ML-DSA / SLH-DSA ────────────────────────────────────────────────────*/
static json testPQCSign(Ctx& ctx, const json& op) {
    json res;
    CK_ULONG mechId   = std::stoul(op["mechanism_id"].get<std::string>(), nullptr, 16);
    CK_ULONG kgMechId = (mechId == CKM_ML_DSA) ? CKM_ML_DSA_KEY_PAIR_GEN : CKM_SLH_DSA_KEY_PAIR_GEN;
    CK_KEY_TYPE ktype = (mechId == CKM_ML_DSA) ? CKK_ML_DSA : CKK_SLH_DSA;
    CK_ULONG paramSet = std::stoul(
        op["params"]["parameter_set_id"].get<std::string>(), nullptr, 16);
    std::vector<uint8_t> msg = fromHex(op["params"]["message_hex"].get<std::string>());

    CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY, privClass = CKO_PRIVATE_KEY;
    CK_BBOOL bTrue = CK_TRUE, bFalse = CK_FALSE;

    CK_ATTRIBUTE pubTempl[] = {
        { CKA_CLASS,         &pubClass, sizeof(pubClass) },
        { CKA_KEY_TYPE,      &ktype,    sizeof(ktype) },
        { CKA_VERIFY,        &bTrue,    sizeof(bTrue) },
        { CKA_PARAMETER_SET, &paramSet, sizeof(paramSet) },
        { CKA_TOKEN,         &bFalse,   sizeof(bFalse) }
    };
    CK_ATTRIBUTE privTempl[] = {
        { CKA_CLASS,         &privClass, sizeof(privClass) },
        { CKA_KEY_TYPE,      &ktype,     sizeof(ktype) },
        { CKA_SIGN,          &bTrue,     sizeof(bTrue) },
        { CKA_PARAMETER_SET, &paramSet,  sizeof(paramSet) },
        { CKA_TOKEN,         &bFalse,    sizeof(bFalse) }
    };

    CK_MECHANISM kgMech   = { kgMechId, nullptr, 0 };
    CK_OBJECT_HANDLE hPub = CK_INVALID_HANDLE, hPriv = CK_INVALID_HANDLE;
    auto t0 = std::chrono::steady_clock::now();

    CK_RV rv = ctx.p11->C_GenerateKeyPair(ctx.session, &kgMech,
        pubTempl, 5, privTempl, 5, &hPub, &hPriv);
    if (isSkipRv(rv)) {
        res["status"]="SKIP";
        res["reason"]=std::string(rvName(rv))+" — not yet implemented";
        ctx.log->skip(op["name"].get<std::string>()); return res;
    }
    if (rv != CKR_OK) { res["status"]="FAIL"; res["error"]=rvName(rv); return res; }

    CK_MECHANISM mech = { mechId, nullptr, 0 };
    rv = ctx.p11->C_SignInit(ctx.session, &mech, hPriv);
    if (isSkipRv(rv)) {
        destroyObj(ctx, hPub); destroyObj(ctx, hPriv);
        res["status"]="SKIP"; res["reason"]=rvName(rv);
        ctx.log->skip(op["name"].get<std::string>()); return res;
    }
    if (rv != CKR_OK) {
        destroyObj(ctx, hPub); destroyObj(ctx, hPriv);
        res["status"]="FAIL"; res["error"]=rvName(rv); return res;
    }

    CK_ULONG sigLen = 0;
    ctx.p11->C_Sign(ctx.session, msg.data(), msg.size(), nullptr, &sigLen);
    std::vector<uint8_t> sig(sigLen);
    rv = ctx.p11->C_Sign(ctx.session, msg.data(), msg.size(), sig.data(), &sigLen);
    sig.resize(sigLen);
    if (rv != CKR_OK) {
        destroyObj(ctx, hPub); destroyObj(ctx, hPriv);
        res["status"]="FAIL"; res["error"]=rvName(rv); return res;
    }

    ctx.p11->C_VerifyInit(ctx.session, &mech, hPub);
    bool verifyOk = (ctx.p11->C_Verify(ctx.session, msg.data(), msg.size(), sig.data(), sig.size()) == CKR_OK);

    std::vector<uint8_t> badSig = sig;
    badSig[0] ^= 0xff;
    ctx.p11->C_VerifyInit(ctx.session, &mech, hPub);
    bool tamperDetected = (ctx.p11->C_Verify(ctx.session, msg.data(), msg.size(), badSig.data(), badSig.size()) != CKR_OK);

    destroyObj(ctx, hPub); destroyObj(ctx, hPriv);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                  std::chrono::steady_clock::now() - t0).count();

    bool pass = verifyOk && tamperDetected;
    res["status"]      = pass ? "PASS" : "FAIL";
    res["error"]       = pass ? json(nullptr) : json(!verifyOk ? "verify failed" : "tamper not detected");
    res["timestamp"]   = isoNow();
    res["duration_ms"] = (int)ms;
    res["inputs"]["parameter_set"] = op["params"]["parameter_set"];
    res["outputs"]["sig_len"]            = (int)sigLen;
    res["outputs"]["verify_ok"]          = verifyOk;
    res["outputs"]["negative_tamper_ok"] = tamperDetected;

    if (pass) ctx.log->pass(op["name"].get<std::string>());
    else      ctx.log->fail(op["name"].get<std::string>());
    return res;
}

/* ═════════════════════════════════════════════════════════════════════════
 *  AES dispatcher
 * ═════════════════════════════════════════════════════════════════════════ */
static json testAES(Ctx& ctx, const json& op) {
    std::string mechName = op.contains("mechanism") && !op["mechanism"].is_null()
        ? op["mechanism"].get<std::string>() : "";
    if (mechName == "CKM_AES_ECB")     return testAES_ECB_CBC(ctx, op, CKM_AES_ECB);
    if (mechName == "CKM_AES_CBC")     return testAES_ECB_CBC(ctx, op, CKM_AES_CBC);
    if (mechName == "CKM_AES_CBC_PAD") return testAES_CBC_PAD(ctx, op);
    if (mechName == "CKM_AES_CTR")     return testAES_CTR(ctx, op);
    if (mechName == "CKM_AES_GCM")     return testAES_GCM(ctx, op);
    if (mechName == "CKM_AES_CMAC")    return testAES_CMAC(ctx, op);
    if (mechName == "CKM_AES_KEY_WRAP")return testAES_KeyWrap(ctx, op);
    json res; res["status"]="FAIL"; res["error"]="unknown AES mechanism: "+mechName;
    return res;
}

/* ═════════════════════════════════════════════════════════════════════════
 *  Main operation dispatcher
 * ═════════════════════════════════════════════════════════════════════════ */
static json dispatchOp(Ctx& ctx, const json& op) {
    std::string cat = op["category"].get<std::string>();
    ctx.log->section(op["id"].get<std::string>() + " — " + op["name"].get<std::string>());

    json result;
    try {
        if      (cat == "RNG")         result = testRNG(ctx, op);
        else if (cat == "Hash")        result = testHash(ctx, op);
        else if (cat == "HMAC")        result = testHMAC(ctx, op);
        else if (cat == "AES")         result = testAES(ctx, op);
        else if (cat == "RSA-Sign")    result = testRSASign(ctx, op);
        else if (cat == "RSA-Encrypt") result = testRSAEncrypt(ctx, op);
        else if (cat == "ECDSA")       result = testECDSA(ctx, op);
        else if (cat == "EdDSA")       result = testEdDSA(ctx, op);
        else if (cat == "ECDH")        result = testECDH(ctx, op);
        else if (cat == "XDH")         result = testECDH(ctx, op);
        else if (cat == "ML-KEM")      result = testMLKEM(ctx, op);
        else if (cat == "ML-DSA")      result = testPQCSign(ctx, op);
        else if (cat == "SLH-DSA")     result = testPQCSign(ctx, op);
        else {
            result["status"] = "SKIP";
            result["reason"] = "unknown category: " + cat;
            ctx.log->skip("unknown category: " + cat);
        }
    } catch (const std::exception& e) {
        result["status"] = "FAIL";
        result["error"]  = std::string("exception: ") + e.what();
        ctx.log->fail(std::string("exception in ") + op["id"].get<std::string>() + ": " + e.what());
    }

    std::string status = result.value("status", "FAIL");
    if      (status == "PASS") ++ctx.passed;
    else if (status == "SKIP") ++ctx.skipped;
    else                       ++ctx.failed;

    return result;
}

/* ═════════════════════════════════════════════════════════════════════════
 *  main()
 * ═════════════════════════════════════════════════════════════════════════ */
int main(int argc, char** argv) {
    // ── Parse arguments ──────────────────────────────────────────────────
    std::string libPath;
    std::string soPin      = "1234";
    std::string userPin    = "5678";
    std::string opsFile    = "tests/pqc_validate_ops.json";
    std::string outputDir  = ".";
    bool        verbose    = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if      (arg == "--so-pin"    && i+1 < argc) soPin      = argv[++i];
        else if (arg == "--user-pin"  && i+1 < argc) userPin    = argv[++i];
        else if (arg == "--ops-file"  && i+1 < argc) opsFile    = argv[++i];
        else if (arg == "--output-dir"&& i+1 < argc) outputDir  = argv[++i];
        else if (arg == "--verbose")                 verbose    = true;
        else if (arg[0] != '-')                      libPath    = arg;
    }

    if (libPath.empty()) {
        std::cerr << "Usage: pqc_validate <library.so> [--so-pin PIN] [--user-pin PIN]\n"
                  << "                                  [--ops-file path] [--output-dir path]\n"
                  << "                                  [--verbose]\n";
        return 2;
    }

    Logger log(verbose);
    Ctx ctx;
    ctx.verbose = verbose;
    ctx.log     = &log;

    // ── Determine output path ─────────────────────────────────────────────
    std::string outPath = determineOutputPath(outputDir);
    std::cout << "\033[1;35m╔══ SoftHSMv3 PKCS#11 v3.2 Algorithm Validator ══╗\033[0m\n";
    std::cout << "  Library:    " << libPath   << "\n";
    std::cout << "  Ops file:   " << opsFile   << "\n";
    std::cout << "  Output:     " << outPath   << "\n";
    std::cout << "  Started:    " << isoNow()  << "\n\n";

    // ── Load ops template ─────────────────────────────────────────────────
    json opsTemplate;
    {
        std::ifstream f(opsFile);
        if (!f) {
            std::cerr << "ERROR: cannot open ops file: " << opsFile << "\n";
            return 2;
        }
        opsTemplate = json::parse(f);
    }

    // ── dlopen library ────────────────────────────────────────────────────
    void* lib = dlopen(libPath.c_str(), RTLD_NOW | RTLD_LOCAL);
    if (!lib) {
        std::cerr << "ERROR: dlopen failed: " << dlerror() << "\n";
        return 1;
    }

    // C_GetFunctionList
    typedef CK_RV (*FnGetFunctionList)(CK_FUNCTION_LIST_PTR_PTR);
    auto getFnList = reinterpret_cast<FnGetFunctionList>(
        dlsym(lib, "C_GetFunctionList"));
    if (!getFnList) {
        std::cerr << "ERROR: C_GetFunctionList not found\n";
        dlclose(lib); return 1;
    }
    if (getFnList(&ctx.p11) != CKR_OK || !ctx.p11) {
        std::cerr << "ERROR: C_GetFunctionList returned error\n";
        dlclose(lib); return 1;
    }

    // V3.2 KEM functions via dlsym
    ctx.encapsulate = reinterpret_cast<FnEncapsulate>(dlsym(lib, "C_EncapsulateKey"));
    ctx.decapsulate = reinterpret_cast<FnDecapsulate>(dlsym(lib, "C_DecapsulateKey"));
    if (ctx.encapsulate) log.info("C_EncapsulateKey found in library");
    else                 log.warn("C_EncapsulateKey NOT found — ML-KEM tests will SKIP");
    if (ctx.decapsulate) log.info("C_DecapsulateKey found in library");
    else                 log.warn("C_DecapsulateKey NOT found — ML-KEM tests will SKIP");

    // ── C_Initialize ──────────────────────────────────────────────────────
    CK_C_INITIALIZE_ARGS initArgs = {};
    initArgs.flags = CKF_OS_LOCKING_OK;
    CK_RV rv = ctx.p11->C_Initialize(&initArgs);
    if (rv != CKR_OK) {
        std::cerr << "ERROR: C_Initialize: " << rvName(rv) << "\n";
        dlclose(lib); return 1;
    }

    // ── Token setup ───────────────────────────────────────────────────────
    if (!initToken(ctx, soPin, userPin)) {
        std::cerr << "ERROR: token initialization failed\n";
        ctx.p11->C_Finalize(nullptr); dlclose(lib); return 1;
    }

    // ── Open session and log in ───────────────────────────────────────────
    rv = ctx.p11->C_OpenSession(ctx.slot,
        CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr, &ctx.session);
    if (rv != CKR_OK) {
        std::cerr << "ERROR: C_OpenSession: " << rvName(rv) << "\n";
        ctx.p11->C_Finalize(nullptr); dlclose(lib); return 1;
    }

    rv = ctx.p11->C_Login(ctx.session, CKU_USER,
        reinterpret_cast<CK_UTF8CHAR_PTR>(const_cast<char*>(userPin.c_str())),
        userPin.size());
    if (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN) {
        std::cerr << "ERROR: C_Login: " << rvName(rv) << "\n";
        ctx.p11->C_CloseSession(ctx.session);
        ctx.p11->C_Finalize(nullptr); dlclose(lib); return 1;
    }

    log.info("Session open, user logged in (slot " + std::to_string(ctx.slot) + ")");

    // ── Run operations ────────────────────────────────────────────────────
    std::string runStarted = isoNow();
    json runOps = opsTemplate["operations"];
    for (auto& op : runOps) {
        json result = dispatchOp(ctx, op);
        op["result"] = result;
    }
    std::string runCompleted = isoNow();

    // ── Logout / cleanup ──────────────────────────────────────────────────
    ctx.p11->C_Logout(ctx.session);
    ctx.p11->C_CloseSession(ctx.session);
    ctx.p11->C_Finalize(nullptr);
    dlclose(lib);

    // ── Build output JSON ─────────────────────────────────────────────────
    // Derive run_id from output path filename
    fs::path op(outPath);
    std::string runId = op.stem().string();  // e.g. pqc_validate_03022026_r1

    json output;
    output["schema_version"]  = opsTemplate["schema_version"];
    output["description"]     = opsTemplate["description"];
    output["openssl_scope"]   = opsTemplate["openssl_scope"];
    output["run_metadata"] = {
        { "run_id",        runId },
        { "started_at",    runStarted },
        { "completed_at",  runCompleted },
        { "library_path",  libPath },
        { "ops_file",      opsFile },
        { "token_slot",    (int)ctx.slot },
        { "summary", {
            { "total",   ctx.passed + ctx.failed + ctx.skipped },
            { "passed",  ctx.passed },
            { "failed",  ctx.failed },
            { "skipped", ctx.skipped }
        }}
    };
    output["operations"] = runOps;

    // ── Write JSON result file ────────────────────────────────────────────
    {
        std::ofstream f(outPath);
        if (!f) {
            std::cerr << "ERROR: cannot write output: " << outPath << "\n";
        } else {
            f << output.dump(2) << "\n";
            log.info("Results written to: " + outPath);
        }
    }

    // ── Summary table ─────────────────────────────────────────────────────
    int total = ctx.passed + ctx.failed + ctx.skipped;
    std::cout << "\n\033[1;35m╔══ Summary ══╗\033[0m\n";
    std::cout << "  Total:   " << total       << "\n";
    std::cout << "  \033[1;32mPassed:  " << ctx.passed  << "\033[0m\n";
    std::cout << "  \033[1;31mFailed:  " << ctx.failed  << "\033[0m\n";
    std::cout << "  \033[0;33mSkipped: " << ctx.skipped << "\033[0m\n";
    std::cout << "  Output:  " << outPath << "\n\n";

    return (ctx.failed > 0) ? 1 : 0;
}
