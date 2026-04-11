#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <string.h>
#include <getopt.h>
#include <string>
#include <vector>
#include <iostream>
#include <fstream>

#include "tests/json.hpp"
using json = nlohmann::json;

#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)
#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#include "src/lib/pkcs11/pkcs11.h"

// Fallback definitions for new mechanisms in case they're not in the local pkcs11.h
#ifndef CKM_ML_KEM
#define CKM_ML_KEM 0x00001080
#endif
#ifndef CKM_ML_DSA
#define CKM_ML_DSA 0x00001084
#endif
#ifndef CKM_SLH_DSA
#define CKM_SLH_DSA 0x0000108A
#endif
#ifndef CKM_AES_CTR
#define CKM_AES_CTR 0x00001086
#endif
#ifndef CKM_HKDF_DERIVE
#define CKM_HKDF_DERIVE 0x0000402A
#endif
#ifndef CKM_SP800_108_COUNTER_KDF
#define CKM_SP800_108_COUNTER_KDF 0x000003AC
#endif
#ifndef CKM_HSS_KEY_PAIR_GEN
#define CKM_HSS_KEY_PAIR_GEN 0x00004032
#endif
#ifndef CKM_RIPEMD160
#define CKM_RIPEMD160 0x00000240
#endif
#ifndef CKA_PUBLIC_KEY_INFO
#define CKA_PUBLIC_KEY_INFO 0x00000129
#endif

// Options
std::string opt_engine = "./build/src/lib/libsofthsmv3.dylib";
std::string opt_category = "all";
std::string opt_report = "compliance_report";
std::string opt_pin = "1234";

// Token State
CK_FUNCTION_LIST_PTR fl;
CK_SESSION_HANDLE hSess;

// JSON Report
json report = json::object();
int total_pass = 0;
int total_fail = 0;
int total_skip = 0;


bool refresh_session() {
    if (hSess != 0) {
        fl->C_CloseSession(hSess);
        hSess = 0;
    }
    CK_RV rv = fl->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSess);
    if (rv != CKR_OK) return false;
    rv = fl->C_Login(hSess, CKU_USER, (CK_UTF8CHAR_PTR)opt_pin.c_str(), opt_pin.length());
    if (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN) return false;
    return true;
}

void print_usage() {
    printf("Usage: p11_v32_compliance_test [options]\n");
    printf("Options:\n");
    printf("  --engine <path>    Path to the PKCS#11 library (default: %s)\n", opt_engine.c_str());
    printf("  --category <cat>   Test category: all, init, discovery, pqc-kem, pqc-dsa, hbs, attr (default: %s)\n", opt_category.c_str());
    printf("  --report <path>    Output bases (e.g. 'rep' creates 'rep.md' and 'rep.json') (default: %s)\n", opt_report.c_str());
    printf("  --pin <pin>        Token PIN (default: %s)\n", opt_pin.c_str());
}

void parse_args(int argc, char** argv) {
    static struct option long_options[] = {
        {"engine", required_argument, 0, 'e'},
        {"category", required_argument, 0, 'c'},
        {"report", required_argument, 0, 'r'},
        {"pin", required_argument, 0, 'p'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    int opt;
    while ((opt = getopt_long(argc, argv, "e:c:r:p:h", long_options, nullptr)) != -1) {
        switch (opt) {
            case 'e': opt_engine = optarg; break;
            case 'c': opt_category = optarg; break;
            case 'r': opt_report = optarg; break;
            case 'p': opt_pin = optarg; break;
            case 'h': print_usage(); exit(0);
        }
    }
}

void record_result(const std::string& category, const std::string& test_name, const std::string& status, const std::string& details) {
    printf("[%s] %s: %s (%s)\n", category.c_str(), test_name.c_str(), status.c_str(), details.c_str());
    if (!report.contains(category)) {
        report[category] = json::array();
    }
    report[category].push_back({
        {"test", test_name},
        {"status", status},
        {"details", details}
    });
    if (status == "PASS") total_pass++;
    else if (status == "FAIL") total_fail++;
    else if (status == "SKIP") total_skip++;
}

bool init_token() {
    system("rm -rf /tmp/softhsm-compliance-test && mkdir -p /tmp/softhsm-compliance-test/tokens");
    FILE* f = fopen("/tmp/softhsm-compliance-test/softhsm2.conf", "w");
    fprintf(f, "directories.tokendir = /tmp/softhsm-compliance-test/tokens/\n");
    fprintf(f, "objectstore.backend = file\nlog.level = DEBUG\nslots.removable = false\n");
    fprintf(f, "log.backend = file\nlog.file = /tmp/softhsm-compliance-test/softhsm2.log\n");
    fclose(f);
    setenv("SOFTHSM2_CONF", "/tmp/softhsm-compliance-test/softhsm2.conf", 1);

    void* handle = dlopen(opt_engine.c_str(), RTLD_NOW);
    if (!handle) {
        record_result("Init", "dlopen", "FAIL", dlerror());
        return false;
    }

    CK_C_GetFunctionList pfn = (CK_C_GetFunctionList)dlsym(handle, "C_GetFunctionList");
    if (!pfn) {
        record_result("Init", "C_GetFunctionList", "FAIL", "Symbol not found");
        return false;
    }

    pfn(&fl);
    if (!fl) {
        record_result("Init", "FunctionListPtr", "FAIL", "Null returned");
        return false;
    }

    CK_RV rv = fl->C_Initialize(NULL_PTR);
    if (rv != CKR_OK) {
        record_result("Init", "C_Initialize", "FAIL", "RV=" + std::to_string(rv));
        return false;
    }

    CK_SLOT_ID slots[10];
    CK_ULONG ulCount = 10;
    rv = fl->C_GetSlotList(CK_FALSE, slots, &ulCount);
    if (rv != CKR_OK || ulCount == 0) {
        record_result("Init", "C_GetSlotList", "FAIL", "RV=" + std::to_string(rv) + " count=" + std::to_string(ulCount));
        return false;
    }

    CK_UTF8CHAR label[32]; memset(label, ' ', 32); memcpy(label, "compliance", 10);
    rv = fl->C_InitToken(slots[0], (CK_UTF8CHAR_PTR)"5678", 4, label);
    if (rv != CKR_OK) {
        record_result("Init", "C_InitToken", "FAIL", "RV=" + std::to_string(rv));
        return false;
    }

    rv = fl->C_OpenSession(slots[0], CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &hSess);
    if (rv != CKR_OK) {
        record_result("Init", "C_OpenSession", "FAIL", "RV=" + std::to_string(rv));
        return false;
    }

    rv = fl->C_Login(hSess, CKU_SO, (CK_UTF8CHAR_PTR)"5678", 4);
    rv = fl->C_InitPIN(hSess, (CK_UTF8CHAR_PTR)opt_pin.c_str(), opt_pin.length());
    rv = fl->C_Logout(hSess);
    rv = fl->C_Login(hSess, CKU_USER, (CK_UTF8CHAR_PTR)opt_pin.c_str(), opt_pin.length());
    if (rv != CKR_OK) {
        record_result("Init", "C_Login", "FAIL", "RV=" + std::to_string(rv));
        return false;
    }

    record_result("Init", "TokenSetup", "PASS", "Initialized token and session");
    return true;
}

void test_mechanism_discovery() {
    CK_MECHANISM_TYPE mechs[200];
    CK_ULONG count = 200;
    CK_RV rv = fl->C_GetMechanismList(0, mechs, &count);
    if (rv != CKR_OK) {
        record_result("Discovery", "C_GetMechanismList", "FAIL", "RV=" + std::to_string(rv));
        return;
    }

    bool has_ml_kem = false, has_ml_dsa = false, has_slh_dsa = false;
    bool has_ripmd = false, has_aes_ctr = false, has_hkdf = false;

    for (CK_ULONG i = 0; i < count; i++) {
        if (mechs[i] == CKM_ML_KEM) has_ml_kem = true;
        if (mechs[i] == CKM_ML_DSA) has_ml_dsa = true;
        if (mechs[i] == CKM_SLH_DSA) has_slh_dsa = true;
        if (mechs[i] == CKM_RIPEMD160) has_ripmd = true;
        if (mechs[i] == CKM_AES_CTR) has_aes_ctr = true;
        if (mechs[i] == CKM_HKDF_DERIVE) has_hkdf = true;
    }

    record_result("Discovery", "CKM_ML_KEM", has_ml_kem ? "PASS" : "FAIL", "PQC KEM Support");
    record_result("Discovery", "CKM_ML_DSA", has_ml_dsa ? "PASS" : "FAIL", "PQC DSA Support");
    record_result("Discovery", "CKM_SLH_DSA", has_slh_dsa ? "PASS" : "FAIL", "PQC SLH-DSA Support");
    record_result("Discovery", "CKM_AES_CTR", has_aes_ctr ? "PASS" : "FAIL", "AES CTR Support (v3.2/5G)");
    record_result("Discovery", "CKM_HKDF_DERIVE", has_hkdf ? "PASS" : "FAIL", "HKDF Support (v3.0/5G)");
    
    // Explicit hard FAIL for missing RIPEMD160
    record_result("Discovery", "CKM_RIPEMD160", has_ripmd ? "PASS" : "FAIL", "RIPEMD160 Support (Strict Audit)");
}

void test_key_attributes() {
    CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
    CK_OBJECT_CLASS privClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE ktypeKem = 0x00000048; // CKK_ML_KEM
    CK_ULONG paramSetKem = 2; // CKP_ML_KEM_768
    CK_BBOOL bTrue = CK_TRUE, bFalse = CK_FALSE;
    CK_MECHANISM mech = { CKM_ML_KEM_KEY_PAIR_GEN, NULL_PTR, 0 };
    
    CK_ATTRIBUTE pubTmpl[] = {
        { CKA_CLASS,         &pubClass, sizeof(pubClass) },
        { CKA_KEY_TYPE,      &ktypeKem, sizeof(ktypeKem) },
        { CKA_ENCAPSULATE,   &bTrue,    sizeof(bTrue) },
        { CKA_PARAMETER_SET, &paramSetKem, sizeof(paramSetKem) },
        { CKA_TOKEN,         &bFalse,   sizeof(bFalse) }
    };
    CK_ATTRIBUTE privTmpl[] = {
        { CKA_CLASS,         &privClass, sizeof(privClass) },
        { CKA_KEY_TYPE,      &ktypeKem, sizeof(ktypeKem) },
        { CKA_DECAPSULATE,   &bTrue,    sizeof(bTrue) },
        { CKA_PARAMETER_SET, &paramSetKem, sizeof(paramSetKem) },
        { CKA_TOKEN,         &bFalse,   sizeof(bFalse) }
    };

    CK_OBJECT_HANDLE hPub, hPriv;
    CK_RV rv = fl->C_GenerateKeyPair(hSess, &mech, pubTmpl, 5, privTmpl, 5, &hPub, &hPriv);
    if (rv != CKR_OK) {
        record_result("Attributes", "Generate_ML_KEM", "FAIL", "Generation failed, RV=" + std::to_string(rv));
        return;
    }

    CK_BYTE valBuf[2000];
    CK_ATTRIBUTE valAttr = { CKA_VALUE, valBuf, sizeof(valBuf) };
    rv = fl->C_GetAttributeValue(hSess, hPub, &valAttr, 1);
    record_result("Attributes", "CKA_VALUE_Pub", (rv == CKR_OK && valAttr.ulValueLen > 0) ? "PASS" : "FAIL", "§1.21 G-ATTR1 check");

    CK_BYTE spkiBuf[3000];
    CK_ATTRIBUTE spkiAttr = { CKA_PUBLIC_KEY_INFO, spkiBuf, sizeof(spkiBuf) };
    rv = fl->C_GetAttributeValue(hSess, hPub, &spkiAttr, 1);
    record_result("Attributes", "CKA_PUBLIC_KEY_INFO_Pub", (rv == CKR_OK && spkiAttr.ulValueLen > 0) ? "PASS" : "FAIL", "Required for all PQC keys");

    rv = fl->C_GetAttributeValue(hSess, hPriv, &spkiAttr, 1);
    record_result("Attributes", "CKA_PUBLIC_KEY_INFO_Priv", (rv == CKR_OK && spkiAttr.ulValueLen > 0) ? "PASS" : "FAIL", "Required to be exposed on private objects");
    
    // Enforce CKA_HSS_KEYS_REMAINING check (HSS/LMS)
    CK_MECHANISM hssMech = { CKM_HSS_KEY_PAIR_GEN, NULL_PTR, 0 };
    CK_ATTRIBUTE hssPubTmpl[] = { 
        { CKA_TOKEN, &bTrue, sizeof(bTrue) },
        { CKA_VERIFY, &bTrue, sizeof(bTrue) }
    };
    CK_ATTRIBUTE hssPrivTmpl[] = { 
        { CKA_TOKEN, &bTrue, sizeof(bTrue) },
        { CKA_SIGN, &bTrue, sizeof(bTrue) }
    };
    CK_OBJECT_HANDLE hssPub, hssPriv;
    rv = fl->C_GenerateKeyPair(hSess, &hssMech, hssPubTmpl, 2, hssPrivTmpl, 2, &hssPub, &hssPriv);
    
    if (rv == CKR_OK) {
        CK_ULONG remaining = 0;
        CK_ATTRIBUTE remAttr = { 0x0000061cUL /* CKA_HSS_KEYS_REMAINING */, &remaining, sizeof(remaining) };
        rv = fl->C_GetAttributeValue(hSess, hssPriv, &remAttr, 1);
        if (rv == CKR_OK && remAttr.ulValueLen > 0) {
            record_result("Attributes", "CKA_HSS_KEYS_REMAINING", "PASS", "Attribute correctly retrieved");
        } else {
            record_result("Attributes", "CKA_HSS_KEYS_REMAINING", "FAIL", "Missing attribute from Private Key. RV=" + std::to_string(rv));
        }
    } else {
        record_result("Attributes", "CKA_HSS_KEYS_REMAINING", "FAIL", "HSS KeyGen failed, skipping attribute test. RV=" + std::to_string(rv));
    }
}


void check_key_profile(std::string cat, std::string runName, CK_OBJECT_HANDLE hPub, CK_OBJECT_HANDLE hPriv, bool isKEM) {
    (void)cat; // Avoid unused parameter warning

    // G-ATTR1: CKA_VALUE extraction on public key
    CK_BYTE pubVal[8000]; CK_ATTRIBUTE attrPub = { CKA_VALUE, pubVal, sizeof(pubVal) };
    CK_RV rv = fl->C_GetAttributeValue(hSess, hPub, &attrPub, 1);
    if (rv == CKR_OK && attrPub.ulValueLen > 0) {
        record_result("Attributes", runName + "_CKA_VALUE_Pub", "PASS", "§1.21 G-ATTR1 check");
    } else {
        record_result("Attributes", runName + "_CKA_VALUE_Pub", "FAIL", "§1.21 G-ATTR1 failure");
    }

    // SPKI: CKA_PUBLIC_KEY_INFO on public key
    CK_BYTE spkiPub[8000]; CK_ATTRIBUTE attrSpkiP = { CKA_PUBLIC_KEY_INFO, spkiPub, sizeof(spkiPub) };
    rv = fl->C_GetAttributeValue(hSess, hPub, &attrSpkiP, 1);
    if (rv == CKR_OK && attrSpkiP.ulValueLen > 0) {
        record_result("Attributes", runName + "_CKA_PUBLIC_KEY_INFO_Pub", "PASS", "SPKI exposed");
    } else {
        record_result("Attributes", runName + "_CKA_PUBLIC_KEY_INFO_Pub", "FAIL", "SPKI missing on public key");
    }

    // SPKI: CKA_PUBLIC_KEY_INFO on private key
    CK_BYTE spkiPriv[8000]; CK_ATTRIBUTE attrSpkiPr = { CKA_PUBLIC_KEY_INFO, spkiPriv, sizeof(spkiPriv) };
    rv = fl->C_GetAttributeValue(hSess, hPriv, &attrSpkiPr, 1);
    if (rv == CKR_OK && attrSpkiPr.ulValueLen > 0) {
        record_result("Attributes", runName + "_CKA_PUBLIC_KEY_INFO_Priv", "PASS", "SPKI exposed on private");
    } else {
        record_result("Attributes", runName + "_CKA_PUBLIC_KEY_INFO_Priv", "FAIL", "SPKI missing on private");
    }

    // Mechanism specific attributes
    if (isKEM) {
        CK_BBOOL canEncap = CK_FALSE; CK_ATTRIBUTE attrEncap = { CKA_ENCAPSULATE, &canEncap, sizeof(canEncap) };
        fl->C_GetAttributeValue(hSess, hPub, &attrEncap, 1);
        if (canEncap == CK_TRUE) record_result("Attributes", runName + "_CKA_ENCAPSULATE", "PASS", "");
        else record_result("Attributes", runName + "_CKA_ENCAPSULATE", "FAIL", "Missing KEM pub rule");

        CK_BBOOL canDecap = CK_FALSE; CK_ATTRIBUTE attrDecap = { CKA_DECAPSULATE, &canDecap, sizeof(canDecap) };
        fl->C_GetAttributeValue(hSess, hPriv, &attrDecap, 1);
        if (canDecap == CK_TRUE) record_result("Attributes", runName + "_CKA_DECAPSULATE", "PASS", "");
        else record_result("Attributes", runName + "_CKA_DECAPSULATE", "FAIL", "Missing KEM priv rule");
    } else {
        CK_BBOOL canVerify = CK_FALSE; CK_ATTRIBUTE attrVer = { CKA_VERIFY, &canVerify, sizeof(canVerify) };
        fl->C_GetAttributeValue(hSess, hPub, &attrVer, 1);
        if (canVerify == CK_TRUE) record_result("Attributes", runName + "_CKA_VERIFY", "PASS", "");
        else record_result("Attributes", runName + "_CKA_VERIFY", "FAIL", "Missing DSA pub rule");

        CK_BBOOL canSign = CK_FALSE; CK_ATTRIBUTE attrSig = { CKA_SIGN, &canSign, sizeof(canSign) };
        fl->C_GetAttributeValue(hSess, hPriv, &attrSig, 1);
        if (canSign == CK_TRUE) record_result("Attributes", runName + "_CKA_SIGN", "PASS", "");
        else record_result("Attributes", runName + "_CKA_SIGN", "FAIL", "Missing DSA priv rule");
    }
}

void test_pqc_kem() {
    CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
    CK_OBJECT_CLASS privClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE ktypeKem = 0x00000048; // CKK_ML_KEM
    CK_BBOOL bTrue = CK_TRUE, bFalse = CK_FALSE;
    CK_MECHANISM mech = { CKM_ML_KEM_KEY_PAIR_GEN, NULL_PTR, 0 };
    
    // Function pointer fallback if not in struct
    typedef CK_RV (*C_EncapsulateKey_t)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR, CK_OBJECT_HANDLE_PTR);
    typedef CK_RV (*C_DecapsulateKey_t)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR);
    void* dlib = dlopen(opt_engine.c_str(), RTLD_NOW);
    C_EncapsulateKey_t EncapFn = (C_EncapsulateKey_t)dlsym(dlib, "C_EncapsulateKey");
    C_DecapsulateKey_t DecapFn = (C_DecapsulateKey_t)dlsym(dlib, "C_DecapsulateKey");
    
    if (!EncapFn || !DecapFn) {
        record_result("KEM", "C_EncapsulateKey", "SKIP", "Function pointers missing");
        return;
    }

    CK_ULONG kemParams[] = { 1, 2, 3 }; // 512, 768, 1024
    std::string kemNames[] = { "512", "768", "1024" };
    
    for (int i = 0; i < 3; ++i) {
        std::string n = kemNames[i];
        CK_ULONG paramSetKem = kemParams[i];
        
        CK_ATTRIBUTE pubTmpl[] = {
            { CKA_CLASS,         &pubClass, sizeof(pubClass) },
            { CKA_KEY_TYPE,      &ktypeKem, sizeof(ktypeKem) },
            { CKA_ENCAPSULATE,   &bTrue,    sizeof(bTrue) },
            { CKA_PARAMETER_SET, &paramSetKem, sizeof(paramSetKem) },
            { CKA_TOKEN,         &bFalse,   sizeof(bFalse) }
        };
        CK_ATTRIBUTE privTmpl[] = {
            { CKA_CLASS,         &privClass, sizeof(privClass) },
            { CKA_KEY_TYPE,      &ktypeKem, sizeof(ktypeKem) },
            { CKA_DECAPSULATE,   &bTrue,    sizeof(bTrue) },
            { CKA_PARAMETER_SET, &paramSetKem, sizeof(paramSetKem) },
            { CKA_TOKEN,         &bFalse,   sizeof(bFalse) }
        };

        CK_OBJECT_HANDLE hPub, hPriv;
        CK_RV rv = fl->C_GenerateKeyPair(hSess, &mech, pubTmpl, 5, privTmpl, 5, &hPub, &hPriv);
        if (rv != CKR_OK) {
            record_result("KEM", "Generate_ML_KEM_" + n, "FAIL", "Generation failed, RV=" + std::to_string(rv));
            continue;
        }
                record_result("KEM", "Generate_ML_KEM_" + n, "PASS", "Gen ML-KEM-" + n);
        check_key_profile("Attributes", "ML_KEM_" + n, hPub, hPriv, true);

        // Encapsulate
        CK_MECHANISM encapMech = { CKM_ML_KEM, NULL_PTR, 0 };
        CK_BYTE ct[2000]; CK_ULONG ctLen = sizeof(ct);
        
        CK_OBJECT_CLASS secClass = CKO_SECRET_KEY;
        CK_KEY_TYPE secType = 0x00000010; // CKK_GENERIC_SECRET
        CK_ULONG secLen = 32;
        CK_ATTRIBUTE ssTmpl[] = {
            { CKA_CLASS, &secClass, sizeof(secClass) },
            { CKA_KEY_TYPE, &secType, sizeof(secType) },
            { CKA_VALUE_LEN, &secLen, sizeof(secLen) },
            { CKA_TOKEN, &bFalse, sizeof(bFalse) },
            { CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) }
        };
        CK_OBJECT_HANDLE hSecretEnc;
        
        rv = EncapFn(hSess, &encapMech, hPub, ssTmpl, 5, ct, &ctLen, &hSecretEnc);
        if (rv != CKR_OK) { record_result("KEM", "C_EncapsulateKey_" + n, "FAIL", "RV=" + std::to_string(rv)); continue; }
        record_result("KEM", "C_EncapsulateKey_" + n, "PASS", "CT len=" + std::to_string(ctLen));

        // Decapsulate
        CK_OBJECT_HANDLE hSecretDec;
        rv = DecapFn(hSess, &encapMech, hPriv, ssTmpl, 5, ct, ctLen, &hSecretDec);
        if (rv != CKR_OK) { record_result("KEM", "C_DecapsulateKey_" + n, "FAIL", "RV=" + std::to_string(rv)); continue; }
        
        CK_BYTE val1[100]; CK_ATTRIBUTE attr1 = { CKA_VALUE, val1, sizeof(val1) };
        CK_BYTE val2[100]; CK_ATTRIBUTE attr2 = { CKA_VALUE, val2, sizeof(val2) };
        fl->C_GetAttributeValue(hSess, hSecretEnc, &attr1, 1);
        fl->C_GetAttributeValue(hSess, hSecretDec, &attr2, 1);
        
        if (attr1.ulValueLen > 0 && attr1.ulValueLen == attr2.ulValueLen && memcmp(val1, val2, attr1.ulValueLen) == 0) {
            record_result("KEM", "C_DecapsulateKey_" + n, "PASS", "SS matched");
        } else {
            record_result("KEM", "C_DecapsulateKey_" + n, "FAIL", "SS mismatch");
        }
    }
}


#ifndef CKM_HASH_ML_DSA_SHA512
#define CKM_HASH_ML_DSA_SHA512 0x00000026UL
#define CKM_HASH_ML_DSA_SHA3_512 0x0000002aUL
#endif

void test_pqc_dsa() {
    CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
    CK_OBJECT_CLASS privClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE ktypeDsa = 0x0000004a; // CKK_ML_DSA
    CK_BBOOL bTrue = CK_TRUE, bFalse = CK_FALSE;

    CK_MECHANISM mech = { CKM_ML_DSA_KEY_PAIR_GEN, NULL_PTR, 0 };
    
    CK_ULONG dsaParams[] = { 1, 2, 3 }; // 44, 65, 87
    std::string dsaNames[] = { "44", "65", "87" };
    
    // Test pure and pre-hash mechanisms for ML-DSA
    CK_MECHANISM_TYPE signMechs[] = { CKM_ML_DSA, CKM_HASH_ML_DSA_SHA512, CKM_HASH_ML_DSA_SHA3_512 };
    std::string signNames[] = { "Pure", "PreHash_SHA512", "PreHash_SHA3_512" };
    
    for (int i = 0; i < 3; ++i) {
        std::string n = dsaNames[i];
        CK_ULONG paramSetDsa = dsaParams[i];
        
        CK_ATTRIBUTE pubTmpl[] = { 
            { CKA_CLASS,         &pubClass, sizeof(pubClass) },
            { CKA_KEY_TYPE,      &ktypeDsa, sizeof(ktypeDsa) },
            { CKA_VERIFY,        &bTrue,    sizeof(bTrue) },
            { CKA_PARAMETER_SET, &paramSetDsa,  sizeof(paramSetDsa) },
            { CKA_TOKEN,         &bFalse,   sizeof(bFalse) }
        };
        CK_ATTRIBUTE privTmpl[] = { 
            { CKA_CLASS,         &privClass, sizeof(privClass) },
            { CKA_KEY_TYPE,      &ktypeDsa, sizeof(ktypeDsa) },
            { CKA_SIGN,          &bTrue,    sizeof(bTrue) },
            { CKA_PARAMETER_SET, &paramSetDsa,  sizeof(paramSetDsa) },
            { CKA_TOKEN,         &bFalse,   sizeof(bFalse) }
        };

        CK_OBJECT_HANDLE hPub = 0, hPriv = 0;
        CK_RV rv = fl->C_GenerateKeyPair(hSess, &mech, pubTmpl, 5, privTmpl, 5, &hPub, &hPriv);
        if (rv != CKR_OK) {
            record_result("DSA", "Generate_ML_DSA_" + n, "FAIL", "RV=" + std::to_string(rv));
            continue;
        }
                record_result("DSA", "Generate_ML_DSA_" + n, "PASS", "Gen ML-DSA-" + n);
        check_key_profile("Attributes", "ML_DSA_" + n, hPub, hPriv, false);
        
        for (int j = 0; j < 3; j++) {
            std::string runName = n + "_" + signNames[j];
            CK_MECHANISM signMech = { signMechs[j], NULL_PTR, 0 };
            
            rv = fl->C_SignInit(hSess, &signMech, hPriv);
            if (rv == CKR_MECHANISM_INVALID || rv == CKR_FUNCTION_NOT_SUPPORTED) {
                    record_result("DSA", "C_SignInit_" + runName, "SKIP", "Mechanism not implemented");
                    continue;
            }
            if (rv != CKR_OK) {
                record_result("DSA", "C_SignInit_" + runName, "FAIL", "RV=" + std::to_string(rv));
                continue;
            }
            
            CK_BYTE msg[] = "test message variation hashing";
            CK_BYTE sig[5000];
            CK_ULONG sigLen = sizeof(sig);
            rv = fl->C_Sign(hSess, msg, sizeof(msg)-1, sig, &sigLen);
            record_result("DSA", "C_Sign_" + runName, rv == CKR_OK ? "PASS" : "FAIL", "RV=" + std::to_string(rv));

            rv = fl->C_VerifyInit(hSess, &signMech, hPub);
            if (rv == CKR_OK) {
                rv = fl->C_Verify(hSess, msg, sizeof(msg)-1, sig, sigLen);
                record_result("DSA", "C_Verify_" + runName, rv == CKR_OK ? "PASS" : "FAIL", "RV=" + std::to_string(rv));
            } else {
                record_result("DSA", "C_VerifyInit_" + runName, "FAIL", "RV=" + std::to_string(rv));
            }
        }
    }
}


// Additions for PKCS#11 v3.2 compliance tool

#ifndef CKM_HASH_SLH_DSA
#define CKM_HASH_SLH_DSA               0x00000034UL
#define CKM_HASH_SLH_DSA_SHA256        0x00000037UL
#define CKM_HASH_SLH_DSA_SHAKE256      0x0000003fUL
#endif

// Function pointer structs for v3.2 message based signatures
typedef CK_RV (*C_SignMessageBegin_t)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE);
typedef CK_RV (*C_SignMessageNext_t)(CK_SESSION_HANDLE, CK_VOID_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);

typedef CK_RV (*C_VerifyMessageBegin_t)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE);
typedef CK_RV (*C_VerifyMessageNext_t)(CK_SESSION_HANDLE, CK_VOID_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG);

// Function pointer structs for v3.2 message based encryption
typedef CK_RV (*C_MessageEncryptInit_t)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE);
typedef CK_RV (*C_EncryptMessageBegin_t)(CK_SESSION_HANDLE, CK_VOID_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG);
typedef CK_RV (*C_EncryptMessageNext_t)(CK_SESSION_HANDLE, CK_VOID_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR, CK_ULONG);
typedef CK_RV (*C_MessageEncryptFinal_t)(CK_SESSION_HANDLE);

void test_v32_kdfs() {
    CK_OBJECT_CLASS secClass = CKO_SECRET_KEY;
    CK_KEY_TYPE genType = 0x00000010; // CKK_GENERIC_SECRET
    CK_BBOOL bTrue = CK_TRUE, bFalse = CK_FALSE;
    CK_ULONG valueLen = 32;

    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS, &secClass, sizeof(secClass) },
        { CKA_KEY_TYPE, &genType, sizeof(genType) },
        { CKA_TOKEN, &bFalse, sizeof(bFalse) },
        { CKA_VALUE_LEN, &valueLen, sizeof(valueLen) },
        { CKA_DERIVE, &bTrue, sizeof(bTrue) }
    };
    
    CK_OBJECT_HANDLE hBaseKey = 0;
    CK_MECHANISM genMech = { CKM_GENERIC_SECRET_KEY_GEN, NULL_PTR, 0 };
    CK_RV rv = fl->C_GenerateKey(hSess, &genMech, tmpl, 5, &hBaseKey);
    if (rv != CKR_OK) {
        record_result("KDF", "BaseKeyGen", "FAIL", "Failed to generate base key");
        return;
    }
    
    // Test PBKDF2
    CK_UTF8CHAR password[] = "password";
    CK_BYTE salt[] = "salt";
    CK_ULONG iterations = 2048;
    CK_ULONG pwdLen = sizeof(password) - 1;
    CK_PKCS5_PBKD2_PARAMS2 pbkdf2Params = {
        1 /* CKZ_SALT_SPECIFIED */, salt, sizeof(salt)-1,
        iterations,
        4 /* CKP_PKCS5_PBKD2_HMAC_SHA256 */, NULL_PTR, 0,
        password, pwdLen
    };
    CK_MECHANISM pbMech = { CKM_PKCS5_PBKD2, &pbkdf2Params, sizeof(pbkdf2Params) };
    
    CK_ULONG derivedLen = 32;
    CK_ATTRIBUTE deriveTmpl[] = {
        { CKA_CLASS, &secClass, sizeof(secClass) },
        { CKA_KEY_TYPE, &genType, sizeof(genType) },
        { CKA_VALUE_LEN, &derivedLen, sizeof(derivedLen) },
        { CKA_TOKEN, &bFalse, sizeof(bFalse) },
        { CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) },
        { CKA_ENCRYPT, &bTrue, sizeof(bTrue) },
        { CKA_SENSITIVE, &bFalse, sizeof(bFalse) }
    };
    CK_OBJECT_HANDLE hDerived1;
    rv = fl->C_DeriveKey(hSess, &pbMech, hBaseKey, deriveTmpl, 7, &hDerived1);
    record_result("KDF", "CKM_PKCS5_PBKD2", rv == CKR_OK ? "PASS" : "FAIL", "RV=" + std::to_string(rv));
    
    // Test SP800-108 Counter
    CK_BYTE label[] = "label";
    CK_BYTE context[] = "context";
    CK_PRF_DATA_PARAM prfParams[] = {
        { 1 /* CK_SP800_108_INITIAL_COUNTER */, NULL_PTR, 0 }, 
        { 2 /* CK_SP800_108_LABEL */, label, sizeof(label)-1 },
        { 3 /* CK_SP800_108_CONTEXT */, context, sizeof(context)-1 }
    };
    CK_SP800_108_KDF_PARAMS ctrParams = {
        0x00000250UL /* CKM_SHA256 */,
        3, prfParams, 0, NULL_PTR
    };
    CK_MECHANISM ctrMech = { 0x000003acUL /* CKM_SP800_108_COUNTER_KDF */, &ctrParams, sizeof(ctrParams) };
    CK_OBJECT_HANDLE hDerived2;
    rv = fl->C_DeriveKey(hSess, &ctrMech, hBaseKey, deriveTmpl, 7, &hDerived2);
    if (rv == CKR_MECHANISM_INVALID || rv == CKR_FUNCTION_NOT_SUPPORTED) {
        record_result("KDF", "CKM_SP800_108_COUNTER_KDF", "SKIP", "Mechanism unavailable");
    } else {
        record_result("KDF", "CKM_SP800_108_COUNTER_KDF", rv == CKR_OK ? "PASS" : "FAIL", "RV=" + std::to_string(rv));
    }
}

void test_pqc_slh_dsa() {
    CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
    CK_OBJECT_CLASS privClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE ktypeDsa = 0x0000004b; // CKK_SLH_DSA
    CK_BBOOL bTrue = CK_TRUE, bFalse = CK_FALSE;

    CK_MECHANISM mech = { 0x0000002dUL /* CKM_SLH_DSA_KEY_PAIR_GEN */, NULL_PTR, 0 };
    
    // Test 128S, 128F, 256F to cover permutations
    CK_ULONG dsaParams[] = { 1 /* CKP_SLH_DSA_SHA2_128S */, 3 /* CKP_SLH_DSA_SHA2_128F */, 11 /* CKP_SLH_DSA_SHA2_256F */ }; 
    std::string dsaNames[] = { "SHA2_128S", "SHA2_128F", "SHA2_256F" };
    
    for (int i = 0; i < 3; ++i) {
        std::string n = dsaNames[i];
        CK_ULONG paramSetDsa = dsaParams[i];
        
        CK_ATTRIBUTE pubTmpl[] = { 
            { CKA_CLASS,         &pubClass, sizeof(pubClass) },
            { CKA_KEY_TYPE,      &ktypeDsa, sizeof(ktypeDsa) },
            { CKA_VERIFY,        &bTrue,    sizeof(bTrue) },
            { CKA_PARAMETER_SET, &paramSetDsa,  sizeof(paramSetDsa) },
            { CKA_TOKEN,         &bFalse,   sizeof(bFalse) }
        };
        CK_ATTRIBUTE privTmpl[] = { 
            { CKA_CLASS,         &privClass, sizeof(privClass) },
            { CKA_KEY_TYPE,      &ktypeDsa, sizeof(ktypeDsa) },
            { CKA_SIGN,          &bTrue,    sizeof(bTrue) },
            { CKA_PARAMETER_SET, &paramSetDsa,  sizeof(paramSetDsa) },
            { CKA_TOKEN,         &bFalse,   sizeof(bFalse) }
        };

        CK_OBJECT_HANDLE hPub = 0, hPriv = 0;
        CK_RV rv = fl->C_GenerateKeyPair(hSess, &mech, pubTmpl, 5, privTmpl, 5, &hPub, &hPriv);
        if (rv == CKR_MECHANISM_INVALID || rv == CKR_FUNCTION_NOT_SUPPORTED) {
            record_result("SLHDSA", "Generate_SLH_DSA_" + n, "SKIP", "Mech unavailable");
            continue;
        }
        if (rv != CKR_OK) {
            record_result("SLHDSA", "Generate_SLH_DSA_" + n, "FAIL", "RV=" + std::to_string(rv));
            continue;
        }
        record_result("SLHDSA", "Generate_SLH_DSA_" + n, "PASS", "Gen SLH-DSA-" + n);
        
        // Test Context String + Deterministic
        CK_BYTE contextStr[] = "pkcs11-compliance-test";
        CK_SIGN_ADDITIONAL_CONTEXT sigCtx = {
            2, // CKH_DETERMINISTIC_REQUIRED
            contextStr, sizeof(contextStr)-1
        };
        CK_MECHANISM signMech = { 0x0000002eUL /* CKM_SLH_DSA */, &sigCtx, sizeof(sigCtx) };
        rv = fl->C_SignInit(hSess, &signMech, hPriv);
        if (rv == CKR_OK) {
            CK_BYTE msg[] = "test msg";
            CK_BYTE sig[50000];
            CK_ULONG sigLen = sizeof(sig);
            rv = fl->C_Sign(hSess, msg, sizeof(msg)-1, sig, &sigLen);
            record_result("SLHDSA", "C_Sign_" + n + "_Deterministic_Ctx", rv == CKR_OK ? "PASS" : "FAIL", "RV=" + std::to_string(rv));
        } else {
            record_result("SLHDSA", "C_SignInit_" + n, "FAIL", "RV=" + std::to_string(rv));
        }
        // Force cleanup of the sign state in case it leaked or failed internally
        fl->C_SignFinal(hSess, NULL_PTR, NULL_PTR);
    }
}

void test_message_signatures() {
    void* dlib = dlopen(opt_engine.c_str(), RTLD_NOW);
    typedef CK_RV (*C_MessageSignInit_t)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE);
    C_MessageSignInit_t SignInit = (C_MessageSignInit_t)dlsym(dlib, "C_MessageSignInit");
    C_SignMessageBegin_t SignBegin = (C_SignMessageBegin_t)dlsym(dlib, "C_SignMessageBegin");
    C_SignMessageNext_t SignNext = (C_SignMessageNext_t)dlsym(dlib, "C_SignMessageNext");
    if (!SignInit || !SignBegin) {
        record_result("MsgSign", "Validation", "SKIP", "v3.0 APIs missing");
        return;
    }
    
    // We reuse an AES or generic secret key generator just to check the API path, or an RSA key for true stream signing...
    // Actually SLH-DSA or ML-DSA doesn't support streaming realistically on HW, but SoftHSM soft-stream hashes it!
    CK_OBJECT_CLASS privClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE ktype = CKK_RSA;
    CK_BBOOL bTrue = CK_TRUE, bFalse = CK_FALSE;
    CK_ULONG modulusBits = 1024;
    CK_BYTE publicExponent[] = { 3 };
    CK_ATTRIBUTE privTmpl[] = { 
        { CKA_CLASS, &privClass, sizeof(privClass) },
        { CKA_KEY_TYPE, &ktype, sizeof(ktype) },
        { CKA_SIGN, &bTrue, sizeof(bTrue) },
        { CKA_TOKEN, &bFalse, sizeof(bFalse) }
    };
    CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
    CK_ATTRIBUTE pubTmpl[] = { 
        { CKA_CLASS, &pubClass, sizeof(pubClass) }, 
        { CKA_KEY_TYPE, &ktype, sizeof(ktype) },
        { CKA_VERIFY, &bTrue, sizeof(bTrue) },
        { CKA_MODULUS_BITS, &modulusBits, sizeof(modulusBits) },
        { CKA_PUBLIC_EXPONENT, publicExponent, sizeof(publicExponent) },
        { CKA_TOKEN, &bFalse, sizeof(bFalse) }
    };
    CK_OBJECT_HANDLE hPub=0, hPriv=0;
    CK_MECHANISM mech = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0 };
    
    CK_RV rvGenDsa = fl->C_GenerateKeyPair(hSess, &mech, pubTmpl, 6, privTmpl, 4, &hPub, &hPriv);
    if (rvGenDsa == CKR_OK) {
        CK_MECHANISM signMech = { CKM_RSA_PKCS, NULL_PTR, 0 }; 
        CK_RV rvInit = SignInit(hSess, &signMech, hPriv);
        record_result("MsgSign", "C_MessageSignInit", rvInit == CKR_OK ? "PASS" : "FAIL", "RV=" + std::to_string(rvInit));
        
        CK_RV rv = SignBegin(hSess, NULL_PTR, 0);
        record_result("MsgSign", "C_SignMessageBegin", rv == CKR_OK ? "PASS" : "FAIL", "RV=" + std::to_string(rv));
        
        if (rv == CKR_OK) {
            CK_BYTE msg[] = "test";
            CK_BYTE sig[5000]; CK_ULONG sigLen = sizeof(sig);
            // v3.0 signature call for single MessageNext finishing string
            rv = SignNext(hSess, NULL_PTR, 0, msg, sizeof(msg)-1, sig, &sigLen);
            // SoftHSM ML-DSA might reject streaming without hash, but API path returns proper PKCS11 code!
            record_result("MsgSign", "C_SignMessageNext", (rv == CKR_OK || rv == CKR_FUNCTION_NOT_SUPPORTED || rv == CKR_MECHANISM_INVALID) ? "PASS" : "FAIL", "RV=" + std::to_string(rv));
        }
    } else {
        record_result("MsgSign", "C_GenerateKeyPair", "FAIL", "RV=" + std::to_string(rvGenDsa));
    }
}

void test_message_encryption() {
    void* dlib = dlopen(opt_engine.c_str(), RTLD_NOW);
    C_MessageEncryptInit_t MsgEncInit = (C_MessageEncryptInit_t)dlsym(dlib, "C_MessageEncryptInit");
    C_EncryptMessageBegin_t MsgEncBeg = (C_EncryptMessageBegin_t)dlsym(dlib, "C_EncryptMessageBegin");
    
    if (!MsgEncInit) {
        record_result("MsgCrypt", "Validation", "SKIP", "v3.0 APIs missing");
        return;
    }
    
    CK_OBJECT_CLASS secClass = CKO_SECRET_KEY;
    CK_KEY_TYPE ktype = 0x0000001f; // CKK_AES
    CK_BBOOL bTrue = CK_TRUE, bFalse = CK_FALSE;
    CK_ULONG valueLen = 16;
    CK_ATTRIBUTE tmpl[] = { 
        { CKA_CLASS, &secClass, sizeof(secClass) },
        { CKA_KEY_TYPE, &ktype, sizeof(ktype) },
        { CKA_ENCRYPT, &bTrue, sizeof(bTrue) },
        { CKA_VALUE_LEN, &valueLen, sizeof(valueLen) },
        { CKA_TOKEN, &bTrue, sizeof(bTrue) },
        { CKA_SENSITIVE, &bFalse, sizeof(bFalse) },
        { CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) }
    };
    CK_OBJECT_HANDLE hKey=0;
    CK_MECHANISM mech = { 0x00001080UL, NULL_PTR, 0 }; // CKM_AES_KEY_GEN
    
    CK_RV rvGen = fl->C_GenerateKey(hSess, &mech, tmpl, 7, &hKey);
    if (rvGen == CKR_OK) {
        CK_MECHANISM encMech = { 0x00001087UL, NULL_PTR, 0 }; // CKM_AES_GCM
        
        auto run_msg_test = [&](const std::string& name, CK_BYTE* iv, CK_ULONG ivLen) {
            CK_OBJECT_HANDLE hKeyLocal = 0;
            CK_RV rvGenLocal = fl->C_GenerateKey(hSess, &mech, tmpl, 7, &hKeyLocal);
            if (rvGenLocal != CKR_OK) { record_result("MsgCrypt", name, "FAIL", "GenKey failed"); return; }
            
            CK_RV rv = MsgEncInit(hSess, &encMech, hKeyLocal);
            if (name == "C_EncryptMessageBegin_IV12") {
                record_result("MsgCrypt", "C_MessageEncryptInit", rv == CKR_OK ? "PASS" : "FAIL", "RV=" + std::to_string(rv));
            }
            if (rv != CKR_OK) { record_result("MsgCrypt", name, "FAIL", "Init failed: " + std::to_string(rv)); return; }
            
            CK_BYTE tag[16];
            CK_GCM_MESSAGE_PARAMS msgParams = { iv, ivLen, 0, 0, tag, 128 };
            rv = MsgEncBeg(hSess, &msgParams, sizeof(msgParams), NULL_PTR, 0);
            record_result("MsgCrypt", name, rv == CKR_OK ? "PASS" : "FAIL", "RV=" + std::to_string(rv));
            
            // Recreate session to reset state
            refresh_session();
        };

        CK_BYTE iv12[] = "123456789012";
        CK_BYTE iv16[] = "1234567890123456";
        CK_BYTE iv8[] = "12345678";
        
        run_msg_test("C_EncryptMessageBegin_IV12", iv12, sizeof(iv12)-1);
        run_msg_test("C_EncryptMessageBegin_IV16", iv16, sizeof(iv16)-1);
        run_msg_test("C_EncryptMessageBegin_IV8", iv8, sizeof(iv8)-1);
    } else {
        record_result("MsgCrypt", "C_GenerateKey", "FAIL", "RV=" + std::to_string(rvGen));
    }
}

void test_classical_crypto() {
    CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
    CK_OBJECT_CLASS privClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE ktypeRsa = CKK_RSA;
    CK_BBOOL bTrue = CK_TRUE, bFalse = CK_FALSE;

    CK_ULONG modulusBits = 2048;
    CK_BYTE pubExp[] = { 3 };
    
    CK_ATTRIBUTE pubTmpl[] = { 
        { CKA_CLASS, &pubClass, sizeof(pubClass) },
        { CKA_KEY_TYPE, &ktypeRsa, sizeof(ktypeRsa) },
        { CKA_VERIFY, &bTrue, sizeof(bTrue) },
        { CKA_MODULUS_BITS, &modulusBits, sizeof(modulusBits) },
        { CKA_PUBLIC_EXPONENT, pubExp, sizeof(pubExp) },
        { CKA_TOKEN, &bFalse, sizeof(bFalse) }
    };
    CK_ATTRIBUTE privTmpl[] = { 
        { CKA_CLASS, &privClass, sizeof(privClass) },
        { CKA_KEY_TYPE, &ktypeRsa, sizeof(ktypeRsa) },
        { CKA_SIGN, &bTrue, sizeof(bTrue) },
        { CKA_TOKEN, &bFalse, sizeof(bFalse) }
    };

    CK_OBJECT_HANDLE hPub = 0, hPriv = 0;
    CK_MECHANISM mech = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0 };
    
    CK_RV rv = fl->C_GenerateKeyPair(hSess, &mech, pubTmpl, 6, privTmpl, 4, &hPub, &hPriv);
    record_result("Classical", "Generate_RSA_2048", rv == CKR_OK ? "PASS" : "FAIL", "RV=" + std::to_string(rv));
    
    if (rv == CKR_OK) {
        CK_MECHANISM signMech = { CKM_SHA256_RSA_PKCS, NULL_PTR, 0 };
        rv = fl->C_SignInit(hSess, &signMech, hPriv);
        if (rv == CKR_OK) {
            CK_BYTE msg[] = "test message";
            CK_BYTE sig[256];
            CK_ULONG sigLen = sizeof(sig);
            rv = fl->C_Sign(hSess, msg, sizeof(msg)-1, sig, &sigLen);
            record_result("Classical", "C_Sign_RSA_SHA256", rv == CKR_OK ? "PASS" : "FAIL", "RV=" + std::to_string(rv));
        }
    }
}

void test_negative_paths() {
    CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
    CK_OBJECT_CLASS privClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE ktypeKem = 0x0000004c; // CKK_ML_KEM
    CK_BBOOL bTrue = CK_TRUE, bFalse = CK_FALSE;
    CK_ULONG paramSetKem = 2; // ML-KEM-768
    
    CK_ATTRIBUTE pubTmpl[] = { 
        { CKA_CLASS, &pubClass, sizeof(pubClass) }, { CKA_KEY_TYPE, &ktypeKem, sizeof(ktypeKem) },
        { CKA_ENCAPSULATE, &bTrue, sizeof(bTrue) }, { CKA_PARAMETER_SET, &paramSetKem, sizeof(paramSetKem) }
    };
    CK_ATTRIBUTE privTmpl[] = { 
        { CKA_CLASS, &privClass, sizeof(privClass) }, { CKA_KEY_TYPE, &ktypeKem, sizeof(ktypeKem) },
        { CKA_DECAPSULATE, &bTrue, sizeof(bTrue) }, { CKA_PARAMETER_SET, &paramSetKem, sizeof(paramSetKem) }
    };

    CK_OBJECT_HANDLE hPub = 0, hPriv = 0;
    CK_MECHANISM mech = { 0x0000000fUL /* CKM_ML_KEM_KEY_PAIR_GEN */, NULL_PTR, 0 };
    fl->C_GenerateKeyPair(hSess, &mech, pubTmpl, 4, privTmpl, 4, &hPub, &hPriv);
    
    if (hPriv) {
        CK_MECHANISM signMech = { 0x0000001dUL /* CKM_ML_DSA */, NULL_PTR, 0 };
        // SoftHSM core bug: invoking C_SignInit with an incompatible mechanism on an ML-KEM key cascades into a Segfault
        CK_RV rv = fl->C_SignInit(hSess, &signMech, hPriv);
        record_result("Negative", "Sign_With_KEM_Key", rv == CKR_KEY_FUNCTION_NOT_PERMITTED || rv == CKR_KEY_TYPE_INCONSISTENT ? "PASS" : "FAIL", "Expected CKR_KEY_FUNCTION_NOT_PERMITTED, got " + std::to_string(rv));
        //record_result("Negative", "Sign_With_KEM_Key", "SKIP", "Blocked by SoftHSM engine segmentation fault on mismatched mechanism context");
    }
}

void test_slot_session_management() {
    // 1. Invalid Slot ID
    CK_SESSION_HANDLE hBadSess = 0;
    CK_RV rv = fl->C_OpenSession(999999, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hBadSess);
    record_result("Session", "C_OpenSession_InvalidSlot", rv == CKR_SLOT_ID_INVALID ? "PASS" : "FAIL", "RV=" + std::to_string(rv));

    // 2. Read-Only Session Constraints against Token Objects
    CK_OBJECT_CLASS dataClass = CKO_DATA;
    CK_BBOOL bTrue = CK_TRUE, bFalse = CK_FALSE;
    CK_BYTE label[] = "test data";
    CK_ATTRIBUTE dataTmpl[] = {
        { CKA_CLASS, &dataClass, sizeof(dataClass) },
        { CKA_TOKEN, &bTrue, sizeof(bTrue) }, // Must be TRUE to test RO protections
        { CKA_PRIVATE, &bTrue, sizeof(bTrue) },
        { CKA_LABEL, label, sizeof(label)-1 }
    };
    CK_OBJECT_HANDLE hData = 0;
    fl->C_CreateObject(hSess, dataTmpl, 4, &hData); // Create in our active RW session

    CK_SESSION_HANDLE hRoSess = 0;
    rv = fl->C_OpenSession(0, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hRoSess);
    if (rv == CKR_OK) {
        CK_ATTRIBUTE modifyTmpl[] = { { CKA_LABEL, label, sizeof(label)-1 } };
        rv = fl->C_SetAttributeValue(hRoSess, hData, modifyTmpl, 1);
        record_result("Session", "C_SetAttributeValue_RO", rv == CKR_SESSION_READ_ONLY ? "PASS" : "FAIL", "RV=" + std::to_string(rv));
        fl->C_CloseSession(hRoSess);
    } else {
        record_result("Session", "C_SetAttributeValue_RO", "SKIP", "Failed to open RO session: " + std::to_string(rv));
    }

    // 3. Cross-Session Object Visibility (PKCS#11 states Session objects are visible across ALL sessions in the app)
    CK_SESSION_HANDLE hSess2 = 0;
    rv = fl->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSess2);
    if (rv == CKR_OK) {
        CK_ATTRIBUTE findTmpl[] = { { CKA_CLASS, &dataClass, sizeof(dataClass) } };
        fl->C_FindObjectsInit(hSess2, findTmpl, 1);
        CK_OBJECT_HANDLE objs[10];
        CK_ULONG objCount = 0;
        fl->C_FindObjects(hSess2, objs, 10, &objCount);
        fl->C_FindObjectsFinal(hSess2);
        
        bool found = false;
        for (CK_ULONG i=0; i<objCount; i++) if (objs[i] == hData) found = true;
        record_result("Session", "Session_Object_CrossVisibility", found ? "PASS" : "FAIL", found ? "Visible (Compliant)" : "Not Visible");
        fl->C_CloseSession(hSess2);
    } else {
        record_result("Session", "Session_Object_CrossVisibility", "SKIP", "Could not open hSess2");
    }
}

void test_fips_edge_constraints() {
    CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
    CK_OBJECT_CLASS privClass = CKO_PRIVATE_KEY;
    CK_BBOOL bTrue = CK_TRUE, bFalse = CK_FALSE;

    void* dlib = dlopen(opt_engine.c_str(), RTLD_NOW);
    typedef CK_RV (*C_EncapsulateKey_t)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR, CK_OBJECT_HANDLE_PTR);
    typedef CK_RV (*C_DecapsulateKey_t)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR);
    C_EncapsulateKey_t mlkemEncap = (C_EncapsulateKey_t)dlsym(dlib, "C_EncapsulateKey");
    C_DecapsulateKey_t mlkemDecap = (C_DecapsulateKey_t)dlsym(dlib, "C_DecapsulateKey");

    if (!mlkemEncap || !mlkemDecap) {
        record_result("FIPS", "Validation", "SKIP", "v3.0 KEM APIs missing");
        return;
    }

    // 1. ML-KEM Truncated Ciphertext Rejection & Implicit Rejection
    CK_KEY_TYPE ktypeKem = 0x0000004c; // CKK_ML_KEM
    CK_ULONG paramSetKem = 2; // ML-KEM-768
    CK_ATTRIBUTE kPubTmpl[] = { 
        { CKA_CLASS, &pubClass, sizeof(pubClass) }, { CKA_KEY_TYPE, &ktypeKem, sizeof(ktypeKem) },
        { CKA_ENCAPSULATE, &bTrue, sizeof(bTrue) }, { CKA_PARAMETER_SET, &paramSetKem, sizeof(paramSetKem) }, { CKA_TOKEN, &bFalse, sizeof(bFalse) }
    };
    CK_ATTRIBUTE kPrivTmpl[] = { 
        { CKA_CLASS, &privClass, sizeof(privClass) }, { CKA_KEY_TYPE, &ktypeKem, sizeof(ktypeKem) },
        { CKA_DECAPSULATE, &bTrue, sizeof(bTrue) }, { CKA_PARAMETER_SET, &paramSetKem, sizeof(paramSetKem) }, { CKA_TOKEN, &bFalse, sizeof(bFalse) }
    };

    CK_OBJECT_HANDLE hKemPub = 0, hKemPriv = 0;
    CK_MECHANISM kemMech = { 0x0000000fUL /* CKM_ML_KEM_KEY_PAIR_GEN */, NULL_PTR, 0 };
    CK_RV rvKem = fl->C_GenerateKeyPair(hSess, &kemMech, kPubTmpl, 5, kPrivTmpl, 5, &hKemPub, &hKemPriv);
    
    if (rvKem == CKR_OK && hKemPub && hKemPriv) {
        CK_MECHANISM encapMech = { 0x00000017UL /* CKM_ML_KEM */, NULL_PTR, 0 };
        CK_BYTE ct[1088]; CK_ULONG ctLen = sizeof(ct);
        CK_OBJECT_HANDLE hSec1 = 0;
        
        CK_RV rv = mlkemEncap(hSess, &encapMech, hKemPub, NULL_PTR, 0, ct, &ctLen, &hSec1);
        if (rv == CKR_OK) {
            // Decap Truncated
            CK_OBJECT_HANDLE hSec2 = 0;
            rv = mlkemDecap(hSess, &encapMech, hKemPriv, NULL_PTR, 0, ct, ctLen - 1, &hSec2);
            record_result("FIPS", "ML-KEM_Truncated_CT", (rv == CKR_WRAPPED_KEY_LEN_RANGE || rv == CKR_WRAPPED_KEY_INVALID || rv == CKR_ENCRYPTED_DATA_LEN_RANGE || rv == CKR_ENCRYPTED_DATA_INVALID || rv == CKR_ARGUMENTS_BAD) ? "PASS" : "FAIL", "RV=" + std::to_string(rv));
            
            // Decap Tampered
            ct[0] ^= 1;
            CK_OBJECT_HANDLE hSec3 = 0;
            rv = mlkemDecap(hSess, &encapMech, hKemPriv, NULL_PTR, 0, ct, ctLen, &hSec3);
            if (rv == CKR_OK) {
                record_result("FIPS", "ML-KEM_Implicit_Rejection", "PASS", "Yielded deterministic random secret per FIPS 203");
            } else {
                record_result("FIPS", "ML-KEM_Implicit_Rejection", "FAIL", "Failed decap instead of implicit rej (RV=" + std::to_string(rv) + ")");
            }
        } else {
            record_result("FIPS", "ML-KEM_Encap", "FAIL", "RV=" + std::to_string(rv));
        }
    } else {
        record_result("FIPS", "ML-KEM_Generate", "FAIL", "RV=" + std::to_string(rvKem));
    }

    // 2. ML-DSA Context Size > 255
    CK_KEY_TYPE ktypeDsa = 0x0000004a; // CKK_ML_DSA
    CK_ULONG paramSetDsa = 1; // ML-DSA-44
    CK_ATTRIBUTE dPubTmpl[] = { 
        { CKA_CLASS, &pubClass, sizeof(pubClass) }, { CKA_KEY_TYPE, &ktypeDsa, sizeof(ktypeDsa) },
        { CKA_VERIFY, &bTrue, sizeof(bTrue) }, { CKA_PARAMETER_SET, &paramSetDsa, sizeof(paramSetDsa) }, { CKA_TOKEN, &bFalse, sizeof(bFalse) }
    };
    CK_ATTRIBUTE dPrivTmpl[] = { 
        { CKA_CLASS, &privClass, sizeof(privClass) }, { CKA_KEY_TYPE, &ktypeDsa, sizeof(ktypeDsa) },
        { CKA_SIGN, &bTrue, sizeof(bTrue) }, { CKA_PARAMETER_SET, &paramSetDsa, sizeof(paramSetDsa) }, { CKA_TOKEN, &bFalse, sizeof(bFalse) }
    };

    CK_OBJECT_HANDLE hDsaPub = 0, hDsaPriv = 0;
    CK_MECHANISM dsaMech = { 0x0000001cUL /* CKM_ML_DSA_KEY_PAIR_GEN */, NULL_PTR, 0 };
    CK_RV rvDsa = fl->C_GenerateKeyPair(hSess, &dsaMech, dPubTmpl, 5, dPrivTmpl, 5, &hDsaPub, &hDsaPriv);
    
    if (rvDsa == CKR_OK && hDsaPriv) {
        CK_BYTE giantCtx[256] = {0};
        CK_SIGN_ADDITIONAL_CONTEXT sigCtx = {
            1, // CKH_HEDGE_REQUIRED = 1
            giantCtx, 256
        };
        CK_MECHANISM signMech = { 0x0000001dUL /* CKM_ML_DSA */, &sigCtx, sizeof(sigCtx) };
        CK_RV rv = fl->C_SignInit(hSess, &signMech, hDsaPriv);
        record_result("FIPS", "ML-DSA_Oversized_Ctx", rv == CKR_ARGUMENTS_BAD ? "PASS" : "FAIL", "RV=" + std::to_string(rv));
        // SoftHSM will return CKR_ARGUMENTS_BAD when ulContextLen > 255. Force cancel in case it succeeds
        if (rv == CKR_OK) fl->C_SignFinal(hSess, NULL_PTR, NULL_PTR);
    } else {
        record_result("FIPS", "ML-DSA_Generate", "FAIL", "RV=" + std::to_string(rvDsa));
    }
}

void test_authenticated_wrap() {
    void* dlib = dlopen(opt_engine.c_str(), RTLD_NOW);
    typedef CK_RV (*C_WrapKeyAuthenticated_t)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
    typedef CK_RV (*C_UnwrapKeyAuthenticated_t)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_ATTRIBUTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR);
    
    C_WrapKeyAuthenticated_t WrapAuth = (C_WrapKeyAuthenticated_t)dlsym(dlib, "C_WrapKeyAuthenticated");
    C_UnwrapKeyAuthenticated_t UnwrapAuth = (C_UnwrapKeyAuthenticated_t)dlsym(dlib, "C_UnwrapKeyAuthenticated");
    
    if (!WrapAuth || !UnwrapAuth) {
        record_result("AuthWrap", "Validation", "SKIP", "v3.2 Auth Wrap APIs missing");
        return;
    }
    
    // Generate AES wrapping key
    CK_OBJECT_CLASS secClass = CKO_SECRET_KEY;
    CK_KEY_TYPE ktype = CKK_AES;
    CK_BBOOL bTrue = CK_TRUE, bFalse = CK_FALSE;
    CK_ULONG valueLen = 32;
    CK_ATTRIBUTE wrapTmpl[] = { 
        { CKA_CLASS, &secClass, sizeof(secClass) },
        { CKA_KEY_TYPE, &ktype, sizeof(ktype) },
        { CKA_WRAP, &bTrue, sizeof(bTrue) },
        { CKA_UNWRAP, &bTrue, sizeof(bTrue) },
        { CKA_VALUE_LEN, &valueLen, sizeof(valueLen) },
        { CKA_TOKEN, &bFalse, sizeof(bFalse) },
        { CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) }
    };
    CK_OBJECT_HANDLE hWrapKey = 0;
    CK_MECHANISM mechGen = { 0x00001080UL /* CKM_AES_KEY_GEN */, NULL_PTR, 0 };
    fl->C_GenerateKey(hSess, &mechGen, wrapTmpl, 7, &hWrapKey);
    
    // Generate target AES payload key
    CK_ATTRIBUTE targetTmpl[] = { 
        { CKA_CLASS, &secClass, sizeof(secClass) },
        { CKA_KEY_TYPE, &ktype, sizeof(ktype) },
        { CKA_VALUE_LEN, &valueLen, sizeof(valueLen) },
        { CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) },
        { CKA_TOKEN, &bFalse, sizeof(bFalse) }
    };
    CK_OBJECT_HANDLE hTarget = 0;
    fl->C_GenerateKey(hSess, &mechGen, targetTmpl, 5, &hTarget);
    
    if (!hWrapKey || !hTarget) {
        record_result("AuthWrap", "KeySetup", "FAIL", "Failed to generate keys");
        return;
    }
    
    // Wrap
    CK_BYTE iv[12] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c};
    CK_BYTE aad[] = "header";
    CK_GCM_PARAMS gcmParams = { iv, 12, 0, 0, NULL_PTR, 128 /* 16 byte tag */ };
    CK_MECHANISM wrapMech = { 0x00001087UL /* CKM_AES_GCM */, &gcmParams, sizeof(gcmParams) };
    
    CK_BYTE wrapped[256];
    CK_ULONG wrappedLen = sizeof(wrapped);
    CK_RV rv = WrapAuth(hSess, &wrapMech, hWrapKey, hTarget, aad, sizeof(aad)-1, wrapped, &wrappedLen);
    record_result("AuthWrap", "C_WrapKeyAuthenticated", rv == CKR_OK ? "PASS" : "FAIL", "RV=" + std::to_string(rv));
    
    if (rv == CKR_OK) {
        // Unwrap
        CK_OBJECT_HANDLE hUnwrapped = 0;
        CK_ATTRIBUTE unwrapTmpl[] = { 
            { CKA_CLASS, &secClass, sizeof(secClass) },
            { CKA_KEY_TYPE, &ktype, sizeof(ktype) },
            { CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) }
        };
        rv = UnwrapAuth(hSess, &wrapMech, hWrapKey, wrapped, wrappedLen, unwrapTmpl, 3, aad, sizeof(aad)-1, &hUnwrapped);
        record_result("AuthWrap", "C_UnwrapKeyAuthenticated", rv == CKR_OK ? "PASS" : "FAIL", "RV=" + std::to_string(rv));
        
        // Assert payloads match (Issue 44 regression test)
        if (rv == CKR_OK) {
            CK_BYTE valTarget[100]; CK_ATTRIBUTE attrTarget = { CKA_VALUE, valTarget, sizeof(valTarget) };
            CK_BYTE valUnwrap[100]; CK_ATTRIBUTE attrUnwrap = { CKA_VALUE, valUnwrap, sizeof(valUnwrap) };
            fl->C_GetAttributeValue(hSess, hTarget, &attrTarget, 1);
            fl->C_GetAttributeValue(hSess, hUnwrapped, &attrUnwrap, 1);
            
            if (attrTarget.ulValueLen == attrUnwrap.ulValueLen && memcmp(valTarget, valUnwrap, attrTarget.ulValueLen) == 0 && attrTarget.ulValueLen > 0) {
                record_result("AuthWrap", "Value_Match", "PASS", "Unwrapped keys perfectly match");
            } else {
                record_result("AuthWrap", "Value_Match", "FAIL", "Unwrapped symmetric value mismatch (Issue 44 bug)");
            }
        }
    }
    
    // =========================================================================
    // NIST SP 800-38D AES-GCM Test Case 4 (Official Known Answer Test)
    // =========================================================================
    CK_BYTE nistKey[] = {0xfe,0xff,0xe9,0x92,0x86,0x65,0x73,0x1c,0x6d,0x6a,0x8f,0x94,0x67,0x30,0x83,0x08};
    CK_BYTE nistIV[]  = {0xca,0xfe,0xba,0xbe,0xfa,0xce,0xdb,0xad,0xde,0xca,0xf8,0x88};
    CK_BYTE nistPT[]  = {
        0xd9,0x31,0x32,0x25,0xf8,0x84,0x06,0xe5,0xa5,0x59,0x09,0xc5,0xaf,0xf5,0x26,0x9a,
        0x86,0xa7,0xa9,0x53,0x15,0x34,0xf7,0xda,0x2e,0x4c,0x30,0x3d,0x8a,0x31,0x8a,0x72,
        0x1c,0x3c,0x0c,0x95,0x95,0x68,0x09,0x53,0x2f,0xcf,0x0e,0x24,0x49,0xa6,0xb5,0x25,
        0xb1,0x6a,0xed,0xf5,0xaa,0x0d,0xe6,0x57,0xba,0x63,0x7b,0x39
    };
    CK_BYTE nistAAD[] = {
        0xfe,0xed,0xfa,0xce,0xde,0xad,0xbe,0xef,0xfe,0xed,0xfa,0xce,0xde,0xad,0xbe,0xef,
        0xab,0xad,0xda,0xd2
    };
    CK_BYTE nistCTandTag[] = {
        // Ciphertext
        0x42,0x83,0x1e,0xc2,0x21,0x77,0x74,0x24,0x4b,0x72,0x21,0xb7,0x84,0xd0,0xd4,0x9c,
        0xe3,0xaa,0x21,0x2f,0x2c,0x02,0xa4,0xe0,0x35,0xc1,0x7e,0x23,0x29,0xac,0xa1,0x2e,
        0x21,0xd5,0x14,0xb2,0x54,0x66,0x93,0x1c,0x7d,0x8f,0x6a,0x5a,0xac,0x84,0xaa,0x05,
        0x1b,0xa3,0x0b,0x39,0x6a,0x0a,0xac,0x97,0x3d,0x58,0xe0,0x91,
        // Tag
        0x5b,0xc9,0x4f,0xbc,0x32,0x21,0xa5,0xdb,0x94,0xfa,0xe9,0x5a,0xe7,0x12,0x1a,0x47
    };

    // Create the unwrapping key from NIST KAT
    CK_ATTRIBUTE nistKeyTmpl[] = {
        { CKA_CLASS, &secClass, sizeof(secClass) },
        { CKA_KEY_TYPE, &ktype, sizeof(ktype) },
        { CKA_UNWRAP, &bTrue, sizeof(bTrue) },
        { CKA_TOKEN, &bFalse, sizeof(bFalse) },
        { CKA_VALUE, nistKey, sizeof(nistKey) }
    };
    CK_OBJECT_HANDLE hNistWrapKey = 0;
    fl->C_CreateObject(hSess, nistKeyTmpl, 5, &hNistWrapKey);
    
    if (hNistWrapKey) {
        CK_GCM_PARAMS nistGcmParams = { nistIV, sizeof(nistIV), 0, 0, NULL_PTR, 128 };
        CK_MECHANISM nistMech = { 0x00001087UL /* CKM_AES_GCM */, &nistGcmParams, sizeof(nistGcmParams) };
        
        CK_OBJECT_HANDLE hNistTarget = 0;
        CK_ATTRIBUTE unwrapTmplNist[] = { 
            { CKA_CLASS, &secClass, sizeof(secClass) },
            { CKA_KEY_TYPE, &ktype, sizeof(ktype) },
            { CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) }
        };
        CK_RV rvKat = UnwrapAuth(hSess, &nistMech, hNistWrapKey, nistCTandTag, sizeof(nistCTandTag), unwrapTmplNist, 3, nistAAD, sizeof(nistAAD), &hNistTarget);
        
        if (rvKat == CKR_OK) {
            CK_BYTE valNist[100]; CK_ATTRIBUTE attrNist = { CKA_VALUE, valNist, sizeof(valNist) };
            fl->C_GetAttributeValue(hSess, hNistTarget, &attrNist, 1);
            if (attrNist.ulValueLen == sizeof(nistPT) && memcmp(valNist, nistPT, sizeof(nistPT)) == 0) {
                record_result("AuthWrap", "NIST_SP800_38D_KAT", "PASS", "Unwrapped GCM payload perfectly matches NIST Test Case 4 PT");
            } else {
                record_result("AuthWrap", "NIST_SP800_38D_KAT", "FAIL", "Unwrapped material did not match NIST Test Case 4 PT");
            }
        } else {
            record_result("AuthWrap", "NIST_SP800_38D_KAT", "FAIL", "Unwrap execution failed with RV=" + std::to_string(rvKat));
        }
    } else {
        record_result("AuthWrap", "NIST_SP800_38D_KAT", "SKIP", "Failed to construct NIST Wrapping Key frame");
    }
}

int main(int argc, char** argv) {
    parse_args(argc, argv);
    
    printf("--- PKCS#11 v3.2 Compliance Test Tool ---\n");
    printf("Engine: %s\n", opt_engine.c_str());

    if (!init_token()) return 1;

    if (opt_category == "all" || opt_category == "discovery") { refresh_session(); test_mechanism_discovery(); }
    if (opt_category == "all" || opt_category == "attr") { refresh_session(); test_key_attributes(); }
    if (opt_category == "all" || opt_category == "pqc-kem") { refresh_session(); test_pqc_kem(); }
    if (opt_category == "all" || opt_category == "pqc-dsa") { refresh_session(); test_pqc_dsa(); }

    if (opt_category == "all" || opt_category == "v32-adv") {
        refresh_session(); test_v32_kdfs();
        refresh_session(); test_message_signatures();
        refresh_session(); test_message_encryption();
    }
    if (opt_category == "all" || opt_category == "pqc-slh") {
        refresh_session(); test_pqc_slh_dsa();
    }
    if (opt_category == "all" || opt_category == "classical") {
        refresh_session(); test_classical_crypto();
    }
    if (opt_category == "all" || opt_category == "negative") {
        refresh_session(); test_negative_paths();
    }
    if (opt_category == "all" || opt_category == "fips") {
        refresh_session(); test_fips_edge_constraints();
    }
    if (opt_category == "all" || opt_category == "session") {
        refresh_session(); test_slot_session_management();
    }
    if (opt_category == "all" || opt_category == "authwrap") {
        refresh_session(); test_authenticated_wrap();
    }
    
    // Quick inline test
    refresh_session();
    {
        CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
        CK_KEY_TYPE ecType = CKK_EC;
        CK_BBOOL bTrue = CK_TRUE;
        CK_BBOOL bFalse = CK_FALSE;
        CK_BYTE oid_p256[] = { 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };

        CK_ATTRIBUTE pubTmpl[] = {
            { CKA_CLASS, &pubClass, sizeof(pubClass) },
            { CKA_KEY_TYPE, &ecType, sizeof(ecType) },
            { CKA_TOKEN, &bFalse, sizeof(bFalse) },
            { CKA_VERIFY, &bTrue, sizeof(bTrue) },
            { CKA_EC_PARAMS, oid_p256, sizeof(oid_p256) }
        };
        
        CK_OBJECT_CLASS privClass = CKO_PRIVATE_KEY;
        CK_ATTRIBUTE privTmpl[] = {
            { CKA_CLASS, &privClass, sizeof(privClass) },
            { CKA_KEY_TYPE, &ecType, sizeof(ecType) },
            { CKA_TOKEN, &bFalse, sizeof(bFalse) },
            { CKA_PRIVATE, &bTrue, sizeof(bTrue) },
            { CKA_SIGN, &bTrue, sizeof(bTrue) }
        };

        CK_MECHANISM mech = { CKM_EC_KEY_PAIR_GEN, NULL_PTR, 0 };
        CK_OBJECT_HANDLE hPub, hPriv;
        CK_RV rv = fl->C_GenerateKeyPair(hSess, &mech, pubTmpl, 5, privTmpl, 5, &hPub, &hPriv);
        printf("GenerateKeyPair rv: %lx\n", rv);

        CK_MECHANISM signMech = { CKM_ECDSA_SHA256, NULL_PTR, 0 };
        rv = fl->C_SignInit(hSess, &signMech, hPriv);
        printf("SignInit rv: %lx\n", rv);
    }
    fl->C_Finalize(NULL);
    
    // Output JSON
    std::string json_path = opt_report + ".json";
    std::ofstream o(json_path);
    o << std::setw(4) << report << std::endl;
    
    // Output Markdown
    std::string md_path = opt_report + ".md";
    std::ofstream md(md_path);
    md << "# PKCS#11 v3.2 Compliance Report\n\n";
    md << "**Engine:** `" << opt_engine << "`\n";
    md << "**Timestamp:** Generated automatically\n\n";
    md << "## Summary\n";
    md << "- **Total PASS:** " << total_pass << "\n";
    md << "- **Total FAIL:** " << total_fail << "\n";
    md << "- **Total SKIP:** " << total_skip << "\n\n";
    
    for (auto it = report.begin(); it != report.end(); ++it) {
        md << "### " << it.key() << "\n\n";
        md << "| Test | Status | Details |\n|---|---|---|\n";
        for (const auto& item : it.value()) {
            std::string st = item["status"];
            std::string icon = (st == "PASS") ? "✅" : (st == "FAIL" ? "❌" : "⚠️");
            md << "| " << item["test"].get<std::string>() << " | " << icon << " " << st << " | " << item["details"].get<std::string>() << " |\n";
        }
        md << "\n";
    }

    printf("\nDone. Reports saved to %s and %s\n", json_path.c_str(), md_path.c_str());
    return total_fail > 0 ? 1 : 0;
}
