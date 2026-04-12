import re
import sys

def main():
    path = "/Users/ericamador/antigravity/softhsmv3/p11_v32_compliance_test.cpp"
    with open(path, "r") as f:
        content = f.read()

    kem_new = """void test_pqc_kem() {
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
"""
    
    dsa_new = """#ifndef CKM_HASH_ML_DSA_SHA512
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
        
        for (int j = 0; j < 3; j++) {
            std::string runName = n + "_" + signNames[j];
            CK_MECHANISM signMech = { signMechs[j], NULL_PTR, 0 };
            
            rv = fl->C_SignInit(hSess, &signMech, hPriv);
            if (isSkipRv((CK_RV)rv)) {  // SoftHSM doesn't have isSkipRv inside the tool, use a direct check:
                if (rv == CKR_MECHANISM_INVALID || rv == CKR_FUNCTION_NOT_SUPPORTED) {
                    record_result("DSA", "C_SignInit_" + runName, "SKIP", "Mechanism not implemented");
                    continue;
                }
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
"""
    
    # regex match the old function bodies
    
    kem_pattern = re.compile(r'void test_pqc_kem\(\) \{.*?\n\}\n', re.DOTALL)
    content = kem_pattern.sub(kem_new + "\n", content)
    
    dsa_pattern = re.compile(r'void test_pqc_dsa\(\) \{.*?\n\}\n', re.DOTALL)
    content = dsa_pattern.sub(dsa_new + "\n", content)

    with open(path, "w") as f:
        f.write(content)

if __name__ == "__main__":
    main()
