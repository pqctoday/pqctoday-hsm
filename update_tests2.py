import re

path = "/Users/ericamador/antigravity/softhsmv3/p11_v32_compliance_test.cpp"
with open(path, "r") as f:
    content = f.read()

# Fix the syntax error first
content = content.replace("if (rv == CKR_MECHANISM_INVALID || rv == CKR_FUNCTION_NOT_SUPPORTED) {\n                if (rv == CKR_MECHANISM_INVALID || rv == CKR_FUNCTION_NOT_SUPPORTED) {", "if (rv == CKR_MECHANISM_INVALID || rv == CKR_FUNCTION_NOT_SUPPORTED) {")

# We want to add a helper function `check_key_profile(std::string cat, std::string runName, CK_OBJECT_HANDLE hPub, CK_OBJECT_HANDLE hPriv, bool isKEM)`
# and then call it right after `C_GenerateKeyPair` in both loops.

helper = """
void check_key_profile(std::string cat, std::string runName, CK_OBJECT_HANDLE hPub, CK_OBJECT_HANDLE hPriv, bool isKEM) {
    CK_BBOOL bTrue = CK_TRUE, bFalse = CK_FALSE;

    // G-ATTR1: CKA_VALUE extraction on public key
    CK_BYTE pubVal[2000]; CK_ATTRIBUTE attrPub = { CKA_VALUE, pubVal, sizeof(pubVal) };
    CK_RV rv = fl->C_GetAttributeValue(hSess, hPub, &attrPub, 1);
    if (rv == CKR_OK && attrPub.ulValueLen > 0) {
        record_result("Attributes", runName + "_CKA_VALUE_Pub", "PASS", "§1.21 G-ATTR1 check");
    } else {
        record_result("Attributes", runName + "_CKA_VALUE_Pub", "FAIL", "§1.21 G-ATTR1 failure");
    }

    // SPKI: CKA_PUBLIC_KEY_INFO on public key
    CK_BYTE spkiPub[2000]; CK_ATTRIBUTE attrSpkiP = { CKA_PUBLIC_KEY_INFO, spkiPub, sizeof(spkiPub) };
    rv = fl->C_GetAttributeValue(hSess, hPub, &attrSpkiP, 1);
    if (rv == CKR_OK && attrSpkiP.ulValueLen > 0) {
        record_result("Attributes", runName + "_CKA_PUBLIC_KEY_INFO_Pub", "PASS", "SPKI exposed");
    } else {
        record_result("Attributes", runName + "_CKA_PUBLIC_KEY_INFO_Pub", "FAIL", "SPKI missing on public key");
    }

    // SPKI: CKA_PUBLIC_KEY_INFO on private key
    CK_BYTE spkiPriv[2000]; CK_ATTRIBUTE attrSpkiPr = { CKA_PUBLIC_KEY_INFO, spkiPriv, sizeof(spkiPriv) };
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
"""

if "check_key_profile(" not in content:
    content = content.replace("void test_pqc_kem()", helper + "\nvoid test_pqc_kem()")

kem_call = """        record_result("KEM", "Generate_ML_KEM_" + n, "PASS", "Gen ML-KEM-" + n);
        check_key_profile("Attributes", "ML_KEM_" + n, hPub, hPriv, true);"""
content = content.replace("record_result(\"KEM\", \"Generate_ML_KEM_\" + n, \"PASS\", \"Gen ML-KEM-\" + n);", kem_call)

dsa_call = """        record_result("DSA", "Generate_ML_DSA_" + n, "PASS", "Gen ML-DSA-" + n);
        check_key_profile("Attributes", "ML_DSA_" + n, hPub, hPriv, false);"""
content = content.replace("record_result(\"DSA\", \"Generate_ML_DSA_\" + n, \"PASS\", \"Gen ML-DSA-\" + n);", dsa_call)

with open(path, "w") as f:
    f.write(content)
