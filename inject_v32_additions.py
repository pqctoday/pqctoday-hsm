import re
with open("/Users/ericamador/antigravity/softhsmv3/p11_v32_compliance_test.cpp", "r") as f:
    orig = f.read()
with open("/Users/ericamador/antigravity/softhsmv3/compliance_additions.cpp", "r") as f:
    additions = f.read()

# Add test_message_encryption to additions
additions += """
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
        { CKA_TOKEN, &bFalse, sizeof(bFalse) }
    };
    CK_OBJECT_HANDLE hKey=0;
    CK_MECHANISM mech = { 0x00000108, NULL_PTR, 0 }; // CKM_AES_KEY_GEN
    
    if (fl->C_GenerateKey(hSess, &mech, tmpl, 5, &hKey) == CKR_OK) {
        // CKM_AES_GCM parameter handling:
        CK_BYTE iv[] = "123456789012";
        CK_GCM_PARAMS gcmParams = { iv, sizeof(iv)-1, 0, NULL_PTR, 0, NULL_PTR, 0, 16 };
        CK_MECHANISM encMech = { 0x0000010d7, &gcmParams, sizeof(gcmParams) }; // CKM_AES_GCM
        
        CK_RV rv = MsgEncInit(hSess, &encMech, hKey);
        record_result("MsgCrypt", "C_MessageEncryptInit", rv == CKR_OK ? "PASS" : "FAIL", "RV=" + std::to_string(rv));
        
        if (rv == CKR_OK) {
            rv = MsgEncBeg(hSess, NULL_PTR, 0);
            record_result("MsgCrypt", "C_EncryptMessageBegin", rv == CKR_OK ? "PASS" : "FAIL", "RV=" + std::to_string(rv));
        }
    }
}
"""

# Insert additions before main
if "test_v32_kdfs" not in orig:
    orig = orig.replace("int main(", additions + "\nint main(")
    
    # Also we need to call them in main if category matches
    call_block = """
        if (cat == "all" || cat == "v32-adv") {
            test_v32_kdfs();
            test_message_signatures();
            test_message_encryption();
        }
        if (cat == "all" || cat == "pqc-slh") {
            test_pqc_slh_dsa();
        }
    """
    orig = orig.replace("    test_key_attributes();", "    test_key_attributes();\n" + call_block)

with open("/Users/ericamador/antigravity/softhsmv3/p11_v32_compliance_test.cpp", "w") as f:
    f.write(orig)
