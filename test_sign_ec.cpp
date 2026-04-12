#include <iostream>
#include <vector>
#include "cryptoki.h"
#include <dlfcn.h>
#include <cstring>

using namespace std;

int main(int argc, char** argv) {
    void* handle = dlopen("./build/src/lib/libsofthsmv3.dylib", RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
        cerr << "Failed to load library: " << dlerror() << endl;
        return 1;
    }

    CK_C_GetFunctionList getFuncList = (CK_C_GetFunctionList)dlsym(handle, "C_GetFunctionList");
    if (!getFuncList) return 1;

    CK_FUNCTION_LIST_PTR p11 = nullptr;
    getFuncList(&p11);

    CK_RV init_rv = p11->C_Initialize(NULL);
    cout << "Init rv: " << hex << init_rv << endl;

    CK_SESSION_HANDLE hSession;
    CK_RV rv_open = p11->C_OpenSession(1, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &hSession);
    cout << "Open rv: " << hex << rv_open << endl;
    
    // Default PIN for slot 1 is 1234
    CK_UTF8CHAR pin[] = "1234";
    CK_RV rv_login = p11->C_Login(hSession, CKU_USER, pin, 4);
    cout << "Login rv: " << hex << rv_login << endl;

    CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
    CK_KEY_TYPE ecType = CKK_EC;
    CK_BBOOL bTrue = CK_TRUE;
    CK_BBOOL bFalse = CK_FALSE;
    CK_BYTE oid_p256[] = { 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };

    CK_ATTRIBUTE pubTpl[] = {
        { CKA_CLASS, &pubClass, sizeof(pubClass) },
        { CKA_KEY_TYPE, &ecType, sizeof(ecType) },
        { CKA_TOKEN, &bFalse, sizeof(bFalse) },
        { CKA_VERIFY, &bTrue, sizeof(bTrue) },
        { CKA_EC_PARAMS, oid_p256, sizeof(oid_p256) }
    };
    
    CK_OBJECT_CLASS privClass = CKO_PRIVATE_KEY;
    CK_ATTRIBUTE privTpl[] = {
        { CKA_CLASS, &privClass, sizeof(privClass) },
        { CKA_KEY_TYPE, &ecType, sizeof(ecType) },
        { CKA_TOKEN, &bFalse, sizeof(bFalse) },
        { CKA_SIGN, &bTrue, sizeof(bTrue) }
    };

    CK_MECHANISM mech = { CKM_EC_KEY_PAIR_GEN, NULL, 0 };
    CK_OBJECT_HANDLE hPub, hPriv;
    CK_RV rv = p11->C_GenerateKeyPair(hSession, &mech, pubTpl, 5, privTpl, 4, &hPub, &hPriv);
    cout << "Generate rv: " << hex << rv << endl;

    if (rv == CKR_OK) {
        CK_MECHANISM signMech = { CKM_ECDSA_SHA256, NULL, 0 };
        rv = p11->C_SignInit(hSession, &signMech, hPriv);
        cout << "SignInit rv: " << hex << rv << endl;
    }

    p11->C_Finalize(NULL);
    return 0;
}
