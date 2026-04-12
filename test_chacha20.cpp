#include <iostream>
#include <vector>
#include "cryptoki.h"

int main() {
    CK_RV rv;
    rv = C_Initialize(NULL_PTR);
    if (rv != CKR_OK) { std::cout << "Init failed: " << std::hex << rv << "\n"; return 1; }

    CK_SLOT_ID slots[10];
    CK_ULONG numSlots = 10;
    rv = C_GetSlotList(CK_TRUE, slots, &numSlots);
    if (rv != CKR_OK || numSlots == 0) { std::cout << "Slot failed: " << std::hex << rv << "\n"; return 1; }

    CK_SESSION_HANDLE hSession;
    rv = C_OpenSession(slots[0], CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession);
    if (rv != CKR_OK) { std::cout << "Session failed: " << std::hex << rv << "\n"; return 1; }

    // Use default SO/user PINs from standard test token: 1234
    rv = C_Login(hSession, CKU_USER, (CK_UTF8CHAR_PTR)"1234", 4);
    if (rv != CKR_OK) { std::cout << "Login failed: " << std::hex << rv << "\n"; }

    CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
    CK_KEY_TYPE keyType = CKK_CHACHA20;
    CK_BBOOL cfalse = CK_FALSE;
    CK_BBOOL ctrue = CK_TRUE;
    
    // 32-byte chacha key
    CK_BYTE keyVal[32] = {0};

    CK_ATTRIBUTE tpl[] = {
        {CKA_CLASS, &keyClass, sizeof(keyClass)},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_TOKEN, &cfalse, sizeof(cfalse)},
        {CKA_ENCRYPT, &ctrue, sizeof(ctrue)},
        {CKA_VALUE, keyVal, sizeof(keyVal)}
    };

    CK_OBJECT_HANDLE hKey;
    rv = C_CreateObject(hSession, tpl, 5, &hKey);
    std::cout << "CreateObject RV: " << std::hex << rv << "\n";

    C_CloseSession(hSession);
    C_Finalize(NULL_PTR);
    return 0;
}
