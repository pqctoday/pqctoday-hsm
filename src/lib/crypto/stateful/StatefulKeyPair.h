#ifndef _SOFTHSM_V3_STATEFULKEYPAIR_H
#define _SOFTHSM_V3_STATEFULKEYPAIR_H

#include "AsymmetricKeyPair.h"

class StatefulKeyPair : public AsymmetricKeyPair {
public:
    virtual PublicKey* getPublicKey() { return nullptr; }
    virtual const PublicKey* getConstPublicKey() const { return nullptr; }
    virtual PrivateKey* getPrivateKey() { return nullptr; }
    virtual const PrivateKey* getConstPrivateKey() const { return nullptr; }
    virtual ByteString serialise() const { return ByteString(); }
};

#endif
