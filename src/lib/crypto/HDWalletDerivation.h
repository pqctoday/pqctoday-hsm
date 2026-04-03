/*
 * SoftHSMv3 HD Wallet Derivation (BIP32 / SLIP-0010)
 */

#ifndef _SOFTHSM_V3_HD_WALLET_DERIVATION_H
#define _SOFTHSM_V3_HD_WALLET_DERIVATION_H

#include "cryptoki.h"
#include "ByteString.h"
#include <string>

class HDWalletDerivation {
public:
    // Derives Master PrivKey and ChainCode from a generic seed
    static bool deriveMasterNode(const ByteString& seed, const std::string& curveOid, ByteString& outPrivKey, ByteString& outChainCode);

    // Derives Child PrivKey and ChainCode
    static bool deriveChildNode(const ByteString& parentPriv, const ByteString& parentChainCode, CK_ULONG index, bool hardened, const std::string& curveOid, ByteString& outPrivKey, ByteString& outChainCode);

private:
    static bool hmacSha512(const ByteString& key, const ByteString& data, ByteString& outMac);
};

#endif // !_SOFTHSM_V3_HD_WALLET_DERIVATION_H
