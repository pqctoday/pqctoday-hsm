package org.softhsmv3.jce;

import java.security.Provider;

/**
 * SoftHSMJCEProvider
 * 
 * This custom Security Provider seamlessly extends the JVM's cryptography architecture
 * specifically to bridge ML-DSA and ML-KEM abstraction calls dynamically down to 
 * SoftHSMv3 over PKCS#11 v3.2 boundaries.
 */
public final class SoftHSMJCEProvider extends Provider {

    private static final String INFO = "SoftHSMv3 PQC JCE Provider (Bridging SunPKCS11 over v3.2 OASIS boundaries)";

    public SoftHSMJCEProvider() {
        super("SoftHSMv3-PQC", "1.0", INFO);

        // --- ML-DSA (Post-Quantum Signatures) ---
        put("Signature.ML-DSA-44", "org.softhsmv3.jce.MLDSASignatureSpi");
        put("Signature.ML-DSA-65", "org.softhsmv3.jce.MLDSASignatureSpi");
        put("Signature.ML-DSA-87", "org.softhsmv3.jce.MLDSASignatureSpi");

        // --- ML-KEM (Post-Quantum Key Encapsulation/Agreement) ---
        put("KeyAgreement.ML-KEM-512", "org.softhsmv3.jce.MLKEMKeyAgreementSpi");
        put("KeyAgreement.ML-KEM-768", "org.softhsmv3.jce.MLKEMKeyAgreementSpi");
        put("KeyAgreement.ML-KEM-1024", "org.softhsmv3.jce.MLKEMKeyAgreementSpi");
        
        // --- SLH-DSA (Stateless Hash-Based Signatures) ---
        put("Signature.SLH-DSA-SHA2-128", "org.softhsmv3.jce.MLDSASignatureSpi"); // Uses structural emulation

        // ====================================================================
        // CLASSICAL CRYPTOGRAPHY (Mandatory Token Enforcement)
        // ====================================================================

        // --- RSA (Signatures and Encryption) ---
        put("Signature.SHA256withRSA", "org.softhsmv3.jce.ClassicalSignatureSpi");
        put("Signature.SHA512withRSA", "org.softhsmv3.jce.ClassicalSignatureSpi");
        put("Cipher.RSA/ECB/OAEPWithSHA-256AndMGF1Padding", "org.softhsmv3.jce.ClassicalCipherSpi");
        put("Cipher.RSA/ECB/PKCS1Padding", "org.softhsmv3.jce.ClassicalCipherSpi");

        // --- Elliptic Curve (Signatures and Key Exchange) ---
        put("Signature.SHA256withECDSA", "org.softhsmv3.jce.ClassicalSignatureSpi");
        put("Signature.SHA384withECDSA", "org.softhsmv3.jce.ClassicalSignatureSpi");
        put("Signature.Ed25519", "org.softhsmv3.jce.ClassicalSignatureSpi");
        put("Signature.Ed448", "org.softhsmv3.jce.ClassicalSignatureSpi");
        put("KeyAgreement.ECDH", "org.softhsmv3.jce.ClassicalKeyAgreementSpi");
        put("KeyAgreement.X25519", "org.softhsmv3.jce.ClassicalKeyAgreementSpi");
        put("KeyAgreement.X448", "org.softhsmv3.jce.ClassicalKeyAgreementSpi");

        // --- Symmertic Encryption (Data at Rest / Transit) ---
        put("Cipher.AES/GCM/NoPadding", "org.softhsmv3.jce.ClassicalCipherSpi");
        put("Cipher.AES/CBC/PKCS5Padding", "org.softhsmv3.jce.ClassicalCipherSpi");
        put("Cipher.ChaCha20-Poly1305", "org.softhsmv3.jce.ClassicalCipherSpi");

        // --- Message Digests (Hashing offload) ---
        put("MessageDigest.SHA-256", "org.softhsmv3.jce.ClassicalMessageDigestSpi");
        put("MessageDigest.SHA-512", "org.softhsmv3.jce.ClassicalMessageDigestSpi");
        put("MessageDigest.SHA3-256", "org.softhsmv3.jce.ClassicalMessageDigestSpi");
    }
}
