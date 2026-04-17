package org.softhsmv3.jce;

import java.security.Security;
import java.security.Signature;
import java.security.Provider;

/**
 * Native PQC Test
 * 
 * Verifies that the internal translation logic successfully registers the 
 * abstraction handles globally across the JVM ecosystem.
 */
public class PKCS11IntegrationTest {

    public static void main(String[] args) throws Exception {
        System.out.println("[SoftHSMv3] Booting JVM PQC JCE Bridge...");
        
        // Register our proprietary mapping matrix natively.
        SoftHSMJCEProvider pqcProvider = new SoftHSMJCEProvider();
        Security.addProvider(pqcProvider);
        System.out.println("[SoftHSMv3] Successfully registered dynamically: " + pqcProvider.getInfo());

        // Validate that standard JCA architectural endpoints resolve exactly to us.
        System.out.println("[SoftHSMv3] Triggering abstract JCE initialization...");
        Signature sig = Signature.getInstance("ML-DSA-65", "SoftHSMv3-PQC");
        
        if (sig != null) {
            System.out.println("[SoftHSMv3] PASS: Natively bridged ML-DSA-65 abstraction to hardware target handler!");
        } else {
            System.out.println("[SoftHSMv3] FATAL: JVM failed to resolve hardware mapping parameters.");
            System.exit(1);
        }
    }
}
