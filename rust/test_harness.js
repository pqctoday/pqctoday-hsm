const crypto = require('crypto');
const { SoftHsmRust } = require('./pkg/softhsmrustv3.js');

function runHarness() {
    console.log("-----------------------------------------");
    console.log("softhsmrustv3 Parity Integration Harness");
    console.log("-----------------------------------------");

    try {
        // 1. Initialize the new Rust WebAssembly module natively
        console.log("[*] Initializing SoftHsmRust in Node.js Engine...");
        const hsm = new SoftHsmRust();

        // 2. Initialize a Token
        console.log("[*] Initializing Slot 0...");
        const initSuccess = hsm.init_token(0, "1234", "MyRustToken");
        console.log(`[+] Slot 0 Initialized: ${initSuccess}`);

        // 3. Generate a 256-bit AES Key
        console.log("\n[*] Generating 256-bit AES Key natively in WASM...");
        const keyId = hsm.generate_aes_key(32);
        console.log(`[+] Success! Key Handle Generated: ${keyId}`);

        // 4. Test Encryption Payload
        const plaintextStr = "This is a highly confidential 5G payload.";
        const plaintextBytes = new TextEncoder().encode(plaintextStr);

        // Generate a random 16-byte IV for AES-CTR using Node's native crypto
        const ivBytes = crypto.randomBytes(16);

        console.log(`\n[*] Executing C_Encrypt (AES-CTR 256) inside WASM...`);
        console.log(`    - Plaintext: "${plaintextStr}"`);

        const cipherBytes = hsm.aes_ctr_encrypt(keyId, ivBytes, plaintextBytes);
        console.log(`[+] Encryption Success! Ciphertext bytes length: ${cipherBytes.length}`);

        // 5. Test Decryption Parity
        console.log(`\n[*] Executing C_Decrypt (AES-CTR 256) inside WASM...`);
        const decryptedBytes = hsm.aes_ctr_decrypt(keyId, ivBytes, cipherBytes);
        const decryptedStr = new TextDecoder().decode(decryptedBytes);

        console.log(`[+] Decryption Success!`);
        console.log(`    - Recovered Plaintext: "${decryptedStr}"`);

        if (plaintextStr === decryptedStr) {
            console.log("\n✅ PARITY TEST PASSED: RustCrypto AES-CTR loop accurately preserved memory.");
        } else {
            console.error("\n❌ PARITY TEST FAILED!");
        }

    } catch (e) {
        console.error("\n❌ FATAL HARNESS EXCEPTION:", e);
    }
}

runHarness();
