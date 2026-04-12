const crypto = require('crypto');

// Basic NIST SP 800-90A AES-256-CTR-DRBG (matching our C implementation)
class AES_256_CTR_DRBG {
    constructor(seed_hex) {
        if (seed_hex.length !== 96) throw new Error("Seed must be 48 bytes (96 hex chars)");
        const buf = Buffer.from(seed_hex, 'hex');
        this.Key = buf.subarray(0, 32); // first 32 bytes
        this.V = buf.subarray(32, 48);   // last 16 bytes
    }

    // update(provided_data)
    update(provided_data) {
        let temp = Buffer.alloc(48);
        for (let i = 0; i < 3; i++) {
            // Increment V (big-endian)
            for (let j = 15; j >= 0; j--) {
                this.V[j]++;
                if (this.V[j] !== 0) break;
            }
            // Encrypt V using Key
            const cipher = crypto.createCipheriv('aes-256-ecb', this.Key, null);
            cipher.setAutoPadding(false);
            const enc = cipher.update(this.V);
            enc.copy(temp, i * 16);
        }
        
        if (provided_data) {
            for (let i = 0; i < 48; i++) {
                temp[i] ^= provided_data[i];
            }
        }
        
        this.Key = temp.subarray(0, 32);
        this.V = temp.subarray(32, 48);
    }

    generate(out_len) {
        let out = Buffer.alloc(out_len);
        let temp = Buffer.alloc(Math.ceil(out_len / 16) * 16);
        let blocks = temp.length / 16;

        for (let i = 0; i < blocks; i++) {
            // Increment V (big-endian)
            for (let j = 15; j >= 0; j--) {
                this.V[j]++;
                if (this.V[j] !== 0) break;
            }
            const cipher = crypto.createCipheriv('aes-256-ecb', this.Key, null);
            cipher.setAutoPadding(false);
            const enc = cipher.update(this.V);
            enc.copy(temp, i * 16);
        }
        
        temp.copy(out, 0, 0, out_len);
        this.update(null);
        return out;
    }
}

const drbg = new AES_256_CTR_DRBG("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1");
console.log("32 byte output:", drbg.generate(32).toString('hex'));
