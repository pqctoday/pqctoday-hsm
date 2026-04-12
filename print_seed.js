const crypto = require('crypto');
class AES_256_CTR_DRBG {
    constructor(seed_hex) {
        const buf = Buffer.from(seed_hex, 'hex');
        this.Key = buf.subarray(0, 32);
        this.V = buf.subarray(32, 48);
    }
    update(provided_data) {
        let temp = Buffer.alloc(48);
        for (let i = 0; i < 3; i++) {
            for (let j = 15; j >= 0; j--) {
                this.V[j]++;
                if (this.V[j] !== 0) break;
            }
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
const kat_drbg = new AES_256_CTR_DRBG("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1");
kat_drbg.update(null); // WAIT. Does NIST CTR-DRBG init do an update first? Let's check `test_kat_parity.js`. 
// Actually I'll just copy `test_kat_parity.js` DRBG exactly.
