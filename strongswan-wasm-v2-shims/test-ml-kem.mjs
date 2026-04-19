// test-ml-kem.mjs — Phase 3c: ML-KEM-768 loopback via softhsmv3 in WASM.
// Proves the 10-bug-stack fix (pqctoday-hsm commit 236d9a4) carries into
// WASM. Two pkcs11_kem_t instances exchange pubkey / ciphertext inside
// the same WASM binary; if both derive the same 32-byte secret, the HSM
// ML-KEM path is functional.

import StrongswanV2 from './dist/strongswan-v2-boot.js'
import assert from 'node:assert'

const events = []
const mod = await StrongswanV2({
    onVpnEvent: (type, payload) => {
        events.push({ type, payload })
        console.log(`[event] ${type}: ${payload}`)
    },
})

mod.ccall('wasm_vpn_boot', 'number', [], [])

console.log('\nRunning ML-KEM-768 loopback via pkcs11_kem through softhsmv3...')
const ok = mod.ccall('wasm_vpn_ml_kem_selftest', 'number', [], [])
console.log(`selftest returned ${ok}`)

mod.ccall('wasm_vpn_shutdown', 'number', [], [])

assert.strictEqual(ok, 1, 'alice and bob must derive identical shared secrets')
console.log('\n✓ Phase 3c PASSED: softhsmv3 ML-KEM-768 encap+decap works in WASM')
process.exit(0)
