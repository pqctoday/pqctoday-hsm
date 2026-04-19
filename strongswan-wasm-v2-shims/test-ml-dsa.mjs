// test-ml-dsa.mjs — Phase 3b: full ML-DSA-65 sign/verify round-trip via
// softhsmv3 inside a WASM binary running under Node. Exercises the exact
// same HSM code path the native sandbox uses (C_GenerateKeyPair mech 0x1C,
// C_Sign/C_Verify mech 0x1D, with CKA_PARAMETER_SET=CKP_ML_DSA_65).

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

console.log('\nRunning ML-DSA-65 sign+verify round-trip...')
const sigLen = mod.ccall('wasm_vpn_ml_dsa_selftest', 'number', [], [])
console.log(`selftest returned signature length = ${sigLen}`)

mod.ccall('wasm_vpn_shutdown', 'number', [], [])

assert.ok(sigLen > 3000 && sigLen < 3400,
    `expected ML-DSA-65 signature ~3293 bytes, got ${sigLen}`)
assert.ok(events.some(e => e.type === 'ml_dsa_selftest'),
    'must receive ml_dsa_selftest event')

console.log('\n✓ Phase 3b PASSED: softhsmv3 ML-DSA-65 sign+verify works in WASM')
process.exit(0)
