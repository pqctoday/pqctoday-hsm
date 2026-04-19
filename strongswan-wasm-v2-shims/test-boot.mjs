// test-boot.mjs — Phase 1 Checkpoint: run library_init + library_deinit under Node.
//
// This is the whole point of the v2 rewrite: prove that the settings_parser
// signature mismatch (fixed in build-strongswan-wasm-v2.sh step 3.1) no longer
// crashes the WASM runtime at library_init → array_destroy_function.
//
// Success criterion: Module receives a "booted" event with no error.

import StrongswanV2 from './dist/strongswan-v2-boot.js'
import assert from 'node:assert'

const events = []
const mod = await StrongswanV2({
    onVpnEvent: (type, payload) => {
        events.push({ type, payload })
        console.log(`[event] ${type}: ${payload}`)
    },
})

console.log('Calling wasm_vpn_boot()...')
const bootRv = mod.ccall('wasm_vpn_boot', 'number', [], [])
console.log(`wasm_vpn_boot returned ${bootRv}`)

console.log('Calling wasm_vpn_shutdown()...')
const shutRv = mod.ccall('wasm_vpn_shutdown', 'number', [], [])
console.log(`wasm_vpn_shutdown returned ${shutRv}`)

// Assertions
assert.strictEqual(bootRv, 0, 'wasm_vpn_boot must return 0')
assert.strictEqual(shutRv, 0, 'wasm_vpn_shutdown must return 0')
assert.ok(events.some(e => e.type === 'booted'), 'must receive booted event')
assert.ok(!events.some(e => e.type === 'error'), 'must receive NO error events')

console.log('\n✓ Phase 1 Checkpoint 1 PASSED')
console.log('  library_init() no longer crashes at settings_parser_load_string')
process.exit(0)
