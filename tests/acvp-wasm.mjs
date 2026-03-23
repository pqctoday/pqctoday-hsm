/**
 * acvp-wasm.mjs — ACVP Validation Suite for SoftHSMv3 WASM
 *
 * Runs 20 ACVP test suites against C++ and/or Rust WASM engines via raw PKCS#11 calls.
 * Direct port of pqc-timeline-app's HsmAcvpTesting.tsx test logic.
 *
 * Usage:
 *   node tests/acvp-wasm.mjs                  # default: C++ engine
 *   node tests/acvp-wasm.mjs --engine=rust    # Rust engine only
 *   node tests/acvp-wasm.mjs --engine=both    # C++ then Rust, side-by-side
 *   node tests/acvp-wasm.mjs --verbose        # show ACVP vector values
 *   node tests/acvp-wasm.mjs --json           # JSON output
 * 
 * Target: v0.3.0 Release Validation
 */
import { fileURLToPath } from 'url'
import path from 'path'
import { readFileSync } from 'fs'
import {
  hexToBytes,
  bytesToHex,
  initializeEngine,
  finalizeEngine,
  getMechanismSet,
  importAESKey,
  importHMACKey,
  importRSAPublicKey,
  importECPublicKey,
  importMLDSAPublicKey,
  importMLKEMPrivateKey,
  generateAESKey,
  generateMLDSAKeyPair,
  generateMLKEMKeyPair,
  generateSLHDSAKeyPair,
  generateEdDSAKeyPair,
  aesDecrypt,
  aesCtrDecrypt,
  hmacVerify,
  rsaVerify,
  ecdsaVerify,
  verifyBytes,
  sign,
  verify,
  slhdsaSign,
  slhdsaVerify,
  eddsaSign,
  eddsaVerify,
  digest,
  encapsulate,
  decapsulate,
  extractKeyValue,
  wrapKey,
  unwrapKey,
  pbkdf2,
  hkdf,
  loadEngine,
  CK,
} from './helpers.mjs'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const verbose = process.argv.includes('--verbose')
const jsonOut = process.argv.includes('--json')
const engineArg = process.argv.find((a) => a.startsWith('--engine='))
const engineMode = engineArg ? engineArg.split('=')[1] : 'cpp'

// ── Load ACVP Vectors ───────────────────────────────────────────────────────
const loadJson = (name) => JSON.parse(readFileSync(path.join(__dirname, 'acvp', name), 'utf8'))
const mlkemVec = loadJson('mlkem_test.json')
const mldsaVec = loadJson('mldsa_test.json')
const aesGcmVec = loadJson('aesgcm_test.json')
const hmacVec = loadJson('hmac_test.json')
const rsaPssVec = loadJson('rsapss_test.json')
const ecdsaVec = loadJson('ecdsa_test.json')
const sha256Vec = loadJson('sha256_test.json')
const aesCbcVec = loadJson('aescbc_test.json')
const aesCtrVec = loadJson('aesctr_test.json')
const hmac384Vec = loadJson('hmac_sha384_test.json')
const hmac512Vec = loadJson('hmac_sha512_test.json')
const ecdsaP384Vec = loadJson('ecdsa_p384_test.json')
const aesKwVec = loadJson('aeskw_test.json')

// ── Helpers ─────────────────────────────────────────────────────────────────
function arrEq(a, b) {
  return a.length === b.length && a.every((v, i) => v === b[i])
}

// ── Run full ACVP suite against one engine ──────────────────────────────────
async function runSuite(engineName) {
  const results = []
  let pass = 0, fail = 0, skip = 0

  function addResult(id, algo, testCase, status, details) {
    results.push({ id, algo, testCase, status, details })
    if (status === 'PASS') pass++
    else if (status === 'FAIL') fail++
    else skip++
    if (!jsonOut) {
      const icon = status === 'PASS' ? '\u2713' : status === 'FAIL' ? '\u2717' : '\u2298'
      console.log(`  ${icon}  ${algo} \u2014 ${testCase}: ${status}`)
      if (verbose && details) console.log(`       ${details}`)
    }
  }

  if (!jsonOut) console.log(`[ACVP] Loading ${engineName.toUpperCase()} engine...`)
  const M = await loadEngine(engineName)
  if (!jsonOut) console.log(`[ACVP] ${engineName.toUpperCase()} engine loaded.\n`)

  const { hSession, slotId } = initializeEngine(M)
  const mechs = getMechanismSet(M, slotId)

  try {
    // ── 1. AES-GCM-256 Decrypt KAT (SP 800-38D) ───────────────────────────
    if (mechs.size > 0 && !mechs.has(CK.CKM_AES_GCM)) {
      addResult('aesgcm', 'AES-GCM-256', 'Decrypt KAT', 'SKIP', 'mechanism not supported')
    } else {
      const tv = aesGcmVec.testGroups[0].tests[0]
      try {
        const keyBytes = hexToBytes(tv.key)
        const ivBytes = hexToBytes(tv.iv)
        const ctBytes = hexToBytes(tv.ct)
        const tagBytes = hexToBytes(tv.tag)
        const expectedPt = hexToBytes(tv.pt)
        const aesH = importAESKey(M, hSession, keyBytes, { encrypt: false, decrypt: true, wrap: false, unwrap: false, derive: false })
        const ctWithTag = new Uint8Array(ctBytes.length + tagBytes.length)
        ctWithTag.set(ctBytes)
        ctWithTag.set(tagBytes, ctBytes.length)
        const pt = aesDecrypt(M, hSession, aesH, ctWithTag, ivBytes, 'gcm')
        const ok = arrEq(pt, expectedPt)
        addResult('aesgcm', 'AES-GCM-256', 'Decrypt KAT', ok ? 'PASS' : 'FAIL', `PT[${pt.length}B]: ${bytesToHex(pt, 16)}`)
      } catch (e) {
        addResult('aesgcm', 'AES-GCM-256', 'Decrypt KAT', 'FAIL', e.message)
      }
    }

    // ── 2. HMAC-SHA256 Verify KAT (RFC 4231) ──────────────────────────────
    if (mechs.size > 0 && !mechs.has(CK.CKM_SHA256_HMAC)) {
      addResult('hmac256', 'HMAC-SHA256', 'Verify KAT', 'SKIP', 'mechanism not supported')
    } else {
      const tv = hmacVec.testGroups[0].tests[0]
      try {
        const h = importHMACKey(M, hSession, hexToBytes(tv.key), { sign: false, verify: true })
        const ok = hmacVerify(M, hSession, h, hexToBytes(tv.msg), hexToBytes(tv.mac))
        addResult('hmac256', 'HMAC-SHA256', 'Verify KAT', ok ? 'PASS' : 'FAIL', `MAC[${tv.mac.length / 2}B]`)
      } catch (e) {
        addResult('hmac256', 'HMAC-SHA256', 'Verify KAT', 'FAIL', e.message)
      }
    }

    // ── 3. RSA-PSS-2048 SigVer KAT (FIPS 186-5) ──────────────────────────
    if (mechs.size > 0 && !mechs.has(CK.CKM_SHA256_RSA_PKCS_PSS)) {
      addResult('rsapss', 'RSA-PSS-2048', 'SigVer KAT', 'SKIP', 'mechanism not supported')
    } else {
      const tv = rsaPssVec.testGroups[0].tests[0]
      try {
        const h = importRSAPublicKey(M, hSession, hexToBytes(tv.n), hexToBytes(tv.e), { encrypt: false })
        const ok = rsaVerify(M, hSession, h, tv.msg, hexToBytes(tv.signature))
        addResult('rsapss', 'RSA-PSS-2048', 'SigVer KAT', ok ? 'PASS' : 'FAIL', `sig[${tv.signature.length / 2}B]`)
      } catch (e) {
        addResult('rsapss', 'RSA-PSS-2048', 'SigVer KAT', 'FAIL', e.message)
      }
    }

    // ── 4. ECDSA P-256 SigVer KAT (FIPS 186-5) ───────────────────────────
    if (mechs.size > 0 && !mechs.has(CK.CKM_ECDSA_SHA256)) {
      addResult('ecdsa256', 'ECDSA P-256', 'SigVer KAT', 'SKIP', 'mechanism not supported')
    } else {
      const tv = ecdsaVec.testGroups[0].tests[0]
      try {
        const h = importECPublicKey(M, hSession, hexToBytes(tv.qx), hexToBytes(tv.qy), 'P-256')
        const rB = hexToBytes(tv.r)
        const sB = hexToBytes(tv.s)
        const sig = new Uint8Array(rB.length + sB.length)
        sig.set(rB)
        sig.set(sB, rB.length)
        const ok = ecdsaVerify(M, hSession, h, tv.msg, sig)
        addResult('ecdsa256', 'ECDSA P-256', 'SigVer KAT', ok ? 'PASS' : 'FAIL', `sig[${sig.length}B]`)
      } catch (e) {
        addResult('ecdsa256', 'ECDSA P-256', 'SigVer KAT', 'FAIL', e.message)
      }
    }

    // ── 5. ML-DSA SigVer KAT (FIPS 204) — 3 variants ─────────────────────
    for (const group of mldsaVec.testGroups) {
      const test = group.tests[0]
      const algo = group.parameterSet
      const v = parseInt(algo.split('-')[2])
      try {
        const h = importMLDSAPublicKey(M, hSession, v, hexToBytes(test.pk))
        const ok = verifyBytes(M, hSession, h, hexToBytes(test.msg), hexToBytes(test.sig))
        addResult(`mldsa-sv-${v}`, algo, 'SigVer KAT', ok ? 'PASS' : 'FAIL', `sig[${test.sig.length / 2}B]`)
      } catch (e) {
        addResult(`mldsa-sv-${v}`, algo, 'SigVer KAT', 'FAIL', e.message)
      }
    }

    // ── 6. ML-DSA Functional Sign+Verify (FIPS 204) — 3 variants ─────────
    for (const v of [44, 65, 87]) {
      const algo = `ML-DSA-${v}`
      try {
        const { pubHandle, privHandle } = generateMLDSAKeyPair(M, hSession, v)
        const sig = sign(M, hSession, privHandle, 'ACVP NIST PQC test')
        const ok = verify(M, hSession, pubHandle, 'ACVP NIST PQC test', sig)
        addResult(`mldsa-f-${v}`, algo, 'Functional Sign+Verify', ok ? 'PASS' : 'FAIL', `sig[${sig.length}B]`)
      } catch (e) {
        addResult(`mldsa-f-${v}`, algo, 'Functional Sign+Verify', 'FAIL', e.message)
      }
    }

    // ── 7. ML-KEM Decapsulation KAT (FIPS 203) — 3 variants ──────────────
    for (const group of mlkemVec.testGroups) {
      const test = group.tests[0]
      const algo = group.parameterSet
      const v = parseInt(algo.split('-')[2]) || 768
      try {
        const h = importMLKEMPrivateKey(M, hSession, v, hexToBytes(test.sk))
        const ssHandle = decapsulate(M, hSession, h, hexToBytes(test.ct), v)
        const ss = extractKeyValue(M, hSession, ssHandle)
        const expected = hexToBytes(test.ss)
        const ok = arrEq(ss, expected)
        addResult(`mlkem-d-${v}`, algo, 'Decapsulate KAT', ok ? 'PASS' : 'FAIL', `SS[${ss.length}B]: ${bytesToHex(ss, 16)}`)
      } catch (e) {
        addResult(`mlkem-d-${v}`, algo, 'Decapsulate KAT', 'FAIL', e.message)
      }
    }

    // ── 8. ML-KEM Encap+Decap Round-Trip (FIPS 203) — 3 variants ─────────
    for (const v of [512, 768, 1024]) {
      const algo = `ML-KEM-${v}`
      try {
        const { pubHandle, privHandle } = generateMLKEMKeyPair(M, hSession, v)
        const { ciphertextBytes, secretHandle: encH } = encapsulate(M, hSession, pubHandle, v)
        const encSS = extractKeyValue(M, hSession, encH)
        const decH = decapsulate(M, hSession, privHandle, ciphertextBytes, v)
        const decSS = extractKeyValue(M, hSession, decH)
        const ok = arrEq(encSS, decSS)
        addResult(`mlkem-rt-${v}`, algo, 'Encap+Decap Round-Trip', ok ? 'PASS' : 'FAIL', `SS[${encSS.length}B] ct=${ciphertextBytes.length}B`)
      } catch (e) {
        addResult(`mlkem-rt-${v}`, algo, 'Encap+Decap Round-Trip', 'FAIL', e.message)
      }
    }

    // ── 9. SLH-DSA Functional Sign+Verify (FIPS 205) — 2 param sets ──────
    for (const { ckp, name } of [
      { ckp: CK.CKP_SLH_DSA_SHA2_128S, name: 'SLH-DSA-SHA2-128s' },
      { ckp: CK.CKP_SLH_DSA_SHAKE_256F, name: 'SLH-DSA-SHAKE-256f' },
    ]) {
      try {
        const { pubHandle, privHandle } = generateSLHDSAKeyPair(M, hSession, ckp)
        const sig = slhdsaSign(M, hSession, privHandle, 'ACVP SLH-DSA functional test')
        const ok = slhdsaVerify(M, hSession, pubHandle, 'ACVP SLH-DSA functional test', sig)
        addResult(`slhdsa-${name}`, name, 'Functional Sign+Verify', ok ? 'PASS' : 'FAIL', `sig[${sig.length}B]`)
      } catch (e) {
        addResult(`slhdsa-${name}`, name, 'Functional Sign+Verify', 'FAIL', e.message)
      }
    }

    // ── 10. SHA-256 Digest KAT (FIPS 180-4) — 3 test cases ───────────────
    if (mechs.size > 0 && !mechs.has(CK.CKM_SHA256)) {
      addResult('sha256', 'SHA-256', 'Digest KAT', 'SKIP', 'mechanism not supported')
    } else {
      for (const test of sha256Vec.testGroups[0].tests) {
        try {
          const d = digest(M, hSession, hexToBytes(test.msg))
          const expected = hexToBytes(test.md)
          const ok = arrEq(d, expected)
          addResult(`sha256-${test.tcId}`, 'SHA-256', `Digest KAT tc=${test.tcId}`, ok ? 'PASS' : 'FAIL', `MD[${d.length}B]: ${bytesToHex(d, 16)}`)
        } catch (e) {
          addResult(`sha256-${test.tcId}`, 'SHA-256', `Digest KAT tc=${test.tcId}`, 'FAIL', e.message)
        }
      }
    }

    // ── 11. AES-CBC-256 Decrypt KAT (SP 800-38A) ─────────────────────────
    if (mechs.size > 0 && !mechs.has(CK.CKM_AES_CBC_PAD)) {
      addResult('aescbc', 'AES-CBC-256', 'Decrypt KAT', 'SKIP', 'mechanism not supported')
    } else {
      const tv = aesCbcVec.testGroups[0].tests[0]
      try {
        const h = importAESKey(M, hSession, hexToBytes(tv.key), { encrypt: false, decrypt: true, wrap: false, unwrap: false, derive: false })
        const pt = aesDecrypt(M, hSession, h, hexToBytes(tv.ct), hexToBytes(tv.iv), 'cbc')
        const ok = arrEq(pt, hexToBytes(tv.pt))
        addResult('aescbc', 'AES-CBC-256', 'Decrypt KAT', ok ? 'PASS' : 'FAIL', `PT[${pt.length}B]: ${bytesToHex(pt, 16)}`)
      } catch (e) {
        addResult('aescbc', 'AES-CBC-256', 'Decrypt KAT', 'FAIL', e.message)
      }
    }

    // ── 12. AES-CTR-256 Decrypt KAT (SP 800-38A) ─────────────────────────
    if (mechs.size > 0 && !mechs.has(CK.CKM_AES_CTR)) {
      addResult('aesctr', 'AES-CTR-256', 'Decrypt KAT', 'SKIP', 'mechanism not supported')
    } else {
      const tv = aesCtrVec.testGroups[0].tests[0]
      const counterBits = aesCtrVec.testGroups[0].counterBits
      try {
        const h = importAESKey(M, hSession, hexToBytes(tv.key), { encrypt: false, decrypt: true, wrap: false, unwrap: false, derive: false })
        const pt = aesCtrDecrypt(M, hSession, h, hexToBytes(tv.iv), counterBits, hexToBytes(tv.ct))
        const ok = arrEq(pt, hexToBytes(tv.pt))
        addResult('aesctr', 'AES-CTR-256', 'Decrypt KAT', ok ? 'PASS' : 'FAIL', `PT[${pt.length}B]: ${bytesToHex(pt, 16)}`)
      } catch (e) {
        addResult('aesctr', 'AES-CTR-256', 'Decrypt KAT', 'FAIL', e.message)
      }
    }

    // ── 13. HMAC-SHA384 Verify KAT ────────────────────────────────────────
    if (mechs.size > 0 && !mechs.has(CK.CKM_SHA384_HMAC)) {
      addResult('hmac384', 'HMAC-SHA384', 'Verify KAT', 'SKIP', 'mechanism not supported')
    } else {
      const tv = hmac384Vec.testGroups[0].tests[0]
      try {
        const h = importHMACKey(M, hSession, hexToBytes(tv.key), { sign: false, verify: true })
        const ok = hmacVerify(M, hSession, h, hexToBytes(tv.msg), hexToBytes(tv.mac), CK.CKM_SHA384_HMAC)
        addResult('hmac384', 'HMAC-SHA384', 'Verify KAT', ok ? 'PASS' : 'FAIL', `MAC[${tv.mac.length / 2}B]`)
      } catch (e) {
        addResult('hmac384', 'HMAC-SHA384', 'Verify KAT', 'FAIL', e.message)
      }
    }

    // ── 14. HMAC-SHA512 Verify KAT ────────────────────────────────────────
    if (mechs.size > 0 && !mechs.has(CK.CKM_SHA512_HMAC)) {
      addResult('hmac512', 'HMAC-SHA512', 'Verify KAT', 'SKIP', 'mechanism not supported')
    } else {
      const tv = hmac512Vec.testGroups[0].tests[0]
      try {
        const h = importHMACKey(M, hSession, hexToBytes(tv.key), { sign: false, verify: true })
        const ok = hmacVerify(M, hSession, h, hexToBytes(tv.msg), hexToBytes(tv.mac), CK.CKM_SHA512_HMAC)
        addResult('hmac512', 'HMAC-SHA512', 'Verify KAT', ok ? 'PASS' : 'FAIL', `MAC[${tv.mac.length / 2}B]`)
      } catch (e) {
        addResult('hmac512', 'HMAC-SHA512', 'Verify KAT', 'FAIL', e.message)
      }
    }

    // ── 15. ECDSA P-384 SigVer KAT (FIPS 186-5) ─────────────────────────
    if (mechs.size > 0 && !mechs.has(CK.CKM_ECDSA_SHA384)) {
      addResult('ecdsa384', 'ECDSA P-384', 'SigVer KAT', 'SKIP', 'mechanism not supported')
    } else {
      const tv = ecdsaP384Vec.testGroups[0].tests[0]
      try {
        const h = importECPublicKey(M, hSession, hexToBytes(tv.qx), hexToBytes(tv.qy), 'P-384')
        const rB = hexToBytes(tv.r)
        const sB = hexToBytes(tv.s)
        const sig = new Uint8Array(rB.length + sB.length)
        sig.set(rB)
        sig.set(sB, rB.length)
        const ok = ecdsaVerify(M, hSession, h, tv.msg, sig, CK.CKM_ECDSA_SHA384)
        addResult('ecdsa384', 'ECDSA P-384', 'SigVer KAT', ok ? 'PASS' : 'FAIL', `sig[${sig.length}B]`)
      } catch (e) {
        addResult('ecdsa384', 'ECDSA P-384', 'SigVer KAT', 'FAIL', e.message)
      }
    }

    // ── 16. EdDSA Ed25519 Functional Sign+Verify (RFC 8032) ───────────────
    if (mechs.size > 0 && !mechs.has(CK.CKM_EDDSA)) {
      addResult('eddsa', 'EdDSA Ed25519', 'Functional Sign+Verify', 'SKIP', 'mechanism not supported')
    } else {
      try {
        const { pubHandle, privHandle } = generateEdDSAKeyPair(M, hSession, 'Ed25519')
        const msg = 'ACVP EdDSA Ed25519 functional round-trip'
        const sig = eddsaSign(M, hSession, privHandle, msg)
        const ok = eddsaVerify(M, hSession, pubHandle, msg, sig)
        addResult('eddsa', 'EdDSA Ed25519', 'Functional Sign+Verify', ok ? 'PASS' : 'FAIL', `sig[${sig.length}B]`)
      } catch (e) {
        addResult('eddsa', 'EdDSA Ed25519', 'Functional Sign+Verify', 'FAIL', e.message)
      }
    }

    // ── 17. PBKDF2 Functional Derivation (PKCS#5 v2.1) ───────────────────
    if (mechs.size > 0 && !mechs.has(CK.CKM_PKCS5_PBKD2)) {
      addResult('pbkdf2', 'PBKDF2-HMAC-SHA512', 'Functional Derivation', 'SKIP', 'mechanism not supported')
    } else {
      try {
        const password = new TextEncoder().encode('ACVP-PBKDF2-test-password')
        const salt = new TextEncoder().encode('ACVP-salt-value')
        const dk1 = pbkdf2(M, hSession, password, salt, 4096, 32)
        const dk2 = pbkdf2(M, hSession, password, salt, 4096, 32)
        const ok = arrEq(dk1, dk2) && dk1.length === 32
        addResult('pbkdf2', 'PBKDF2-HMAC-SHA512', 'Functional Derivation', ok ? 'PASS' : 'FAIL', `DK[${dk1.length}B]: ${bytesToHex(dk1, 16)}`)
      } catch (e) {
        addResult('pbkdf2', 'PBKDF2-HMAC-SHA512', 'Functional Derivation', 'FAIL', e.message)
      }
    }

    // ── 18. HKDF Functional Derivation (RFC 5869) ────────────────────────
    {
      try {
        const ikmH = generateAESKey(M, hSession, 256, {
          encrypt: false, decrypt: false, wrap: false, unwrap: false, derive: true, extractable: false,
        })
        const salt = new TextEncoder().encode('ACVP-HKDF-salt')
        const info = new TextEncoder().encode('ACVP-HKDF-info')
        const okm1 = hkdf(M, hSession, ikmH, CK.CKM_SHA256, true, true, salt, info, 32)
        const okm2 = hkdf(M, hSession, ikmH, CK.CKM_SHA256, true, true, salt, info, 32)
        const ok = arrEq(okm1, okm2) && okm1.length === 32
        addResult('hkdf', 'HKDF-SHA256', 'Functional Derivation', ok ? 'PASS' : 'FAIL', `OKM[${okm1.length}B]: ${bytesToHex(okm1, 16)}`)
      } catch (e) {
        addResult('hkdf', 'HKDF-SHA256', 'Functional Derivation', 'FAIL', e.message)
      }
    }

    // ── 19. AES-KW Wrap KAT (RFC 3394) ───────────────────────────────────
    if (mechs.size > 0 && !mechs.has(CK.CKM_AES_KEY_WRAP)) {
      addResult('aeskw', 'AES-KW-256', 'Wrap KAT', 'SKIP', 'mechanism not supported')
    } else {
      const tv = aesKwVec.testGroups[0].tests[0]
      try {
        const kekH = importAESKey(M, hSession, hexToBytes(tv.kek), {
          encrypt: false, decrypt: false, wrap: true, unwrap: false, derive: false,
        })
        const targetH = importAESKey(M, hSession, hexToBytes(tv.keyData), {
          encrypt: false, decrypt: false, wrap: false, unwrap: false, derive: false, extractable: true,
        })
        const wrapped = wrapKey(M, hSession, CK.CKM_AES_KEY_WRAP, kekH, targetH)
        const expected = hexToBytes(tv.wrapped)
        const ok = arrEq(wrapped, expected)
        addResult('aeskw', 'AES-KW-256', 'Wrap KAT', ok ? 'PASS' : 'FAIL', `Wrapped[${wrapped.length}B]: ${bytesToHex(wrapped, 16)}`)
      } catch (e) {
        addResult('aeskw', 'AES-KW-256', 'Wrap KAT', 'FAIL', e.message)
      }
    }

    // ── 20. AES-KWP Wrap+Unwrap Round-Trip (RFC 5649) ────────────────────
    if (mechs.size > 0 && !mechs.has(CK.CKM_AES_KEY_WRAP_KWP)) {
      addResult('aeskwp', 'AES-KWP-256', 'Wrap+Unwrap Round-Trip', 'SKIP', 'mechanism not supported')
    } else {
      try {
        const kekH = generateAESKey(M, hSession, 256, {
          encrypt: false, decrypt: false, wrap: true, unwrap: true, derive: false, extractable: false,
        })
        const targetH = generateAESKey(M, hSession, 256, {
          encrypt: false, decrypt: false, wrap: false, unwrap: false, derive: false, extractable: true,
        })
        const origVal = extractKeyValue(M, hSession, targetH)
        const wrapped = wrapKey(M, hSession, CK.CKM_AES_KEY_WRAP_KWP, kekH, targetH)
        const unwrappedH = unwrapKey(M, hSession, CK.CKM_AES_KEY_WRAP_KWP, kekH, wrapped, [
          { type: CK.CKA_CLASS, value: CK.CKO_SECRET_KEY },
          { type: CK.CKA_KEY_TYPE, value: CK.CKK_AES },
          { type: CK.CKA_ENCRYPT, value: true },
          { type: CK.CKA_DECRYPT, value: true },
          { type: CK.CKA_TOKEN, value: false },
          { type: CK.CKA_EXTRACTABLE, value: true },
          { type: CK.CKA_SENSITIVE, value: false }, // PKCS#11 v3.2 §4.3 — mandatory for secret keys; FALSE since EXTRACTABLE=TRUE
        ])
        const unwrappedVal = extractKeyValue(M, hSession, unwrappedH)
        const ok = arrEq(origVal, unwrappedVal)
        addResult('aeskwp', 'AES-KWP-256', 'Wrap+Unwrap Round-Trip', ok ? 'PASS' : 'FAIL', `key=${origVal.length}B wrapped=${wrapped.length}B`)
      } catch (e) {
        addResult('aeskwp', 'AES-KWP-256', 'Wrap+Unwrap Round-Trip', 'FAIL', e.message)
      }
    }
  } finally {
    finalizeEngine(M, hSession)
  }

  return { engine: engineName, pass, fail, skip, total: results.length, results }
}

// ── Main: run engine(s) ─────────────────────────────────────────────────────
const engines = engineMode === 'both' ? ['cpp', 'rust'] : [engineMode]
const allRuns = []
let anyFail = false

for (const eng of engines) {
  if (!jsonOut && engines.length > 1) {
    console.log(`\n${'='.repeat(50)}`)
    console.log(`  Engine: ${eng.toUpperCase()}`)
    console.log(`${'='.repeat(50)}\n`)
  }
  const run = await runSuite(eng)
  allRuns.push(run)
  if (run.fail > 0) anyFail = true

  if (!jsonOut) {
    console.log(`\n${'='.repeat(42)}`)
    console.log(`  ${eng.toUpperCase()} ACVP: ${run.pass} PASS, ${run.fail} FAIL, ${run.skip} SKIP (${run.total} total)`)
    console.log(`${'='.repeat(42)}\n`)
  }
}

// ── Side-by-side comparison for --engine=both ────────────────────────────────
if (engines.length > 1 && !jsonOut) {
  console.log('='.repeat(70))
  console.log('  GAP ANALYSIS: C++ vs Rust')
  console.log('='.repeat(70))
  const cppRes = allRuns[0].results
  const rustRes = allRuns[1].results
  const allIds = new Set([...cppRes.map((r) => r.id), ...rustRes.map((r) => r.id)])
  const cppMap = Object.fromEntries(cppRes.map((r) => [r.id, r]))
  const rustMap = Object.fromEntries(rustRes.map((r) => [r.id, r]))
  let gapCount = 0
  const pad = (s, n) => s.slice(0, n).padEnd(n)
  console.log(`  ${pad('Test', 30)} ${pad('C++', 8)} ${pad('Rust', 8)} Gap?`)
  console.log(`  ${'-'.repeat(30)} ${'-'.repeat(8)} ${'-'.repeat(8)} ----`)
  for (const id of allIds) {
    const c = cppMap[id]
    const r = rustMap[id]
    const cStatus = c ? c.status : 'ABSENT'
    const rStatus = r ? r.status : 'ABSENT'
    const gap = cStatus !== rStatus
    if (gap) gapCount++
    const label = c ? `${c.algo} ${c.testCase}` : r ? `${r.algo} ${r.testCase}` : id
    const marker = gap ? ' <-- GAP' : ''
    console.log(`  ${pad(label, 30)} ${pad(cStatus, 8)} ${pad(rStatus, 8)}${marker}`)
  }
  console.log(`\n  Total gaps: ${gapCount} / ${allIds.size} tests`)
  console.log('='.repeat(70) + '\n')
}

if (jsonOut) {
  console.log(JSON.stringify(engines.length > 1 ? allRuns : allRuns[0], null, 2))
}

process.exit(anyFail ? 1 : 0)
