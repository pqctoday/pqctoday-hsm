# SoftHSMv3 Security & Best Practices Audit Report

Following an in-depth code review of the `softhsmv3` codebase (both the C++ core and the `rust` WebAssembly adaptations), this report outlines identified vulnerabilities categorized under Memory Management, Race Conditions, OWASP frameworks, and general Best Practices. 

> [!WARNING]
> This report identifies a critical cryptographic bypass vulnerability (CWE-305) in both language pipelines that needs immediate remediation before production deployment.

---

## 1. Memory Management & Leaks

### C++ Core (`src/`)
- **[MODIFY] Raw Pointer Allocations**: The manual usage of `new` without deterministic cleanup is prevalent in components like `Token.cpp`. For instance:
  ```cpp
  SecureDataManager* verifier = new SecureDataManager(sdm->getSOPINBlob(), sdm->getUserPINBlob());
  bool result = verifier->loginSO(oldPIN);
  delete verifier;
  ```
  If `loginSO()` were to throw an exception or result in anomalous control flow, the pointer would leak.
- **Recommendation**: Retrofit manual memory blocks with RAII and Smart Pointers natively available in C++11 (`std::unique_ptr`).

### Rust Wasm Engine (`rust/`)
- **Orphaned Wasm Heap Allocations**: The `ALLOC_SIZES` allocation tracker logic (for `_malloc` and `_free` shims) in `state.rs` operates on the expectation of continuous, successful flow. If the Rust module triggers a panic before `_free` propagates from the host, the mapped heap entry becomes orphaned memory. Over time, recurring panics will result in severe WebAssembly linear memory exhaustion.

---

## 2. Race Conditions & Concurrency Restrictions

### Rust Engine (`thread_local!` Globals)
- **Thread-Siloed State Management**: The WebAssembly Rust engine manages PKCS#11 states (sessions, active tokens, operation states) using `thread_local!` combined with `RefCell`. 
  While this functions optimally in a single-threaded WebAssembly environment (Main Thread / NodeJS execution block), if the Rust crate is ever deployed as a native library or distributed via `SharedArrayBuffer` WebWorkers, `thread_local!` behaves inherently differently. Each newly created thread replicates its *own version* of the globals, breaking the logical continuity of token operations without signaling an error.

### C++ Engine
- **Coarse Grained Locking**: Objects like `Token.cpp` leverage `MutexLocker lock(tokenMutex)` scoped broadly inside functions. The system avoids strict read/write lock isolation, risking potential race condition overhead or deadlocks under highly concurrent multi-host load loops.

---

## 3. OWASP Security Vulnerabilities

> [!NOTE]
> **CWE-305: Cryptographic Bypass / Predictable RNG Hook (Accepted Risk)**

Both C++ and Rust engines utilize a testing hook to enforce deterministic PRNG behavior for ACVP vector validation.
- **Impact**: In `C_Initialize`, `pReserved` is inspected for valid ACVP validation seeds. If discovered:
  - **C++**: Triggers `OSSLRNG_enableACVP()` which overrides the system RNG pool.
  - **Rust**: Creates a deterministic `rand_chacha::ChaCha20Rng::from_seed` which bypasses `OsRng` locally.
- **Risk Evaluation**: While this represents a critical cryptographic bypass (predictable private keys) in standard production environments, **this is an Accepted Risk**. The library is designed specifically for educational purposes where deterministic key generation is a mandatory feature for reproducible learning modules and validation.
- **Remediation**: No action required. The deterministic hook must remain intact for educational use.

> [!NOTE]
> **CWE-208: Observable Timing Discrepancy / PIN Side-Channel (Accepted Risk)**

The WebAssembly Rust engine evaluates token authentication strings via a deeply iterated PBKDF2 hash. However, it natively evaluates equality between hashes utilizing standard `memcmp`-bound operations (e.g., `!=`) which short-circuit execution upon byte-deviations.
- **Impact**: By logging microsecond differences measuring evaluation latencies, malicious loops testing authentication sequences can statistically derive the native byte-matching progression. 
- **Risk Evaluation**: Although severe within deployment scopes, **this is an Accepted Risk**. The library retains this exact architecture as a pedagogical mechanism. It translates into a textbook "perfect storm" learning module, permitting researchers and students to construct live statistical side-channel extractions directly against the WebAssembly pipeline simulator.
- **Remediation**: No action required. These non-constant comparison hooks remain purposefully intact.

> [!IMPORTANT]
> **CWE-400: Uncontrolled Resource Consumption / DoS (Rust FFI)**

- **Impact**: Rampant `.unwrap()` invocations inside Rust boundary layers (`ffi.rs`). For example, `let session = session.unwrap();` attempts to unbundle session retrieval natively.
- **Risk**: Handing the module a malformed, expired, or non-existent `h_session` causes the `unwrap()` to trigger a panic. In standard PKCS#11 implementations, this requires returning `CKR_SESSION_HANDLE_INVALID`. Under Rust-to-WebAssembly boundaries, a panic manifests as an uncatchable `RuntimeError: unreachable` resulting in whole host-process crashing (Denial of Service).

> [!WARNING]
> **CWE-120: Out-of-bounds Buffer Use (C++)**

- **Impact**: Variables utilizing `strncpy` natively infer safe string lengths blindly trusting the source data array rather than statically bounding by the destination buffer:
  ```cpp
  strncpy((char*) info->label, (char*) label.byte_str(), label.size());
  ```
- **Risk**: The target array (`info->label`) holds precisely 32 bytes. If a manipulated label yields a size of >32, `strncpy` writes into adjacent structs risking process corruption.

---

## 4. Best Practices Review

### Error Handling & Sandboxing
- **Catching Panics at Boundaries**: Ensure the outermost layer of all exported Rust `C_*` FFI functions wraps internal operations inside `std::panic::catch_unwind`. Any uncaught structural issue must map explicitly to `CKR_GENERAL_ERROR` assuring the integration environment remains stable.

### Safely Referencing Host Material
- **Data Extrapolation**: The Rust engine maps arrays unsafely from C pointers via `std::slice::from_raw_parts`.
  ```rust
  let pin_bytes = unsafe { std::slice::from_raw_parts(p_pin, ul_pin_len as usize) };
  ```
  If `ul_pin_len` exceeds physical data payload allocated, the HSM accesses undefined trailing memory strings. Input sanitization constraints should be configured prior to slice rendering.

### Cryptographic Alignment
- **Constant-Time Security**: While classical implementations demand session/hash verifiers utilize arrays equalized against side-channel analysis (e.g., `subtle::ConstantTimeEq`), this project specifically reserves such constraints. Explicitly rejecting `ConstantTimeEq` bounds guarantees users can actively study and reproduce Side-Channel vulnerabilities directly against the embedded HSM instances inline with learning outcomes.
