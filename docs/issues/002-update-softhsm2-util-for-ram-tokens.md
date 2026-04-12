# Issue: Update Tooling / Utility Scripts for RAM Tokens

## Component
Tooling (`softhsm2-util` logic, PKCS#11 tooling proxy)

## Description
Since SoftHSMv3 operates identically to a RAM disk without file persistence, using typical commands like `softhsm2-util --init-token ...` immediately creates the token and deletes it as the script closes.

If we keep the RAM-only approach for extremely rapid CI/CD pipelines, we still need a way for humans to manage these keys and tokens without writing native C++ wrappers.

## Proposed Resolution
We should introduce an IPC socket-based configuration tool, or instruct users clearly via `p11-kit`.

1. **Option A (The Daemon Approach):** Distribute a systemd unit file and a generic daemon binary (`softhsm-server`) that permanently maps `libsofthsm2.so` in RAM and opens a local socket. `softhsm2-util` would be heavily rewritten to communicate via IPC to this daemon instead of using internal library `C_Initialize`.
2. **Option B (Configuration Injection):** Modify `C_Initialize` to immediately ingest a JSON or PEM blob specified by an environment variable like `SOFTHSMV3_BOOTSTRAP_STATE`. The CLI utility could simply output base64 JSON instead of writing to disk, allowing an ops user to inject the keys into their OpenSSL processes on boot dynamically.

## Impact
Providing a clear pathway to inject keys mitigates the ephemeral nature of the vault and saves operators dozens of hours configuring `p11-kit`.
