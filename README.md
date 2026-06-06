# SPAKE2-Java

SPAKE2-Java is an ADB-focused Java implementation of the SPAKE2-over-Edwards25519 exchange used by Android wireless debugging pairing.

The compatibility target is the SPAKE25519 behavior used by AOSP/BoringSSL in the `adb` pairing-auth flow. This repository is not maintained as a general-purpose PAKE library, or a general cryptographic toolkit.

## What This Library Covers

This library provides the SPAKE2 core needed by ADB wireless debugging pairing:

- role-specific SPAKE2 message generation and processing
- ADB-compatible participant-name handling
- password-material processing compatible with AOSP/BoringSSL pairing-auth semantics
- transcript hashing compatible with the ADB SPAKE25519 exchange

The surrounding ADB client remains responsible for:

- TLS setup and TLS exporter bytes
- pairing-code collection and password-material construction
- HKDF/AES-GCM peer-info wrapping
- `ADB_DEVICE_GUID` validation
- mDNS discovery
- reconnect and transport state management

## Compatibility

The supported product scope is ADB wireless debugging pairing used by `Kadb` only. It does not guarantee compatibility for any other purpose.

The default random-number generator path uses `SecureRandom.getInstanceStrong()` through reflection when the runtime provides it. On Android API 23-25 it falls back to `new SecureRandom()` to avoid direct linkage to APIs added after the supported minimum Android runtime.

For ADB pairing, participant names include a trailing NUL byte:

- client/Alice: `adb pair client\u0000`
- server/Bob: `adb pair server\u0000`

The trailing NUL is part of the ADB compatibility surface. Do not remove it when using this library for ADB pairing.

The implementation intentionally follows AOSP/BoringSSL behavior for the ADB path, including details that may look unusual in isolation. In particular, the code preserves raw scalar bit 255 after the ADB cofactor shift and accepts the AOSP-compatible "identity after unmasking" path instead of adding an extra Java-only rejection.

## Important Limits

**This project is provided on an AS IS basis for the narrow ADB pairing scope described above.**

It does not claim:

- general-purpose PAKE suitability
- JVM-level constant-time execution
- exhaustive malformed-input coverage over every possible Edwards25519 encoding
- compatibility with non-ADB SPAKE2 variants
- correctness for use of dependency signing APIs outside the ADB pairing path

Production code in this repository must not use `ed25519-elisabeth` signing APIs. They are outside the ADB-only product path and are guarded by tests.

Network-controlled peer messages are copied before dependency point/public-key wrappers and before transcript hashing. This avoids byte-array aliasing from mutable caller-owned input.

## Audit-Relevant Fixes

The current audited branch addresses the ADB-relevant issues found during review:

- High-bit scalar preservation: the post-cofactor scalar path no longer uses `Scalar.fromBits()` in a way that clears bit 255 and collapses some valid reduced scalars to the wrong result.
- AOSP/BoringSSL password scalar behavior: the ADB password-scalar hardening logic is aligned with the upstream pairing-auth semantics.
- Peer transcript stability: peer messages are copied before dependency decoding and transcript hashing.
- AOSP-compatible peer handling: the Java-only rejection after unmasking was removed so the transcript behavior matches BoringSSL/AOSP.
- Release guardrails: tests reject production reintroduction of unsafe ADB-path APIs such as `Scalar.fromBits()` in the protected scalar path and `ed25519-elisabeth` signing imports.

These fixes are scoped to ADB SPAKE2 compatibility. They are not a statement that the library has been proven safe for unrelated protocols.

## Evidence Available

The non-device verification work used external oracles rather than Kadb as the source of truth:

- pinned BoringSSL SPAKE25519 behavior
- pinned AOSP adb pairing-auth behavior
- deterministic BoringSSL oracle vectors committed under `src/test/resources/oracle-vectors/`
- 512 valid transcript fuzz vectors committed under `src/test/resources/oracle-vectors/`
- independent Java/JUnit replay of the oracle vectors
- strict Gradle dependency verification
- wrapper-free JUnit verification as a secondary check

The current core test suite contains 29 JUnit tests for the SPAKE25519 path. Recent verification passed with Gradle 9.5.1 using strict dependency verification:

```powershell
.\gradlew.bat --no-daemon --dependency-verification strict test --rerun-tasks --stacktrace
```

This is strong regression evidence for the targeted ADB pairing core. It is not a mathematical proof and does not replace real-device end-to-end testing of the complete ADB client stack.

## Usage

Import `com.flyfish233.crypto.spake2.*`.

In the example below, `buildAdbPairingPasswordMaterial()` and `readPeerSpakeMessage()` represent the surrounding ADB pairing-auth layer. They are not provided by this library.

```java
byte[] clientName = "adb pair client\u0000".getBytes(StandardCharsets.UTF_8);
byte[] serverName = "adb pair server\u0000".getBytes(StandardCharsets.UTF_8);
byte[] passwordMaterial = buildAdbPairingPasswordMaterial(); // pair code bytes + TLS exporter bytes
byte[] peerMessage = readPeerSpakeMessage(); // the 32-byte SPAKE2 message received from the peer

try (Spake2Context client = new Spake2Context(Spake2Role.Alice, clientName, serverName)) {
    byte[] clientMessage = client.generateMessage(passwordMaterial);
    sendClientSpakeMessage(clientMessage);

    byte[] sharedKey = client.processMessage(peerMessage);
    useSharedKeyForAdbPairingAuth(sharedKey);
}
```

Use a fresh `Spake2Context` for each pairing attempt. The context wipes sensitive state after the exchange completes.

## Verification

For the normal Gradle test path:

```powershell
.\gradlew.bat test
```

For the stricter release-style gate:

```powershell
.\gradlew.bat --no-daemon --dependency-verification strict test --rerun-tasks --stacktrace
```

Oracle vectors are stored in:

- `src/test/resources/oracle-vectors/boringssl_spake2_vectors.txt`
- `src/test/resources/oracle-vectors/boringssl_spake2_fuzz_vectors.txt`

Local audit logs, temporary oracles, and machine-specific notes are intentionally ignored under local-only documentation and `tmp/` paths.

## Credits

- ED25519 implementation is a modified and simplified version of the [EdDSA-Java](https://github.com/str4d/ed25519-java) library (CC0 license).
- SPAKE2 implementation is based on BoringSSL's SPAKE25519 implementation used by Android/AOSP adb pairing (MIT license).
- A few methods are modified from [Curve25519-java](https://github.com/signalapp/curve25519-java) (GPL-3.0 license).

## License

Copyright 2021 Muntashir Al-Islam 

Modified Flyfish233 from fork [76b3aa](https://github.com/MuntashirAkon/spake2-java/commit/76b3aadce7f2b4d62b94032610e24206002373d5) 

Licensed under the GPLv3: https://www.gnu.org/licenses/gpl-3.0.html
