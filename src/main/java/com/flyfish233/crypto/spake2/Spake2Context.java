/*
 * Copyright (C) 2021 Muntashir Al-Islam
 * Modified 2025 Flyfish233
 *
 * Licensed according to the LICENSE file in this repository.
 */

package com.flyfish233.crypto.spake2;

import cafe.cryptography.curve25519.CompressedEdwardsY;
import cafe.cryptography.curve25519.Constants;
import cafe.cryptography.curve25519.EdwardsPoint;
import cafe.cryptography.curve25519.InvalidEncodingException;
import cafe.cryptography.ed25519.Ed25519PublicKey;

import javax.security.auth.Destroyable;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Mutable holder for the state necessary to perform a single SPAKE2 password-authenticated key exchange.
 *
 * <p>The context is not thread-safe and is intended to be used by a single participant for the lifetime of one
 * protocol run. Instances must be destroyed (or closed) after use to minimise the time sensitive material stays in
 * memory.</p>
 */
@SuppressWarnings("unused")
public class Spake2Context implements Destroyable, AutoCloseable {
    /**
     * Maximum SPAKE2 message size in bytes. Messages are encoded Edwards25519 points and are always 32 bytes long.
     */
    public static final int MAX_MSG_SIZE = 32;  // fixed for ed25519
    /**
     * Maximum derived key size in bytes. The final KDF output is the SHA-512 digest and therefore 64 bytes long.
     */
    public static final int MAX_KEY_SIZE = 64;
    /**
     * Maximum participant name size in bytes.
     */
    public static final int MAX_NAME_SIZE = 4096;      // 4 KiB
    /**
     * Maximum password size in bytes accepted by this implementation.
     */
    public static final int MAX_PASSWORD_SIZE = 65536; // 64 KiB
    private static final byte[] M_POINT_ENCODED = HexUtils.hexToBytes("5ada7e4bf6ddd9adb6626d32131c6b5c51a1e347a3478f53cfcf441b88eed12e");
    private static final byte[] N_POINT_ENCODED = HexUtils.hexToBytes("10e3df0ae37d8e7a99b5fe74b44672103dbddcbd06af680d71329a11693bc778");

    private static final EdwardsPoint LIB_M;
    private static final EdwardsPoint LIB_N;
    private static final String HASH_ALGORITHM = "SHA-512";

    static {
        try {
            LIB_M = new CompressedEdwardsY(M_POINT_ENCODED).decompress();
            LIB_N = new CompressedEdwardsY(N_POINT_ENCODED).decompress();
        } catch (InvalidEncodingException e) {
            throw new ExceptionInInitializerError(e);
        }
    }
    private final byte[] myName;
    private final byte[] theirName;
    private final Spake2Role myRole;
    private final byte[] privateKey = new byte[32];
    private final byte[] myMsg = new byte[32];
    private final byte[] passwordScalar = new byte[32];
    private final byte[] passwordHash = new byte[64];
    /**
     * Randomness source that drives ephemeral key generation and other random values required by the protocol.
     */
    private final SecureRandom secureRandom; // 可注入随机源

    private State state;
    private boolean isDestroyed = false;

    /**
     * Creates a new SPAKE2 context using the default secure random number generator.
     *
     * @param myRole    role of this participant (Alice or Bob)
     * @param myName    UTF-8 encoded name (or identifier) of this participant
     * @param theirName UTF-8 encoded name (or identifier) of the remote participant
     * @throws IllegalArgumentException if any argument is invalid
     */
    public Spake2Context(Spake2Role myRole,
                         final byte[] myName,
                         final byte[] theirName) {
        this(myRole, myName, theirName, null);
    }

    /**
     * Creates a new SPAKE2 context.
     *
     * <p>The context holds all mutable protocol state for a single SPAKE2 exchange. The constructor clones the
     * participant identifiers to ensure subsequent mutations of the caller provided arrays do not influence protocol
     * behaviour.</p>
     *
     * @param myRole    role of this participant (Alice or Bob)
     * @param myName    name of this participant
     * @param theirName name of the other participant
     * @param rng       secure random number generator. If {@code null}, a default secure RNG will be used.
     * @throws IllegalArgumentException if any argument is invalid
     */
    public Spake2Context(Spake2Role myRole,
                         final byte[] myName,
                         final byte[] theirName,
                         final SecureRandom rng) {
        if (myRole == null) throw new IllegalArgumentException("Role must not be null.");
        if (myName == null || theirName == null) {
            throw new IllegalArgumentException("Participant names must not be null.");
        }
        if (myName.length > MAX_NAME_SIZE || theirName.length > MAX_NAME_SIZE) {
            throw new IllegalArgumentException("Participant name too large.");
        }
        this.myRole = myRole;
        this.myName = myName.clone();
        this.theirName = theirName.clone();
        this.state = State.Init;
        this.secureRandom = rng != null ? rng : SecureRandomHolder.INSTANCE;
    }

    /**
     * Multiplies {@code n} by eight by performing a three bit left shift.
     *
     * <p>The SPAKE2 construction requires all scalars to be a multiple of the cofactor (eight). Shifting a reduced,
     * 32-byte scalar by three bits matches BoringSSL's implementation and guarantees the result is congruent to the
     * original value multiplied by eight modulo the curve order, so no additional modular reduction is necessary.</p>
     *
     * @param n 32 byte little-endian scalar value
     */
    private static void leftShift3(byte[] n) {
        int carry = 0;
        for (int i = 0; i < 32; i++) {
            int next_carry = (byte) ((n[i] & 0xFF) >>> 5);
            n[i] = (byte) ((n[i] << 3) | carry);
            carry = next_carry;
        }
    }

    private static void updateWithLengthPrefix(MessageDigest sha, final byte[] data, int len) {
        byte[] len_le = new byte[8];
        long v = len & 0xFFFFFFFFL;
        for (int i = 0; i < 8; ++i) {
            len_le[i] = (byte) (v & 0xFF);
            v >>>= 8;
        }
        sha.update(len_le);
        sha.update(data, 0, len);
    }

    // Package private for testing
    /**
     * Computes the SHA-512 digest of the supplied byte array.
     *
     * @param bytes input to hash
     * @return 64 byte SHA-512 digest
     * @throws IllegalArgumentException if SHA-512 is not supported by the runtime
     */
    static byte[] getHash(byte[] bytes) throws IllegalArgumentException {
        MessageDigest md = newSha512Digest();
        md.reset();
        return md.digest(bytes);
    }

    /**
     * Returns the role of the local participant.
     *
     * @return the local participant role
     */
    public Spake2Role getMyRole() {
        return myRole;
    }

    /**
     * Returns the encoded SPAKE2 message generated for the local participant.
     *
     * @return a defensive copy of the local participant's message
     */
    public byte[] getMyMsg() {
        return myMsg.clone();
    }

    /**
     * Returns the identifier of the local participant.
     *
     * @return a defensive copy of the local participant's name
     */
    public byte[] getMyName() {
        return myName.clone();
    }

    /**
     * Returns the identifier of the remote participant.
     *
     * @return a defensive copy of the remote participant's name
     */
    public byte[] getTheirName() {
        return theirName.clone();
    }

    @Override
    public boolean isDestroyed() {
        return isDestroyed;
    }

    @Override
    public void destroy() {
        if (isDestroyed) {
            return;
        }
        isDestroyed = true;
        wipeSensitiveState();
    }

    @Override
    public void close() {
        destroy();
    }

    /**
     * Generates the local SPAKE2 message using the provided shared password.
     *
     * @param password shared password
     * @return a message of size {@link #MAX_MSG_SIZE}
     * @throws IllegalArgumentException if the password is invalid or SHA-512 is unavailable
     * @throws IllegalStateException    if the message has already been generated
     */
    public byte[] generateMessage(final byte[] password) throws IllegalArgumentException, IllegalStateException {
        if (password == null || password.length == 0) {
            throw new IllegalArgumentException("Invalid password input.");
        }
        if (password.length > MAX_PASSWORD_SIZE) {
            throw new IllegalArgumentException("Password too large.");
        }
        byte[] privateKey = new byte[64];
        secureRandom.nextBytes(privateKey);
        try {
            return generateMessage(password, privateKey);
        } finally {
            Arrays.fill(privateKey, (byte) 0);
        }
    }

    // Package private method for testing purposes
    byte[] generateMessage(final byte[] password, byte[] privateKey) throws IllegalArgumentException, IllegalStateException {
        if (password == null || password.length == 0) {
            throw new IllegalArgumentException("Invalid password input.");
        }
        if (password.length > MAX_PASSWORD_SIZE) {
            throw new IllegalArgumentException("Password too large.");
        }
        if (privateKey == null || privateKey.length != 64) {
            throw new IllegalArgumentException("Invalid private key input.");
        }
        if (isDestroyed) {
            throw new IllegalStateException("The context was destroyed.");
        }
        if (this.state != State.Init) {
            throw new IllegalStateException("Invalid state: " + this.state);
        }

        byte[] reducedPrivate = cafe.cryptography.curve25519.Scalar.fromBytesModOrderWide(privateKey).toByteArray();
        try {
            leftShift3(reducedPrivate);
            System.arraycopy(reducedPrivate, 0, this.privateKey, 0, this.privateKey.length);

            final cafe.cryptography.curve25519.Scalar nativePrivateScalar =
                    cafe.cryptography.curve25519.Scalar.fromBits(this.privateKey);
            final EdwardsPoint nativeP = Constants.ED25519_BASEPOINT.multiply(nativePrivateScalar);

            byte[] passwordTmp = getHash(password); // 64 bytes
            try {
                System.arraycopy(passwordTmp, 0, this.passwordHash, 0, this.passwordHash.length);
                byte[] reduced = cafe.cryptography.curve25519.Scalar.fromBytesModOrderWide(passwordTmp).toByteArray();
                try {
                    System.arraycopy(reduced, 0, this.passwordScalar, 0, this.passwordScalar.length);
                } finally {
                    Arrays.fill(reduced, (byte) 0);
                }
            } finally {
                Arrays.fill(passwordTmp, (byte) 0);
            }

            EdwardsPoint nativeMaskBase = this.myRole == Spake2Role.Alice ? LIB_M : LIB_N;
            cafe.cryptography.curve25519.Scalar nativePasswordScalar =
                    cafe.cryptography.curve25519.Scalar.fromBytesModOrder(this.passwordScalar);
            EdwardsPoint nativeMask = nativeMaskBase.multiply(nativePasswordScalar);
            EdwardsPoint nativePStar = nativeP.add(nativeMask);

            byte[] encoded = nativePStar.compress().toByteArray();
            try {
                try {
                    Ed25519PublicKey.fromByteArray(encoded);
                } catch (InvalidEncodingException e) {
                    throw new IllegalStateException("Generated point cannot be encoded properly", e);
                }
                System.arraycopy(encoded, 0, this.myMsg, 0, this.myMsg.length);
                this.state = State.MsgGenerated;
                return this.myMsg.clone();
            } finally {
                Arrays.fill(encoded, (byte) 0);
            }
        } finally {
            Arrays.fill(reducedPrivate, (byte) 0);
        }
    }

    /**
     * Processes the peer message and derives the shared session key.
     *
     * @param theirMsg message generated/received from the other end
     * @return key of size {@link #MAX_KEY_SIZE}
     * @throws IllegalArgumentException if the message is invalid or SHA-512 is unavailable
     * @throws IllegalStateException    if the key has already been generated
     */
    public byte[] processMessage(final byte[] theirMsg) throws IllegalArgumentException, IllegalStateException {
        byte[] dhShared = null;
        try {
            if (isDestroyed) throw new IllegalStateException("The context was destroyed.");
            if (this.state != State.MsgGenerated) {
                throw new IllegalStateException("Invalid state: " + this.state);
            }
            if (theirMsg == null || theirMsg.length != MAX_MSG_SIZE) {
                throw new IllegalArgumentException("Invalid peer message.");
            }
            try {
                Ed25519PublicKey.fromByteArray(theirMsg);
            } catch (InvalidEncodingException e) {
                throw new IllegalArgumentException("Point received from peer was not on the curve.", e);
            }
            EdwardsPoint nativeQStar;
            try {
                nativeQStar = new CompressedEdwardsY(theirMsg).decompress();
            } catch (InvalidEncodingException e) {
                throw new IllegalArgumentException("Point received from peer was not on the curve.", e);
            }
            EdwardsPoint nativePeersMaskBase = this.myRole == Spake2Role.Alice ? LIB_N : LIB_M;
            cafe.cryptography.curve25519.Scalar nativePasswordScalar =
                    cafe.cryptography.curve25519.Scalar.fromBytesModOrder(this.passwordScalar);
            EdwardsPoint nativePeersMask = nativePeersMaskBase.multiply(nativePasswordScalar);
            EdwardsPoint nativeQExt = nativeQStar.subtract(nativePeersMask);
            // Check if 8*Q == 0
            EdwardsPoint q8 = nativeQExt;
            q8 = q8.add(q8); // 2Q
            q8 = q8.add(q8); // 4Q
            q8 = q8.add(q8); // 8Q
            byte[] q8enc = q8.compress().toByteArray();
            try {
                if (q8enc.length == 32 && q8enc[0] == 0x01) {
                    boolean allZero = true;
                    for (int i = 1; i < 32; ++i) {
                        if (q8enc[i] != 0) {
                            allZero = false;
                            break;
                        }
                    }
                    if (allZero)
                        throw new IllegalArgumentException("Peer message reduces to identity after unmasking (8*Q == 0).");
                }
            } finally {
                Arrays.fill(q8enc, (byte) 0);
            }
            cafe.cryptography.curve25519.Scalar nativePrivateScalar =
                    cafe.cryptography.curve25519.Scalar.fromBits(this.privateKey);
            dhShared = nativeQExt.multiply(nativePrivateScalar).compress().toByteArray();
            MessageDigest sha = newSha512Digest();
            if (this.myRole == Spake2Role.Alice) {
                updateWithLengthPrefix(sha, this.myName, this.myName.length);
                updateWithLengthPrefix(sha, this.theirName, this.theirName.length);
                updateWithLengthPrefix(sha, this.myMsg, this.myMsg.length);
                updateWithLengthPrefix(sha, theirMsg, MAX_MSG_SIZE);
            } else {
                updateWithLengthPrefix(sha, this.theirName, this.theirName.length);
                updateWithLengthPrefix(sha, this.myName, this.myName.length);
                updateWithLengthPrefix(sha, theirMsg, MAX_MSG_SIZE);
                updateWithLengthPrefix(sha, this.myMsg, this.myMsg.length);
            }
            updateWithLengthPrefix(sha, dhShared, dhShared.length);
            updateWithLengthPrefix(sha, this.passwordHash, this.passwordHash.length);
            byte[] key = sha.digest();
            byte[] result = key.clone();
            Arrays.fill(key, (byte) 0);
            this.state = State.KeyGenerated;
            return result;
        } finally {
            if (dhShared != null) {
                Arrays.fill(dhShared, (byte) 0);
            }
            wipeSensitiveState();
        }
    }

    private static MessageDigest newSha512Digest() {
        try {
            return MessageDigest.getInstance(HASH_ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException("SHA-512 algorithm is not supported.", e);
        }
    }

    /**
     * Wipes all sensitive state information.
     *
     * <p>This includes key material, session-identifying information, and our own message, also after successful key
     * derivation to reduce the amount of metadata remaining in memory.</p>
     */
    private void wipeSensitiveState() {
        Arrays.fill(privateKey, (byte) 0);
        Arrays.fill(passwordScalar, (byte) 0);
        Arrays.fill(passwordHash, (byte) 0);
        Arrays.fill(myName, (byte) 0);
        Arrays.fill(theirName, (byte) 0);
        Arrays.fill(myMsg, (byte) 0);
    }

    private enum State {
        Init,
        MsgGenerated,
        KeyGenerated,
    }

    private static final class SecureRandomHolder {
        private static final SecureRandom INSTANCE;

        static {
            SecureRandom tmp;
            try {
                tmp = SecureRandom.getInstanceStrong();
            } catch (Throwable t) {
                tmp = new SecureRandom();
            }
            INSTANCE = tmp;
        }
    }

    static class Scalar {
        private final byte[] bytes;

        public Scalar(byte[] bytes) {
            this.bytes = new byte[32];
            System.arraycopy(bytes, 0, this.bytes, 0, 32);
        }

        public Scalar(Scalar src) {
            this();
            copy(src);
        }

        public Scalar() {
            this.bytes = new byte[32];
        }

        public byte getByte(int idx) {
            return bytes[idx];
        }

        public byte[] getBytes() {
            return bytes;
        }

        public void reset() {
            Arrays.fill(this.bytes, (byte) 0);
        }

        public void copyFrom(byte[] src) {
            System.arraycopy(src, 0, this.bytes, 0, 32);
        }

        /**
         * Copy bytes from the given scalar
         */
        public void copy(Scalar scalar) {
            System.arraycopy(scalar.bytes, 0, this.bytes, 0, 32);
        }

        /**
         * Conditional move (constant-time byte-wise).
         * Place into this = mask ? whenTrue : whenFalse
         */
        public void conditionalCopyFrom(Scalar whenTrue, Scalar whenFalse, long mask) {
            int maskInt = (int) mask;
            for (int i = 0; i < 8; ++i) {
                int idx = i * 4;
                for (int j = 0; j < 4; ++j) {
                    int shift = j * 8;
                    int m = (maskInt >>> shift) & 0xFF;
                    int nm = (~m) & 0xFF;
                    int a = whenTrue.bytes[idx + j] & 0xFF;
                    int b = whenFalse.bytes[idx + j] & 0xFF;
                    this.bytes[idx + j] = (byte) ((m & a) | (nm & b));
                }
            }
        }

        // Backward compatible API: returns new scalar selecting between this and src.
        public Scalar cmov(Scalar src, long mask) {
            Scalar out = new Scalar(this);
            out.conditionalCopyFrom(this, src, mask);
            return out;
        }

        /**
         * @return 2 * this
         */
        Scalar dbl() {
            return new Scalar(this).dblInPlace();
        }

        Scalar dblInPlace() {
            int carry = 0;
            for (int i = 0; i < 32; ++i) {
                int carryOut = (this.bytes[i] & 0xFF) >>> 7;
                this.bytes[i] = (byte) ((this.bytes[i] << 1) | carry);
                carry = carryOut;
            }
            return this;
        }

        /**
         * @return src + this
         */
        Scalar add(Scalar src) {
            return new Scalar(this).addInPlace(src);
        }

        Scalar addInPlace(Scalar src) {
            int carry = 0;
            for (int i = 0; i < 32; ++i) {
                int tmp = (src.bytes[i] & 0xFF) + (this.bytes[i] & 0xFF) + carry;
                this.bytes[i] = (byte) tmp;
                carry = tmp >>> 8;
            }
            return this;
        }
    }
}
