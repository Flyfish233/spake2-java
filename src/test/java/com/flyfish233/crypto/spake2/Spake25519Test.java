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
import org.junit.Test;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import static org.junit.Assert.*;

public class Spake25519Test {
    private static final byte[] B_EIGHT = HexUtils.hexToBytes("0800000000000000000000000000000000000000000000000000000000000000");
    private static final byte[] M_POINT_ENCODED =
            HexUtils.hexToBytes("5ada7e4bf6ddd9adb6626d32131c6b5c51a1e347a3478f53cfcf441b88eed12e");
    private static final byte[] N_POINT_ENCODED =
            HexUtils.hexToBytes("10e3df0ae37d8e7a99b5fe74b44672103dbddcbd06af680d71329a11693bc778");
    private static final String REDUCED_PASSWORD_ONE_HEX =
            "8f7065e6cdf9cb668e006212ce2d7bba08463df98a2164ab32d8dda39f69cb09";
    private static final String HARDENED_PASSWORD_ONE_HEX =
            "309432b751e9271fbe103841270fd62209463df98a2164ab32d8dda39f69cb59";

    private static void assertEphemeralPrivateKeyCleared(Spake2Context context) throws Exception {
        java.lang.reflect.Field scalarField = Spake2Context.class.getDeclaredField("privateKey");
        scalarField.setAccessible(true);
        byte[] scalar = (byte[]) scalarField.get(context);
        // After multiplying by the cofactor (leftShift3), low 3 bits must be zero
        assertEquals(0, scalar[0] & 0x07);
    }

    private static byte[] sequentialPrivateKey() {
        byte[] privateKey = new byte[64];
        for (int i = 0; i < privateKey.length; ++i) privateKey[i] = (byte) i;
        return privateKey;
    }

    private static byte[] highCarryPrivateKey() {
        byte[] privateKey = new byte[64];
        privateKey[31] = 0x10;
        return privateKey;
    }

    private static byte[] readByteArrayField(Spake2Context ctx, String fieldName) throws Exception {
        Field f = Spake2Context.class.getDeclaredField(fieldName);
        f.setAccessible(true);
        return ((byte[]) f.get(ctx)).clone();
    }

    private static EdwardsPoint decodePoint(byte[] encoded) throws InvalidEncodingException {
        return new CompressedEdwardsY(encoded.clone()).decompress();
    }

    private static EdwardsPoint multiplyByRawScalar(EdwardsPoint point, byte[] scalar) throws Exception {
        Method method = Spake2Context.class.getDeclaredMethod("multiplyByRawScalar", EdwardsPoint.class, byte[].class);
        method.setAccessible(true);
        return (EdwardsPoint) method.invoke(null, point, scalar.clone());
    }

    private static EdwardsPoint multiplyByBitwiseReference(EdwardsPoint point, byte[] scalar) {
        EdwardsPoint result = EdwardsPoint.IDENTITY;
        EdwardsPoint addend = point;
        // Independent, deliberately simple reference: walk the little-endian
        // scalar bit by bit so the nibble-window implementation cannot mask a
        // bit-ordering or high-bit bug.
        for (int byteIndex = 0; byteIndex < 32; ++byteIndex) {
            int value = scalar[byteIndex] & 0xFF;
            for (int bit = 0; bit < 8; ++bit) {
                if (((value >>> bit) & 1) != 0) {
                    result = result.add(addend);
                }
                addend = addend.dbl();
            }
        }
        return result;
    }

    private static void updateWithLengthPrefix(MessageDigest sha, byte[] data) {
        byte[] lenLe = new byte[8];
        long length = data.length & 0xFFFFFFFFL;
        for (int i = 0; i < lenLe.length; ++i) {
            lenLe[i] = (byte) (length & 0xFF);
            length >>>= 8;
        }
        sha.update(lenLe);
        sha.update(data);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> readOracleVectors() throws IOException {
        try (InputStream in = Spake25519Test.class.getResourceAsStream(
                "/oracle-vectors/boringssl-spake2-vectors.json")) {
            if (in == null) {
                throw new IOException("Missing oracle vector resource.");
            }
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buffer = new byte[4096];
            int read;
            while ((read = in.read(buffer)) != -1) {
                out.write(buffer, 0, read);
            }
            return (Map<String, Object>) new JsonParser(out.toString(StandardCharsets.UTF_8.name())).parse();
        }
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> readFuzzVectors() throws IOException {
        try (InputStream in = Spake25519Test.class.getResourceAsStream(
                "/oracle-vectors/boringssl-spake2-fuzz-vectors.jsonl")) {
            if (in == null) {
                throw new IOException("Missing oracle fuzz vector resource.");
            }
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            int read;
            while ((read = in.read(buffer)) != -1) {
                out.write(buffer, 0, read);
            }
            String[] lines = out.toString(StandardCharsets.UTF_8.name()).split("\\R");
            List<Map<String, Object>> cases = new ArrayList<>();
            for (String line : lines) {
                if (!line.trim().isEmpty()) {
                    cases.add((Map<String, Object>) new JsonParser(line).parse());
                }
            }
            return cases;
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> object(Object value) {
        return (Map<String, Object>) value;
    }

    @SuppressWarnings("unchecked")
    private static List<Object> array(Object value) {
        return (List<Object>) value;
    }

    private static String string(Map<String, Object> map, String key) {
        return (String) map.get(key);
    }

    private static boolean bool(Map<String, Object> map, String key) {
        return (Boolean) map.get(key);
    }

    private static byte[] hex(Map<String, Object> map, String key) {
        return HexUtils.hexToBytes(string(map, key + "Hex"));
    }

    private static Spake2Role role(Map<String, Object> party) {
        return "alice".equals(string(party, "role")) ? Spake2Role.Alice : Spake2Role.Bob;
    }

    private static Spake2Context contextFor(Map<String, Object> party) {
        Spake2Context context = new Spake2Context(role(party), hex(party, "myName"), hex(party, "theirName"));
        context.setDisablePasswordScalarHack(bool(party, "disablePasswordScalarHack"));
        return context;
    }

    private static void assertGeneratedMessageMatchesOracle(Map<String, Object> party) {
        Map<String, Object> generate = object(party.get("generate"));
        try (Spake2Context context = contextFor(party)) {
            byte[] message = context.generateMessage(hex(party, "password"), hex(generate, "privateInput64"));
            assertArrayEquals(hex(generate, "privateScalar"), readByteArrayField(context, "privateKey"));
            assertArrayEquals(hex(generate, "passwordHash"), readByteArrayField(context, "passwordHash"));
            assertArrayEquals(hex(generate, "passwordScalar"), readByteArrayField(context, "passwordScalar"));
            assertArrayEquals(hex(generate, "message"), message);
        } catch (Exception e) {
            throw new AssertionError("Oracle generation mismatch for " + party.get("id"), e);
        }
    }

    private static void assertProcessMatchesOracle(Map<String, Object> party, byte[] peerMessage,
                                                   Map<String, Object> process) {
        Map<String, Object> generate = object(party.get("generate"));
        try (Spake2Context context = contextFor(party)) {
            byte[] message = context.generateMessage(hex(party, "password"), hex(generate, "privateInput64"));
            assertArrayEquals(hex(generate, "message"), message);
            if (bool(process, "success")) {
                assertArrayEquals(hex(process, "key"), context.processMessage(peerMessage));
            } else {
                assertThrows(RuntimeException.class, () -> context.processMessage(peerMessage));
            }
        } catch (Exception e) {
            throw new AssertionError("Oracle process mismatch for " + party.get("id"), e);
        }
    }

    private static byte[] hkdfSha256(byte[] ikm, byte[] info, int outLen) throws GeneralSecurityException {
        byte[] salt = new byte[32];
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(salt, "HmacSHA256"));
        byte[] prk = mac.doFinal(ikm);
        byte[] out = new byte[outLen];
        byte[] previous = new byte[0];
        int offset = 0;
        int counter = 1;
        while (offset < outLen) {
            mac.init(new SecretKeySpec(prk, "HmacSHA256"));
            mac.update(previous);
            mac.update(info);
            mac.update((byte) counter);
            previous = mac.doFinal();
            int copy = Math.min(previous.length, outLen - offset);
            System.arraycopy(previous, 0, out, offset, copy);
            offset += copy;
            counter++;
        }
        Arrays.fill(prk, (byte) 0);
        Arrays.fill(previous, (byte) 0);
        return out;
    }

    private static byte[] aesGcm(byte[] key, long sequence, byte[] input, int mode)
            throws GeneralSecurityException {
        byte[] nonce = new byte[12];
        long v = sequence;
        // ADB pairing-auth uses the sequence counter as the low 64 bits of the
        // 96-bit GCM nonce, encoded little-endian.
        for (int i = 0; i < 8; ++i) {
            nonce[i] = (byte) (v & 0xFF);
            v >>>= 8;
        }
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(mode, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
        return cipher.doFinal(input);
    }

    private static void assertZeroField(Spake2Context ctx, String fieldName) throws Exception {
        Field f = Spake2Context.class.getDeclaredField(fieldName);
        f.setAccessible(true);
        byte[] v = (byte[]) f.get(ctx);
        for (byte b : v) assertEquals(0, b);
    }

    private static void assertSensitiveStateCleared(Spake2Context ctx) throws Exception {
        assertZeroField(ctx, "privateKey");
        assertZeroField(ctx, "passwordScalar");
        assertZeroField(ctx, "passwordHash");
        assertZeroField(ctx, "myMsg");
        assertZeroField(ctx, "myName");
        assertZeroField(ctx, "theirName");
    }

    private static byte[] readClassResource(String resourceName) throws IOException {
        try (InputStream in = Spake25519Test.class.getClassLoader().getResourceAsStream(resourceName)) {
            assertNotNull(in);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buffer = new byte[1024];
            int read;
            while ((read = in.read(buffer)) != -1) {
                out.write(buffer, 0, read);
            }
            return out.toByteArray();
        }
    }

    private static boolean constantPoolContainsMethodRef(
            byte[] classFile, String owner, String name, String descriptor) {
        if (readU4(classFile, 0) != 0xCAFEBABE) {
            throw new IllegalArgumentException("Not a Java class file.");
        }

        int constantPoolCount = readU2(classFile, 8);
        String[] utf8 = new String[constantPoolCount];
        int[] classNameIndex = new int[constantPoolCount];
        int[] refTag = new int[constantPoolCount];
        int[] refClassIndex = new int[constantPoolCount];
        int[] refNameAndTypeIndex = new int[constantPoolCount];
        int[] nameAndTypeNameIndex = new int[constantPoolCount];
        int[] nameAndTypeDescriptorIndex = new int[constantPoolCount];

        int offset = 10;
        for (int i = 1; i < constantPoolCount; i++) {
            int tag = readU1(classFile, offset++);
            switch (tag) {
                case 1:
                    int length = readU2(classFile, offset);
                    offset += 2;
                    utf8[i] = new String(classFile, offset, length, StandardCharsets.UTF_8);
                    offset += length;
                    break;
                case 3:
                case 4:
                    offset += 4;
                    break;
                case 5:
                case 6:
                    offset += 8;
                    i++;
                    break;
                case 7:
                    classNameIndex[i] = readU2(classFile, offset);
                    offset += 2;
                    break;
                case 8:
                case 16:
                case 19:
                case 20:
                    offset += 2;
                    break;
                case 9:
                case 10:
                case 11:
                    refTag[i] = tag;
                    refClassIndex[i] = readU2(classFile, offset);
                    refNameAndTypeIndex[i] = readU2(classFile, offset + 2);
                    offset += 4;
                    break;
                case 12:
                    nameAndTypeNameIndex[i] = readU2(classFile, offset);
                    nameAndTypeDescriptorIndex[i] = readU2(classFile, offset + 2);
                    offset += 4;
                    break;
                case 15:
                    offset += 3;
                    break;
                case 17:
                case 18:
                    offset += 4;
                    break;
                default:
                    throw new IllegalArgumentException("Unsupported constant-pool tag " + tag);
            }
        }

        for (int i = 1; i < constantPoolCount; i++) {
            if (refTag[i] != 10 && refTag[i] != 11) {
                continue;
            }
            int classIndex = refClassIndex[i];
            int nameAndTypeIndex = refNameAndTypeIndex[i];
            if (classIndex == 0 || nameAndTypeIndex == 0) {
                continue;
            }
            String refOwner = utf8[classNameIndex[classIndex]];
            String refName = utf8[nameAndTypeNameIndex[nameAndTypeIndex]];
            String refDescriptor = utf8[nameAndTypeDescriptorIndex[nameAndTypeIndex]];
            if (owner.equals(refOwner) && name.equals(refName) && descriptor.equals(refDescriptor)) {
                return true;
            }
        }
        return false;
    }

    private static int readU1(byte[] bytes, int offset) {
        return bytes[offset] & 0xFF;
    }

    private static int readU2(byte[] bytes, int offset) {
        return ((bytes[offset] & 0xFF) << 8) | (bytes[offset + 1] & 0xFF);
    }

    private static int readU4(byte[] bytes, int offset) {
        return (readU2(bytes, offset) << 16) | readU2(bytes, offset + 2);
    }

    @Test
    public void scalarTestCmov() {
        Spake2Context.Scalar scalar = new Spake2Context.Scalar(HexUtils.hexToBytes(
                "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010"));
        Spake2Context.Scalar zero = new Spake2Context.Scalar();
        String zeroHex = "0000000000000000000000000000000000000000000000000000000000000000";
        String scalarHex = "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010";
        assertEquals(zeroHex, HexUtils.bytesToHex(scalar.cmov(zero, 0).getBytes()));
        assertEquals(scalarHex, HexUtils.bytesToHex(scalar.cmov(zero, 1).getBytes()));
        assertEquals(scalarHex, HexUtils.bytesToHex(scalar.cmov(zero, 0xF9).getBytes()));
    }

    @Test
    public void scalarTestCmov2() {
        Spake2Context.Scalar scalar = new Spake2Context.Scalar(HexUtils.hexToBytes(
                "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010"));
        Spake2Context.Scalar eight = new Spake2Context.Scalar(B_EIGHT);
        String scalarHex = "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010";
        String eightHex = HexUtils.bytesToHex(B_EIGHT);
        Spake2Context.Scalar out = scalar.cmov(eight, 0);
        assertEquals(eightHex, HexUtils.bytesToHex(out.getBytes()));
        out = scalar.cmov(eight, 1);
        assertEquals(scalarHex, HexUtils.bytesToHex(out.getBytes()));
        out = scalar.cmov(eight, 2);
        assertEquals(scalarHex, HexUtils.bytesToHex(out.getBytes()));
    }

    @Test
    public void scalarTestDbl() {
        Spake2Context.Scalar scalar = new Spake2Context.Scalar(HexUtils.hexToBytes(
                "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010"));
        Spake2Context.Scalar eight = new Spake2Context.Scalar(B_EIGHT);
        assertEquals("daa7ebb934c624b0ac39ef45bdf3bd2900000000000000000000000000000020",
                HexUtils.bytesToHex(scalar.dbl().getBytes()));
        assertEquals("1000000000000000000000000000000000000000000000000000000000000000",
                HexUtils.bytesToHex(eight.dbl().getBytes()));
        scalar.copy(scalar.dbl());
        assertEquals("daa7ebb934c624b0ac39ef45bdf3bd2900000000000000000000000000000020",
                HexUtils.bytesToHex(scalar.getBytes()));
    }

    @Test
    public void scalarTestAdd() {
        Spake2Context.Scalar scalar = new Spake2Context.Scalar(HexUtils.hexToBytes(
                "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010"));
        Spake2Context.Scalar eight = new Spake2Context.Scalar(B_EIGHT);
        assertEquals("f5d3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010",
                HexUtils.bytesToHex(eight.add(scalar).getBytes()));
        assertEquals("daa7ebb934c624b0ac39ef45bdf3bd2900000000000000000000000000000020",
                HexUtils.bytesToHex(scalar.add(scalar).getBytes()));
    }

    @Test
    public void defaultConstructorCanGenerateMessageWithPlatformRng() {
        try (Spake2Context alice = new Spake2Context(
                Spake2Role.Alice,
                "alice".getBytes(StandardCharsets.UTF_8),
                "bob".getBytes(StandardCharsets.UTF_8))) {
            byte[] msg = alice.generateMessage("shared password".getBytes(StandardCharsets.UTF_8));
            assertEquals(Spake2Context.MAX_MSG_SIZE, msg.length);
        }
    }

    @Test
    public void defaultPlatformRngUsesStrongFactoryWhenAvailable() throws Exception {
        SecureRandom expected = SecureRandom.getInstanceStrong();
        Class<?> holder = Class.forName("com.flyfish233.crypto.spake2.Spake2Context$SecureRandomHolder");
        Method factory = holder.getDeclaredMethod("createDefaultSecureRandom");
        factory.setAccessible(true);
        SecureRandom actual = (SecureRandom) factory.invoke(null);
        assertEquals(expected.getAlgorithm(), actual.getAlgorithm());
        assertEquals(expected.getProvider().getName(), actual.getProvider().getName());
    }

    @Test
    public void ephemeralPrivateScalarClearsLowBits() throws Exception {
        byte[] password = "shared password".getBytes(StandardCharsets.UTF_8);
        byte[] privateKey = sequentialPrivateKey();

        try (Spake2Context alice = new Spake2Context(
                Spake2Role.Alice,
                "alice".getBytes(StandardCharsets.UTF_8),
                "bob".getBytes(StandardCharsets.UTF_8))) {
            alice.generateMessage(password, privateKey.clone());
            assertEphemeralPrivateKeyCleared(alice);
        }

        try (Spake2Context bob = new Spake2Context(
                Spake2Role.Bob,
                "bob".getBytes(StandardCharsets.UTF_8),
                "alice".getBytes(StandardCharsets.UTF_8))) {
            bob.generateMessage(password, privateKey.clone());
            assertEphemeralPrivateKeyCleared(bob);
        }
    }

    @Test
    public void highBitCarryPrivateScalarStillInteroperates() {
        byte[] password = "515109".getBytes(StandardCharsets.UTF_8);
        try (Spake2Context alice = new Spake2Context(
                Spake2Role.Alice,
                "alice".getBytes(StandardCharsets.UTF_8),
                "bob".getBytes(StandardCharsets.UTF_8));
             Spake2Context bob = new Spake2Context(
                     Spake2Role.Bob,
                     "bob".getBytes(StandardCharsets.UTF_8),
                     "alice".getBytes(StandardCharsets.UTF_8))) {
            byte[] aliceMsg = alice.generateMessage(password, highCarryPrivateKey());
            byte[] bobMsg = bob.generateMessage(password, sequentialPrivateKey());
            byte[] aliceKey = alice.processMessage(bobMsg);
            byte[] bobKey = bob.processMessage(aliceMsg);
            assertArrayEquals(aliceKey, bobKey);
        }
    }

    @Test
    public void highBitCarryMessageMatchesExpectedPoint() throws Exception {
        byte[] password = "515109".getBytes(StandardCharsets.UTF_8);
        byte[] expectedPrivateScalar = new byte[32];
        expectedPrivateScalar[31] = (byte) 0x80;

        byte[] passwordHash = MessageDigest.getInstance("SHA-512").digest(password);
        byte[] passwordScalar = cafe.cryptography.curve25519.Scalar
                .fromBytesModOrderWide(passwordHash)
                .toByteArray();

        EdwardsPoint baseMultiple = Constants.ED25519_BASEPOINT;
        for (int i = 0; i < 255; ++i) {
            baseMultiple = baseMultiple.dbl();
        }
        EdwardsPoint mask = decodePoint(M_POINT_ENCODED)
                .multiply(cafe.cryptography.curve25519.Scalar.fromBytesModOrder(passwordScalar));
        byte[] expectedMsg = baseMultiple.add(mask).compress().toByteArray();

        try (Spake2Context alice = new Spake2Context(
                Spake2Role.Alice,
                "alice".getBytes(StandardCharsets.UTF_8),
                "bob".getBytes(StandardCharsets.UTF_8))) {
            byte[] actualMsg = alice.generateMessage(password, highCarryPrivateKey());
            assertArrayEquals(expectedPrivateScalar, readByteArrayField(alice, "privateKey"));
            assertArrayEquals(expectedMsg, actualMsg);
        } finally {
            Arrays.fill(passwordHash, (byte) 0);
            Arrays.fill(passwordScalar, (byte) 0);
        }
    }

    @Test
    public void rawScalarMultiplyMatchesBitwiseReferenceAcrossRepresentativeInputs() throws Exception {
        byte[] zeroScalar = new byte[32];
        byte[] sequentialScalar = HexUtils.hexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        byte[] allOnesScalar = new byte[32];
        Arrays.fill(allOnesScalar, (byte) 0xFF);
        byte[] topBitOnlyScalar = new byte[32];
        topBitOnlyScalar[31] = (byte) 0x80;
        byte[] stripedScalar = HexUtils.hexToBytes("a55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55a");

        EdwardsPoint[] points = new EdwardsPoint[] {
                Constants.ED25519_BASEPOINT,
                decodePoint(M_POINT_ENCODED),
                decodePoint(N_POINT_ENCODED),
                decodePoint(M_POINT_ENCODED).add(Constants.ED25519_BASEPOINT)
        };
        byte[][] scalars = new byte[][] {
                zeroScalar,
                sequentialScalar,
                topBitOnlyScalar,
                stripedScalar,
                allOnesScalar
        };

        for (EdwardsPoint point : points) {
            for (byte[] scalar : scalars) {
                byte[] expected = multiplyByBitwiseReference(point, scalar).compress().toByteArray();
                byte[] actual = multiplyByRawScalar(point, scalar).compress().toByteArray();
                assertArrayEquals(expected, actual);
            }
        }
    }

    @Test
    public void processMessageCopiesPeerMessageBeforeDependencyUse() throws Exception {
        String source = new String(Files.readAllBytes(Paths.get(
                "src", "main", "java", "com", "flyfish233", "crypto", "spake2", "Spake2Context.java")),
                StandardCharsets.UTF_8);
        // Guard the security-sensitive ordering: clone the caller-owned network
        // bytes before any dependency wrapper or transcript hash can observe them.
        assertTrue(source.contains("byte[] peerMsg = null;"));
        assertTrue(source.contains("peerMsg = theirMsg.clone();"));
        assertTrue(source.contains("Ed25519PublicKey.fromByteArray(peerMsg);"));
        assertTrue(source.contains("new CompressedEdwardsY(peerMsg).decompress();"));
        assertTrue(source.contains("updateWithLengthPrefix(sha, peerMsg, MAX_MSG_SIZE);"));
        assertFalse(source.contains("updateWithLengthPrefix(sha, theirMsg, MAX_MSG_SIZE);"));
    }

    @Test
    public void productionCodeDoesNotUseForbiddenDependencyApis() throws Exception {
        String source = new String(Files.readAllBytes(Paths.get(
                "src", "main", "java", "com", "flyfish233", "crypto", "spake2", "Spake2Context.java")),
                StandardCharsets.UTF_8);
        // Scalar.fromBits collapses the high-bit cofactor-shift case, and the
        // ed25519 signing APIs are outside this ADB-only SPAKE2 product path.
        assertFalse(source.contains("Scalar.fromBits"));
        assertFalse(source.contains("Ed25519ExpandedPrivateKey"));
        assertFalse(source.contains("Ed25519PrivateKey"));
        assertFalse(source.contains("Ed25519Signature"));
        assertFalse(source.contains(".sign("));
    }

    @Test
    public void productionCodeDoesNotDirectlyLinkAndroid26SecureRandomFactory() throws Exception {
        String forbidden = new StringBuilder("getInstance").append("Strong").toString();
        byte[] holderClass = readClassResource(
                "com/flyfish233/crypto/spake2/Spake2Context$SecureRandomHolder.class");
        String classBytes = new String(holderClass, StandardCharsets.ISO_8859_1);
        assertTrue(classBytes.contains(forbidden)); // Reflection can use the strong factory on newer runtimes.
        assertTrue(constantPoolContainsMethodRef(holderClass,
                "java/lang/Class",
                "getMethod",
                "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;"));
        assertTrue(constantPoolContainsMethodRef(holderClass,
                "java/lang/reflect/Method",
                "invoke",
                "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;"));
        assertFalse(constantPoolContainsMethodRef(holderClass,
                "java/security/SecureRandom",
                "getInstanceStrong",
                "()Ljava/security/SecureRandom;"));
    }

    @Test
    public void passwordScalarHardeningMatchesBoringSslForKnownPassword() throws Exception {
        try (Spake2Context alice = new Spake2Context(
                Spake2Role.Alice,
                "alice".getBytes(StandardCharsets.UTF_8),
                "bob".getBytes(StandardCharsets.UTF_8))) {
            alice.generateMessage("1".getBytes(StandardCharsets.UTF_8), sequentialPrivateKey());
            byte[] passwordScalar = readByteArrayField(alice, "passwordScalar");
            assertEquals(HARDENED_PASSWORD_ONE_HEX, HexUtils.bytesToHex(passwordScalar));
            assertEquals(0, passwordScalar[0] & 0x07);
        }
    }

    @Test
    public void disablingPasswordScalarHackRestoresLegacyScalar() throws Exception {
        try (Spake2Context alice = new Spake2Context(
                Spake2Role.Alice,
                "alice".getBytes(StandardCharsets.UTF_8),
                "bob".getBytes(StandardCharsets.UTF_8))) {
            alice.setDisablePasswordScalarHack(true);
            alice.generateMessage("1".getBytes(StandardCharsets.UTF_8), sequentialPrivateKey());
            byte[] passwordScalar = readByteArrayField(alice, "passwordScalar");
            assertEquals(REDUCED_PASSWORD_ONE_HEX, HexUtils.bytesToHex(passwordScalar));
            assertEquals(0x07, passwordScalar[0] & 0x07);
        }
    }

    @Test
    public void processMessageAcceptsIdentityAfterUnmaskingToMatchAosp() throws Exception {
        byte[] password = "515109".getBytes(StandardCharsets.UTF_8);
        byte[] myName = "alice".getBytes(StandardCharsets.UTF_8);
        byte[] theirName = "bob".getBytes(StandardCharsets.UTF_8);

        try (Spake2Context alice = new Spake2Context(Spake2Role.Alice, myName, theirName)) {
            byte[] myMsg = alice.generateMessage(password, sequentialPrivateKey());
            byte[] passwordScalar = readByteArrayField(alice, "passwordScalar");
            byte[] theirMsg = multiplyByRawScalar(decodePoint(N_POINT_ENCODED), passwordScalar).compress().toByteArray();
            byte[] expectedDhShared = EdwardsPoint.IDENTITY.compress().toByteArray();

            MessageDigest sha = MessageDigest.getInstance("SHA-512");
            updateWithLengthPrefix(sha, myName);
            updateWithLengthPrefix(sha, theirName);
            updateWithLengthPrefix(sha, myMsg);
            updateWithLengthPrefix(sha, theirMsg);
            updateWithLengthPrefix(sha, expectedDhShared);
            updateWithLengthPrefix(sha, Spake2Context.getHash(password));
            byte[] expectedKey = sha.digest();

            byte[] actualKey = alice.processMessage(theirMsg);
            assertArrayEquals(expectedKey, actualKey);
        }
    }

    @Test
    public void generatedMessagesMatchBoringSslOracleVectors() throws Exception {
        Map<String, Object> vectors = readOracleVectors();
        assertEquals("boringssl-spake2-deterministic-harness", string(vectors, "oracle"));
        for (Object item : array(vectors.get("exchanges"))) {
            Map<String, Object> exchange = object(item);
            assertGeneratedMessageMatchesOracle(object(exchange.get("alice")));
            assertGeneratedMessageMatchesOracle(object(exchange.get("bob")));
        }
    }

    @Test
    public void derivedKeysMatchBoringSslOracleVectors() throws Exception {
        Map<String, Object> vectors = readOracleVectors();
        for (Object item : array(vectors.get("exchanges"))) {
            Map<String, Object> exchange = object(item);
            Map<String, Object> alice = object(exchange.get("alice"));
            Map<String, Object> bob = object(exchange.get("bob"));
            Map<String, Object> aliceProcess = object(exchange.get("aliceProcess"));
            Map<String, Object> bobProcess = object(exchange.get("bobProcess"));
            assertProcessMatchesOracle(alice, hex(object(bob.get("generate")), "message"), aliceProcess);
            assertProcessMatchesOracle(bob, hex(object(alice.get("generate")), "message"), bobProcess);
        }
    }

    @Test
    public void processCasesMatchBoringSslOracleVectors() throws Exception {
        Map<String, Object> vectors = readOracleVectors();
        Map<String, Object> normal = object(array(vectors.get("exchanges")).get(0));
        Map<String, Object> alice = object(normal.get("alice"));
        for (Object item : array(vectors.get("processCases"))) {
            Map<String, Object> processCase = object(item);
            Map<String, Object> process = object(processCase.get("process"));
            assertProcessMatchesOracle(alice, hex(process, "theirMessage"), process);
        }
    }

    @Test
    public void aospPairingAuthAesGcmWrappingMatchesOracleKeyMaterial() throws Exception {
        Map<String, Object> vectors = readOracleVectors();
        Map<String, Object> aospExchange = null;
        Map<String, Object> wrongPasswordExchange = null;
        for (Object item : array(vectors.get("exchanges"))) {
            Map<String, Object> exchange = object(item);
            if ("aosp-adb-names".equals(string(exchange, "id"))) {
                aospExchange = exchange;
            } else if ("normal".equals(string(exchange, "id"))) {
                wrongPasswordExchange = exchange;
            }
        }
        assertNotNull(aospExchange);
        assertNotNull(wrongPasswordExchange);

        byte[] keyMaterial = hex(object(aospExchange.get("aliceProcess")), "key");
        byte[] key = hkdfSha256(
                keyMaterial,
                "adb pairing_auth aes-128-gcm key".getBytes(StandardCharsets.UTF_8),
                16);
        byte[] msg = HexUtils.hexToBytes("2a2b2cff451233");
        byte[] encrypted = aesGcm(key, 0, msg, Cipher.ENCRYPT_MODE);
        assertArrayEquals(msg, aesGcm(key, 0, encrypted, Cipher.DECRYPT_MODE));

        byte[] encryptedSecond = aesGcm(key, 1, msg, Cipher.ENCRYPT_MODE);
        assertArrayEquals(msg, aesGcm(key, 1, encryptedSecond, Cipher.DECRYPT_MODE));
        assertThrows(GeneralSecurityException.class, () -> aesGcm(key, 0, encryptedSecond, Cipher.DECRYPT_MODE));

        byte[] wrongKey = hkdfSha256(
                hex(object(wrongPasswordExchange.get("aliceProcess")), "key"),
                "adb pairing_auth aes-128-gcm key".getBytes(StandardCharsets.UTF_8),
                16);
        try {
            assertThrows(GeneralSecurityException.class, () -> aesGcm(wrongKey, 0, encrypted, Cipher.DECRYPT_MODE));
        } finally {
            Arrays.fill(key, (byte) 0);
            Arrays.fill(wrongKey, (byte) 0);
        }
    }

    @Test
    public void fuzzTranscriptVectorsMatchBoringSslOracle() throws Exception {
        for (Map<String, Object> vector : readFuzzVectors()) {
            byte[] password = hex(vector, "password");
            byte[] aliceName = hex(vector, "aliceName");
            byte[] bobName = hex(vector, "bobName");
            try (Spake2Context alice = new Spake2Context(Spake2Role.Alice, aliceName, bobName);
                 Spake2Context bob = new Spake2Context(Spake2Role.Bob, bobName, aliceName)) {
                int index = ((Number) vector.get("index")).intValue();
                if (bool(vector, "aliceDisablePasswordScalarHack")) {
                    alice.setDisablePasswordScalarHack(true);
                }
                if (bool(vector, "bobDisablePasswordScalarHack")) {
                    bob.setDisablePasswordScalarHack(true);
                }
                byte[] aliceMsg = alice.generateMessage(password, hex(vector, "alicePrivateInput64"));
                byte[] bobMsg = bob.generateMessage(password, hex(vector, "bobPrivateInput64"));
                assertArrayEquals("alice message index " + index, hex(vector, "aliceMessage"), aliceMsg);
                assertArrayEquals("bob message index " + index, hex(vector, "bobMessage"), bobMsg);
                assertTrue("alice oracle success index " + index, bool(vector, "aliceSuccess"));
                assertTrue("bob oracle success index " + index, bool(vector, "bobSuccess"));
                assertArrayEquals("alice key index " + index, hex(vector, "aliceKey"), alice.processMessage(bobMsg));
                assertArrayEquals("bob key index " + index, hex(vector, "bobKey"), bob.processMessage(aliceMsg));
            }
        }
    }

    @Test
    public void generateMessageNullPasswordFails() {
        try (Spake2Context c = new Spake2Context(
                Spake2Role.Alice, "alice".getBytes(StandardCharsets.UTF_8),
                "bob".getBytes(StandardCharsets.UTF_8))) {
            assertThrows(IllegalArgumentException.class, () -> c.generateMessage(null));
        }
    }

    @Test
    public void generateMessageEmptyPasswordFails() {
        try (Spake2Context c = new Spake2Context(
                Spake2Role.Alice, "alice".getBytes(StandardCharsets.UTF_8),
                "bob".getBytes(StandardCharsets.UTF_8))) {
            assertThrows(IllegalArgumentException.class, () -> c.generateMessage(new byte[0]));
        }
    }

    @Test
    public void generateMessageRejectsInvalidPrivateKeyLength() {
        byte[] pw = "shared password".getBytes(StandardCharsets.UTF_8);
        try (Spake2Context c = new Spake2Context(
                Spake2Role.Alice, "alice".getBytes(StandardCharsets.UTF_8),
                "bob".getBytes(StandardCharsets.UTF_8))) {
            assertThrows(IllegalArgumentException.class, () -> c.generateMessage(pw, new byte[31]));
        }
    }

    @Test
    public void processMessageNullInputFailsAndWipes() throws Exception {
        byte[] pw = "shared password".getBytes(StandardCharsets.UTF_8);
        byte[] sk = sequentialPrivateKey();
        try (Spake2Context c = new Spake2Context(
                Spake2Role.Alice, "alice".getBytes(StandardCharsets.UTF_8),
                "bob".getBytes(StandardCharsets.UTF_8))) {
            c.generateMessage(pw, sk.clone());
            assertThrows(IllegalArgumentException.class, () -> c.processMessage(null));
            assertTrue(c.isDestroyed());
            assertThrows(IllegalStateException.class,
                    () -> c.processMessage(new byte[Spake2Context.MAX_MSG_SIZE]));
            assertSensitiveStateCleared(c);
        }
    }

    @Test
    public void processMessageWrongLengthFailsAndWipes() throws Exception {
        byte[] pw = "shared password".getBytes(StandardCharsets.UTF_8);
        byte[] sk = sequentialPrivateKey();
        try (Spake2Context c = new Spake2Context(
                Spake2Role.Alice, "alice".getBytes(StandardCharsets.UTF_8),
                "bob".getBytes(StandardCharsets.UTF_8))) {
            c.generateMessage(pw, sk.clone());
            byte[] bad = new byte[Spake2Context.MAX_MSG_SIZE - 1];
            assertThrows(IllegalArgumentException.class, () -> c.processMessage(bad));
            assertTrue(c.isDestroyed());
            assertThrows(IllegalStateException.class,
                    () -> c.processMessage(new byte[Spake2Context.MAX_MSG_SIZE]));
            assertSensitiveStateCleared(c);
        }
    }

    @Test
    public void spake2() {
        for (int i = 0; i < 20; i++) {
            SPAKE2Run spake2 = new SPAKE2Run();
            assertTrue(spake2.run());
            assertTrue(spake2.keyMatches());
        }
    }

    @Test
    public void oldAlice() {
        for (int i = 0; i < 20; i++) {
            SPAKE2Run spake2 = new SPAKE2Run();
            spake2.aliceDisablePasswordScalarHack = true;
            assertTrue(spake2.run());
            assertTrue(spake2.keyMatches());
        }
    }

    @Test
    public void oldBob() {
        for (int i = 0; i < 20; i++) {
            SPAKE2Run spake2 = new SPAKE2Run();
            spake2.bobDisablePasswordScalarHack = true;
            assertTrue(spake2.run());
            assertTrue(spake2.keyMatches());
        }
    }

    @Test
    public void wrongPassword() {
        SPAKE2Run spake2 = new SPAKE2Run();
        spake2.bobPassword = "wrong password".getBytes(StandardCharsets.UTF_8);
        assertTrue(spake2.run());
        assertFalse(spake2.keyMatches());
    }

    @Test
    public void wrongNames() {
        SPAKE2Run spake2 = new SPAKE2Run();
        spake2.aliceNames.second = "charlie";
        spake2.bobNames.second = "charlie";
        assertTrue(spake2.run());
        assertFalse(spake2.keyMatches());
    }

    @Test
    public void corruptMessages() {
        for (int i = 0; i < 8 * Spake2Context.MAX_MSG_SIZE; i++) {
            SPAKE2Run spake2 = new SPAKE2Run();
            spake2.aliceCorruptMsgBit = i;
            assertFalse(spake2.run() && spake2.keyMatches());
        }
    }

    // Based on https://android.googlesource.com/platform/external/boringssl/+/f9e0b0e17fabac35627f18f94a8954c3857784ac/src/crypto/curve25519/spake25519_test.cc
    private static class SPAKE2Run {
        private final Pair<String, String> aliceNames = new Pair<>("adb pair client\u0000", "adb pair server\u0000");
        private final Pair<String, String> bobNames = new Pair<>("adb pair server\u0000", "adb pair client\u0000");
        private final byte[] alicePassword = HexUtils.hexToBytes("353932373831E63DD959651C211600F3B6561D0B9D90AF09D0A4A453EE2059A480CC7C5A94D4D48933F9FFF5FE43317D52FA7BFF8F8BC4F3488B8007330FEC7C7EDC91C20E5D");
        private byte[] bobPassword = alicePassword;
        private int aliceCorruptMsgBit = -1;
        private boolean aliceDisablePasswordScalarHack = false;
        private boolean bobDisablePasswordScalarHack = false;
        private boolean keyMatches = false;

        private boolean run() {
            keyMatches = false;
            try (Spake2Context alice = new Spake2Context(
                    Spake2Role.Alice,
                    aliceNames.first.getBytes(StandardCharsets.UTF_8),
                    aliceNames.second.getBytes(StandardCharsets.UTF_8));
                 Spake2Context bob = new Spake2Context(
                         Spake2Role.Bob,
                         bobNames.first.getBytes(StandardCharsets.UTF_8),
                         bobNames.second.getBytes(StandardCharsets.UTF_8))) {
                if (aliceDisablePasswordScalarHack) {
                    alice.setDisablePasswordScalarHack(true);
                }
                if (bobDisablePasswordScalarHack) {
                    bob.setDisablePasswordScalarHack(true);
                }

                byte[] aliceMsg;
                byte[] bobMsg;
                try {
                    aliceMsg = alice.generateMessage(alicePassword, HexUtils.hexToBytes("47f6c458e5f062db8427d2d9bb20c954a76d6943959756a18d11d45e1ad190f980a86d185a93ca1d3025c5febe3aac4045b34a39b1f511385ca97fc4332137f3"));
                    bobMsg = bob.generateMessage(bobPassword, HexUtils.hexToBytes("a6bf9f9bf7819e0ded8c2dd82a1aa38acb2f8a6403429cff33d64ea9c40439d5fd7029811a5f5a8f7c89c8b44ac0b421f6b24ca2ba18d2069995831730cd8c5a"));
                } catch (Exception e) {
                    return false;
                }

                if (aliceCorruptMsgBit >= 0 && aliceCorruptMsgBit < (8 * aliceMsg.length)) {
                    aliceMsg[aliceCorruptMsgBit / 8] ^= 1 << (aliceCorruptMsgBit & 7);
                }

                byte[] aliceKey;
                byte[] bobKey;
                try {
                    aliceKey = alice.processMessage(bobMsg);
                    bobKey = bob.processMessage(aliceMsg);
                } catch (Exception e) {
                    return false;
                }

                keyMatches = MessageDigest.isEqual(aliceKey, bobKey);
                return true;
            }
        }

        boolean keyMatches() {
            return keyMatches;
        }
    }

    private static class Pair<S, T> {
        private S first;
        private T second;

        public Pair(S first, T second) {
            this.first = first;
            this.second = second;
        }
    }

    private static final class JsonParser {
        private final String input;
        private int pos;

        JsonParser(String input) {
            this.input = input;
        }

        Object parse() {
            Object value = parseValue();
            skipWhitespace();
            if (pos != input.length()) {
                throw new IllegalArgumentException("Trailing JSON content at " + pos);
            }
            return value;
        }

        private Object parseValue() {
            skipWhitespace();
            if (pos >= input.length()) {
                throw new IllegalArgumentException("Unexpected end of JSON.");
            }
            char c = input.charAt(pos);
            if (c == '{') return parseObject();
            if (c == '[') return parseArray();
            if (c == '"') return parseString();
            if (input.startsWith("true", pos)) {
                pos += 4;
                return Boolean.TRUE;
            }
            if (input.startsWith("false", pos)) {
                pos += 5;
                return Boolean.FALSE;
            }
            if (input.startsWith("null", pos)) {
                pos += 4;
                return null;
            }
            if (c == '-' || (c >= '0' && c <= '9')) {
                return parseNumber();
            }
            throw new IllegalArgumentException("Unexpected JSON token at " + pos);
        }

        private Map<String, Object> parseObject() {
            expect('{');
            Map<String, Object> map = new LinkedHashMap<>();
            skipWhitespace();
            if (peek('}')) {
                pos++;
                return map;
            }
            while (true) {
                String key = parseString();
                skipWhitespace();
                expect(':');
                map.put(key, parseValue());
                skipWhitespace();
                if (peek('}')) {
                    pos++;
                    return map;
                }
                expect(',');
            }
        }

        private List<Object> parseArray() {
            expect('[');
            List<Object> list = new ArrayList<>();
            skipWhitespace();
            if (peek(']')) {
                pos++;
                return list;
            }
            while (true) {
                list.add(parseValue());
                skipWhitespace();
                if (peek(']')) {
                    pos++;
                    return list;
                }
                expect(',');
            }
        }

        private String parseString() {
            expect('"');
            StringBuilder out = new StringBuilder();
            while (pos < input.length()) {
                char c = input.charAt(pos++);
                if (c == '"') {
                    return out.toString();
                }
                if (c != '\\') {
                    out.append(c);
                    continue;
                }
                if (pos >= input.length()) {
                    throw new IllegalArgumentException("Invalid JSON escape.");
                }
                char esc = input.charAt(pos++);
                switch (esc) {
                    case '"': out.append('"'); break;
                    case '\\': out.append('\\'); break;
                    case '/': out.append('/'); break;
                    case 'b': out.append('\b'); break;
                    case 'f': out.append('\f'); break;
                    case 'n': out.append('\n'); break;
                    case 'r': out.append('\r'); break;
                    case 't': out.append('\t'); break;
                    case 'u':
                        if (pos + 4 > input.length()) {
                            throw new IllegalArgumentException("Short JSON unicode escape.");
                        }
                        out.append((char) Integer.parseInt(input.substring(pos, pos + 4), 16));
                        pos += 4;
                        break;
                    default:
                        throw new IllegalArgumentException("Unsupported JSON escape: " + esc);
                }
            }
            throw new IllegalArgumentException("Unterminated JSON string.");
        }

        private Number parseNumber() {
            int start = pos;
            if (peekRaw('-')) {
                pos++;
            }
            while (pos < input.length() && Character.isDigit(input.charAt(pos))) {
                pos++;
            }
            return Long.parseLong(input.substring(start, pos));
        }

        private void expect(char expected) {
            skipWhitespace();
            if (pos >= input.length() || input.charAt(pos) != expected) {
                throw new IllegalArgumentException("Expected '" + expected + "' at " + pos);
            }
            pos++;
        }

        private boolean peek(char expected) {
            skipWhitespace();
            return pos < input.length() && input.charAt(pos) == expected;
        }

        private boolean peekRaw(char expected) {
            return pos < input.length() && input.charAt(pos) == expected;
        }

        private void skipWhitespace() {
            while (pos < input.length()) {
                char c = input.charAt(pos);
                if (c != ' ' && c != '\n' && c != '\r' && c != '\t') {
                    return;
                }
                pos++;
            }
        }
    }
}
