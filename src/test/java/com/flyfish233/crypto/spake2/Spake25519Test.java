/*
 * Copyright (C) 2021 Muntashir Al-Islam
 * Modified 2025 Flyfish233
 *
 * Licensed according to the LICENSE file in this repository.
 */

package com.flyfish233.crypto.spake2;

import org.junit.Test;

import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

import static org.junit.Assert.*;

public class Spake25519Test {
    private static final byte[] B_EIGHT = HexUtils.hexToBytes("0800000000000000000000000000000000000000000000000000000000000000");

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

    @Test
    public void scalarTestCmov() {
        Spake2Context.Scalar scalar = new Spake2Context.Scalar(HexUtils.hexToBytes(
                "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010"));
        Spake2Context.Scalar zero = new Spake2Context.Scalar();
        assertEquals("0000000000000000000000000000000000000000000000000000000000000000",
                HexUtils.bytesToHex(scalar.cmov(zero, 0).getBytes()));
        assertEquals("0100000000000000000000000000000000000000000000000000000000000000",
                HexUtils.bytesToHex(scalar.cmov(zero, 1).getBytes()));
        assertEquals("0500000000000000040000000400000000000000000000000000000000000000",
                HexUtils.bytesToHex(scalar.cmov(zero, 5).getBytes()));
        assertEquals("0100000010000000100000001000000000000000000000000000000000000000",
                HexUtils.bytesToHex(scalar.cmov(zero, 0x11).getBytes()));
        assertEquals("2100000010000000100000001000000000000000000000000000000000000000",
                HexUtils.bytesToHex(scalar.cmov(zero, 0x31).getBytes()));
        assertEquals("6100000010000000500000005000000000000000000000000000000000000000",
                HexUtils.bytesToHex(scalar.cmov(zero, 0x71).getBytes()));
        assertEquals("e900000018000000d0000000d800000000000000000000000000000000000000",
                HexUtils.bytesToHex(scalar.cmov(zero, 0xF9).getBytes()));
    }

    @Test
    public void scalarTestCmov2() {
        Spake2Context.Scalar scalar = new Spake2Context.Scalar(HexUtils.hexToBytes(
                "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010"));
        Spake2Context.Scalar base = new Spake2Context.Scalar();
        base.copy(scalar.cmov(base, 0));
        assertEquals("0000000000000000000000000000000000000000000000000000000000000000",
                HexUtils.bytesToHex(base.getBytes()));
        base.copy(scalar.cmov(base, 1));
        assertEquals("0100000000000000000000000000000000000000000000000000000000000000",
                HexUtils.bytesToHex(base.getBytes()));
        base.copy(scalar.cmov(base, 5));
        assertEquals("0500000000000000040000000400000000000000000000000000000000000000",
                HexUtils.bytesToHex(base.getBytes()));
        base.copy(scalar.cmov(base, 0x11));
        assertEquals("0500000010000000140000001400000000000000000000000000000000000000",
                HexUtils.bytesToHex(base.getBytes()));
        base.copy(scalar.cmov(base, 0x31));
        assertEquals("2500000010000000140000001400000000000000000000000000000000000000",
                HexUtils.bytesToHex(base.getBytes()));
        base.copy(scalar.cmov(base, 0x71));
        assertEquals("6500000010000000540000005400000000000000000000000000000000000000",
                HexUtils.bytesToHex(base.getBytes()));
        base.copy(scalar.cmov(base, 0xF9));
        assertEquals("ed00000018000000d4000000dc00000000000000000000000000000000000000",
                HexUtils.bytesToHex(base.getBytes()));
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
    public void ephemeralPrivateScalarClearsLowBits() throws Exception {
        byte[] password = "shared password".getBytes(StandardCharsets.UTF_8);
        byte[] privateKey = new byte[64];
        for (int i = 0; i < privateKey.length; ++i) {
            privateKey[i] = (byte) i;
        }

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
            assertTrue(spake2.run());
            if (!spake2.keyMatches()) {
                System.out.printf("Iteration %d: Keys didn't match.\n", i);
            }
        }
    }

    @Test
    public void oldBob() {
        for (int i = 0; i < 20; i++) {
            SPAKE2Run spake2 = new SPAKE2Run();
            assertTrue(spake2.run());
            if (!spake2.keyMatches()) {
                System.out.printf("Iteration %d: Keys didn't match.\n", i);
            }
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
}