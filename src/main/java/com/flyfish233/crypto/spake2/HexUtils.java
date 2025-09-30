/*
 * Copyright (C) 2025 Flyfish233
 *
 * Licensed according to the LICENSE file in this repository.
 */

package com.flyfish233.crypto.spake2;

final class HexUtils {
    private HexUtils() {
    }

    static byte[] hexToBytes(String hex) {
        if (hex == null) {
            throw new IllegalArgumentException("hex string must not be null");
        }
        if ((hex.length() & 1) != 0) {
            throw new IllegalArgumentException("hex string must have even length");
        }
        int len = hex.length();
        byte[] out = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            int hi = Character.digit(hex.charAt(i), 16);
            int lo = Character.digit(hex.charAt(i + 1), 16);
            if (hi == -1 || lo == -1) {
                throw new IllegalArgumentException("invalid hexadecimal character");
            }
            out[i / 2] = (byte) ((hi << 4) | lo);
        }
        return out;
    }

    static String bytesToHex(byte[] data) {
        if (data == null) {
            return null;
        }
        StringBuilder sb = new StringBuilder(data.length * 2);
        for (byte b : data) {
            sb.append(Character.forDigit((b >>> 4) & 0xF, 16));
            sb.append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }
}
