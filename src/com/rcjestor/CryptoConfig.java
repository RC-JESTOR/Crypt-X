package com.rcjestor.cryptx;

/**
 * Cryptographic constants for the Crypt-X Zero-Trust AES-256-GCM container format.
 *
 * Binary header layout (.crx v1):
 *   [0..3]   Magic bytes: "CRX1" (4 bytes)
 *   [4..7]   PBKDF2 iteration count (big-endian int, 4 bytes)
 *   [8..23]  Random PBKDF2 salt (16 bytes)
 *   [24..35] Random AES-GCM nonce/IV (12 bytes)
 *   [36..]   AES-256-GCM ciphertext + 128-bit authentication tag
 */
public final class CryptoConfig {
    public static final byte[] MAGIC = new byte[] { 'C', 'R', 'X', '1' };
    public static final String CIPHER_ALGO = "AES/GCM/NoPadding";
    public static final String KDF_ALGO = "PBKDF2WithHmacSHA256";
    public static final String KEY_ALGO = "AES";

    public static final int KEY_BITS = 256;
    public static final int GCM_TAG_BITS = 128;
    public static final int SALT_BYTES = 16;
    public static final int IV_BYTES = 12;
    public static final int DEFAULT_PBKDF2_ITERATIONS = 310_000;
    public static final int BUFFER_SIZE = 65_536;

    private CryptoConfig() {}
}
