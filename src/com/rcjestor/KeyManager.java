package com.rcjestor.cryptx;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Zero-trust local key derivation & secure memory zeroing helper.
 * Passwords and raw derived keys never leave local process memory and are wiped after use.
 */
public final class KeyManager {
    private static final SecureRandom RNG = new SecureRandom();

    private KeyManager() {}

    public static byte[] randomBytes(int length) {
        byte[] out = new byte[length];
        RNG.nextBytes(out);
        return out;
    }

    public static SecretKey deriveKey(char[] password, byte[] salt, int iterations)
            throws GeneralSecurityException {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, CryptoConfig.KEY_BITS);
        byte[] rawKey = null;
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(CryptoConfig.KDF_ALGO);
            rawKey = factory.generateSecret(spec).getEncoded();
            return new SecretKeySpec(rawKey, CryptoConfig.KEY_ALGO);
        } finally {
            spec.clearPassword();
            if (rawKey != null) {
                Arrays.fill(rawKey, (byte) 0);
            }
        }
    }

    public static void wipe(char[] data) {
        if (data != null) {
            Arrays.fill(data, '\0');
        }
    }

    public static void wipe(byte[] data) {
        if (data != null) {
            Arrays.fill(data, (byte) 0);
        }
    }
}
