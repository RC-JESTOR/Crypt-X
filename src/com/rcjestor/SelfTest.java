package com.rcjestor.cryptx;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;

/**
 * Built-in zero-dependency verification suite for Crypt-X AES-256-GCM encryption & tamper detection.
 */
public final class SelfTest {

    private SelfTest() {}

    public static void runAll() throws Exception {
        Path tempDir = Files.createTempDirectory("cryptx-selftest-");
        Path plain = tempDir.resolve("sample.txt");
        Path encrypted = tempDir.resolve("sample.txt.crx");
        Path decrypted = tempDir.resolve("sample.decrypted.txt");
        Path tampered = tempDir.resolve("sample.tampered.crx");
        Path tamperedOut = tempDir.resolve("tampered.out");

        String message = "RC-JESTOR Zero-Trust AES-256-GCM Verification Payload :: 2026";
        Files.writeString(plain, message, StandardCharsets.UTF_8);

        char[] pass = "StrongTestPassphrase!2026".toCharArray();
        char[] wrongPass = "WrongPassphrase!0000".toCharArray();

        try {
            // 1. Encrypt & Decrypt Round-Trip
            CryptEngine.encryptFile(plain, encrypted, pass.clone());
            CryptEngine.HeaderInfo hdr = CryptEngine.inspectHeader(encrypted);
            if (!"CRX1".equals(hdr.magic) || hdr.iterations != CryptoConfig.DEFAULT_PBKDF2_ITERATIONS) {
                throw new AssertionError("Header verification failed.");
            }

            CryptEngine.decryptFile(encrypted, decrypted, pass.clone());
            String origHash = CryptEngine.sha256Hex(plain);
            String decHash = CryptEngine.sha256Hex(decrypted);
            if (!origHash.equals(decHash)) {
                throw new AssertionError("SHA-256 mismatch after round-trip decryption!");
            }
            System.out.println("[PASS] 1/3 AES-256-GCM round-trip encryption & SHA-256 integrity verified.");

            // 2. Wrong Passphrase Rejection
            boolean wrongRejected = false;
            try {
                CryptEngine.decryptFile(encrypted, tamperedOut, wrongPass.clone());
            } catch (GeneralSecurityException expected) {
                wrongRejected = true;
            }
            if (!wrongRejected) {
                throw new AssertionError("Wrong passphrase was not rejected!");
            }
            System.out.println("[PASS] 2/3 Wrong passphrase cleanly rejected by GCM auth tag.");

            // 3. Ciphertext Tampering Detection
            byte[] bytes = Files.readAllBytes(encrypted);
            bytes[bytes.length - 1] ^= 0xFF; // Flip bits in auth tag / ciphertext
            Files.write(tampered, bytes);

            boolean tamperRejected = false;
            try {
                CryptEngine.decryptFile(tampered, tamperedOut, pass.clone());
            } catch (GeneralSecurityException expected) {
                tamperRejected = true;
            }
            if (!tamperRejected) {
                throw new AssertionError("Tampered ciphertext was not detected!");
            }
            System.out.println("[PASS] 3/3 Tampered ciphertext cleanly detected & rejected.");
            System.out.println("\n[+] All Crypt-X zero-trust self-tests passed.");
        } finally {
            KeyManager.wipe(pass);
            KeyManager.wipe(wrongPass);
            Files.deleteIfExists(plain);
            Files.deleteIfExists(encrypted);
            Files.deleteIfExists(decrypted);
            Files.deleteIfExists(tampered);
            Files.deleteIfExists(tamperedOut);
            Files.deleteIfExists(tempDir);
        }
    }
}
