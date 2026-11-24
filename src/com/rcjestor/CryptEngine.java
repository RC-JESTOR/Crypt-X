package com.rcjestor.cryptx;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;

/**
 * Streaming AES-256-GCM file encryption, decryption, header inspection, and SHA-256 hashing engine.
 */
public final class CryptEngine {

    public static final class HeaderInfo {
        public final String magic;
        public final int iterations;
        public final byte[] salt;
        public final byte[] iv;

        public HeaderInfo(String magic, int iterations, byte[] salt, byte[] iv) {
            this.magic = magic;
            this.iterations = iterations;
            this.salt = salt;
            this.iv = iv;
        }
    }

    private CryptEngine() {}

    public static void encryptFile(Path inputPath, Path outputPath, char[] password)
            throws IOException, GeneralSecurityException {
        if (!Files.isRegularFile(inputPath)) {
            throw new IOException("Input file not found: " + inputPath);
        }

        byte[] salt = KeyManager.randomBytes(CryptoConfig.SALT_BYTES);
        byte[] iv = KeyManager.randomBytes(CryptoConfig.IV_BYTES);
        int iterations = CryptoConfig.DEFAULT_PBKDF2_ITERATIONS;

        SecretKey key = KeyManager.deriveKey(password, salt, iterations);
        Cipher cipher = Cipher.getInstance(CryptoConfig.CIPHER_ALGO);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(CryptoConfig.GCM_TAG_BITS, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
        // Bind header fields as Associated Authenticated Data (AAD) to prevent header tampering
        cipher.updateAAD(CryptoConfig.MAGIC);
        cipher.updateAAD(salt);
        cipher.updateAAD(iv);

        try (InputStream in = new BufferedInputStream(Files.newInputStream(inputPath), CryptoConfig.BUFFER_SIZE);
             OutputStream rawOut = new BufferedOutputStream(Files.newOutputStream(outputPath), CryptoConfig.BUFFER_SIZE);
             DataOutputStream hdrOut = new DataOutputStream(rawOut)) {

            hdrOut.write(CryptoConfig.MAGIC);
            hdrOut.writeInt(iterations);
            hdrOut.write(salt);
            hdrOut.write(iv);
            hdrOut.flush();

            try (CipherOutputStream cipherOut = new CipherOutputStream(rawOut, cipher)) {
                byte[] buffer = new byte[CryptoConfig.BUFFER_SIZE];
                int read;
                while ((read = in.read(buffer)) != -1) {
                    cipherOut.write(buffer, 0, read);
                }
            }
        } finally {
            KeyManager.wipe(salt);
            KeyManager.wipe(iv);
        }
    }

    public static void decryptFile(Path inputPath, Path outputPath, char[] password)
            throws IOException, GeneralSecurityException {
        if (!Files.isRegularFile(inputPath)) {
            throw new IOException("Encrypted file not found: " + inputPath);
        }

        byte[] salt = new byte[CryptoConfig.SALT_BYTES];
        byte[] iv = new byte[CryptoConfig.IV_BYTES];

        try (InputStream rawIn = new BufferedInputStream(Files.newInputStream(inputPath), CryptoConfig.BUFFER_SIZE);
             DataInputStream hdrIn = new DataInputStream(rawIn)) {

            byte[] magic = new byte[4];
            hdrIn.readFully(magic);
            if (!Arrays.equals(magic, CryptoConfig.MAGIC)) {
                throw new IOException("Invalid Crypt-X file header (expected CRX1 magic bytes).");
            }

            int iterations = hdrIn.readInt();
            if (iterations < 10_000 || iterations > 5_000_000) {
                throw new IOException("Unsupported PBKDF2 iteration count in header: " + iterations);
            }

            hdrIn.readFully(salt);
            hdrIn.readFully(iv);

            SecretKey key = KeyManager.deriveKey(password, salt, iterations);
            Cipher cipher = Cipher.getInstance(CryptoConfig.CIPHER_ALGO);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(CryptoConfig.GCM_TAG_BITS, iv);
            cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);
            cipher.updateAAD(magic);
            cipher.updateAAD(salt);
            cipher.updateAAD(iv);

            Path tempOut = outputPath.resolveSibling(outputPath.getFileName().toString() + ".tmp");
            try (CipherInputStream cipherIn = new CipherInputStream(rawIn, cipher);
                 OutputStream out = new BufferedOutputStream(Files.newOutputStream(tempOut), CryptoConfig.BUFFER_SIZE)) {
                byte[] buffer = new byte[CryptoConfig.BUFFER_SIZE];
                int read;
                while ((read = cipherIn.read(buffer)) != -1) {
                    out.write(buffer, 0, read);
                }
            } catch (IOException ex) {
                Files.deleteIfExists(tempOut);
                if (ex.getCause() instanceof AEADBadTagException) {
                    throw new GeneralSecurityException(
                            "Authentication failed: wrong passphrase or file has been tampered with.",
                            ex.getCause());
                }
                throw ex;
            }

            Files.move(tempOut, outputPath, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        } finally {
            KeyManager.wipe(salt);
            KeyManager.wipe(iv);
        }
    }

    public static HeaderInfo inspectHeader(Path filePath) throws IOException {
        try (DataInputStream in = new DataInputStream(new BufferedInputStream(Files.newInputStream(filePath)))) {
            byte[] magic = new byte[4];
            in.readFully(magic);
            if (!Arrays.equals(magic, CryptoConfig.MAGIC)) {
                throw new IOException("Not a valid Crypt-X (.crx) file.");
            }
            int iterations = in.readInt();
            byte[] salt = new byte[CryptoConfig.SALT_BYTES];
            byte[] iv = new byte[CryptoConfig.IV_BYTES];
            in.readFully(salt);
            in.readFully(iv);
            return new HeaderInfo(new String(magic), iterations, salt, iv);
        }
    }

    public static String sha256Hex(Path filePath) throws IOException, GeneralSecurityException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        try (InputStream in = new BufferedInputStream(Files.newInputStream(filePath), CryptoConfig.BUFFER_SIZE)) {
            byte[] buffer = new byte[CryptoConfig.BUFFER_SIZE];
            int read;
            while ((read = in.read(buffer)) != -1) {
                md.update(buffer, 0, read);
            }
        }
        return toHex(md.digest());
    }

    public static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
