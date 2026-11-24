package com.rcjestor.cryptx;

import java.io.Console;
import java.nio.file.Path;
import java.util.Scanner;

/**
 * Crypt-X CLI — Zero-Trust Local AES-256-GCM File Encryption Utility.
 */
public final class Main {

    private static void printUsage() {
        System.out.println("Crypt-X v1.0.0 -- Zero-Trust AES-256-GCM File Encryption Utility");
        System.out.println("Usage:");
        System.out.println("  java -cp out com.rcjestor.cryptx.Main encrypt <input_file> <output_file.crx>");
        System.out.println("  java -cp out com.rcjestor.cryptx.Main decrypt <input_file.crx> <output_file>");
        System.out.println("  java -cp out com.rcjestor.cryptx.Main inspect <file.crx>");
        System.out.println("  java -cp out com.rcjestor.cryptx.Main hash <file>");
        System.out.println("  java -cp out com.rcjestor.cryptx.Main selftest");
    }

    private static char[] promptPassword(String label) {
        Console console = System.console();
        if (console != null) {
            return console.readPassword("%s", label);
        }
        System.out.print(label);
        Scanner sc = new Scanner(System.in);
        return sc.nextLine().toCharArray();
    }

    public static void main(String[] args) {
        if (args.length == 0) {
            printUsage();
            return;
        }

        String cmd = args[0].toLowerCase();
        char[] password = null;

        try {
            switch (cmd) {
                case "encrypt": {
                    if (args.length < 3) { printUsage(); return; }
                    Path in = Path.of(args[1]);
                    Path out = Path.of(args[2]);
                    password = promptPassword("Enter encryption passphrase: ");
                    CryptEngine.encryptFile(in, out, password);
                    System.out.println("[+] Encrypted -> " + out.toAbsolutePath());
                    System.out.println("    SHA-256   : " + CryptEngine.sha256Hex(out));
                    break;
                }
                case "decrypt": {
                    if (args.length < 3) { printUsage(); return; }
                    Path in = Path.of(args[1]);
                    Path out = Path.of(args[2]);
                    password = promptPassword("Enter decryption passphrase: ");
                    CryptEngine.decryptFile(in, out, password);
                    System.out.println("[+] Decrypted & Verified -> " + out.toAbsolutePath());
                    System.out.println("    SHA-256              : " + CryptEngine.sha256Hex(out));
                    break;
                }
                case "inspect": {
                    if (args.length < 2) { printUsage(); return; }
                    CryptEngine.HeaderInfo h = CryptEngine.inspectHeader(Path.of(args[1]));
                    System.out.println("[ CRYPT-X CONTAINER HEADER ]");
                    System.out.println("  Format Magic : " + h.magic);
                    System.out.println("  Cipher       : " + CryptoConfig.CIPHER_ALGO + " (256-bit)");
                    System.out.println("  KDF          : " + CryptoConfig.KDF_ALGO + " (" + h.iterations + " iterations)");
                    System.out.println("  Salt (hex)   : " + CryptEngine.toHex(h.salt));
                    System.out.println("  IV   (hex)   : " + CryptEngine.toHex(h.iv));
                    break;
                }
                case "hash": {
                    if (args.length < 2) { printUsage(); return; }
                    System.out.println("SHA-256: " + CryptEngine.sha256Hex(Path.of(args[1])));
                    break;
                }
                case "selftest": {
                    SelfTest.runAll();
                    break;
                }
                default:
                    printUsage();
            }
        } catch (Exception ex) {
            System.err.println("[!] Error: " + ex.getMessage());
            System.exit(1);
        } finally {
            KeyManager.wipe(password);
        }
    }
}
