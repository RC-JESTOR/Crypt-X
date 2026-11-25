# Crypt-X

![Java](https://img.shields.io/badge/Java-17%2B-00ff66?style=for-the-badge&logo=openjdk&logoColor=white)
![AES-256-GCM](https://img.shields.io/badge/Cipher-AES--256--GCM-00d2ff?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-a855f7?style=for-the-badge)

Zero-trust local file encryption engine engineered in **Java** around **AES-256-GCM** authenticated encryption and **PBKDF2WithHmacSHA256** key derivation. Designed for tamper-resistant single-file document protection with zero cloud dependencies and zero third-party libraries.

---

## Security Architecture

- **Authenticated Encryption (AEAD):** Uses `AES/GCM/NoPadding` with a **256-bit key**, **96-bit random IV**, and **128-bit authentication tag** per file. Header fields (`CRX1` magic, salt, IV) are cryptographically bound via GCM Associated Authenticated Data (AAD), immediately rejecting any modified or corrupted file.
- **Hardened Key Derivation:** Derives unique per-file keys locally using `PBKDF2WithHmacSHA256` with **310,000 iterations** (OWASP recommended) and a **128-bit `SecureRandom` salt**.
- **Zero-Trust Memory Hygiene:** Passphrases (`char[]`) and derived key material (`byte[]`) are explicitly zeroed (`Arrays.fill`) in `finally` blocks after every operation.
- **Streaming I/O:** Processes files in 64 KB chunks via `CipherOutputStream` / `CipherInputStream` so large files encrypt smoothly without high heap usage.

---

## Build & Run (Windows / Linux / macOS)

Requires **JDK 17+** (zero external Maven/Gradle dependencies).

### Windows
```bat
git clone https://github.com/RC-JESTOR/Crypt-X.git
cd Crypt-X
build.bat
java -cp out com.rcjestor.cryptx.Main selftest
```

### Linux / macOS
```bash
git clone https://github.com/RC-JESTOR/Crypt-X.git
cd Crypt-X
chmod +x build.sh && ./build.sh
java -cp out com.rcjestor.cryptx.Main selftest
```

### CLI Commands

```bash
# Encrypt a document into a tamper-evident .crx vault file
java -cp out com.rcjestor.cryptx.Main encrypt secret.pdf secret.pdf.crx

# Inspect container metadata (PBKDF2 iterations, salt, IV)
java -cp out com.rcjestor.cryptx.Main inspect secret.pdf.crx

# Decrypt and verify authentication tag
java -cp out com.rcjestor.cryptx.Main decrypt secret.pdf.crx restored.pdf

# Compute SHA-256 integrity hash
java -cp out com.rcjestor.cryptx.Main hash restored.pdf
```

---

## Project Structure

```text
Crypt-X/
├── build.bat
├── build.sh
└── src/com/rcjestor/cryptx/
    ├── CryptoConfig.java  # CRX1 header spec & OWASP cryptographic parameters
    ├── KeyManager.java    # PBKDF2WithHmacSHA256 derivation & memory wiping
    ├── CryptEngine.java   # Streaming AES-256-GCM encrypt/decrypt & SHA-256
    ├── SelfTest.java      # Automated round-trip, wrong-key & tamper tests
    └── Main.java          # Interactive zero-trust CLI
```

---

## Author

**Navida Sathsindu Wijesooriya (RC-JESTOR)**  
Cyber Security & IT Graduate | National CTF Finalist & Top Performer  
[GitHub](https://github.com/RC-JESTOR) • [LinkedIn](https://www.linkedin.com/in/navida-wijesooriya)
