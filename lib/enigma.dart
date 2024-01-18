/// The Enigma Dart package provides a comprehensive suite of cryptographic functionalities, including:
/// - Generation of secure random cryptographic keys and initial vectors (IVs) using the Fortuna algorithm (industry-standard CSPRNG).
/// - Derivation of keys from user-supplied passphrases using PBKDF2 with SHA-256 HMAC (industry-standard method for password-based key derivation).
/// - Encryption and decryption of data using various methods including:
///   - AES encryption in Cipher Block Chaining (CBC) mode, a widely-adopted symmetric encryption standard.
///   - AES encryption in Galois/Counter Mode (GCM), offering authenticated encryption with integrated authentication.
///   - ChaCha20 encryption as specified in RFC 7539, suitable for high-performance streaming data encryption.
///   - ChaCha20-Poly1305 for authenticated encryption, combining confidentiality and data integrity.
/// - Implementation of RSA cryptography, supporting key generation, encryption, decryption, signing, and verification with various key strengths.
/// This package aims to offer robust, efficient, and easy-to-use cryptographic operations for Dart applications.
library enigma;

export 'src/aes.dart';
export 'src/cbc.dart';
export 'src/chacha.dart';
export 'src/gcm.dart';
export 'src/keygen.dart';
export 'src/padding.dart';
export 'src/random.dart';
export 'src/rsa.dart';
