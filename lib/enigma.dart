/// This utility file contains  methods to:
/// - Generate secure random cryptographic keys and initial vectors (IVs) using the Fortuna algorithm (industry-standard CSPRNG).
/// - Derive keys from user-supplied passphrases using PBKDF2 with SHA-256 HMAC (industry-standard method for password-based key derivation).
/// - Encrypt and decrypt data using AES encryption with Cipher Block Chaining (CBC) mode (widely-adopted symmetric encryption standard).
library enigma;

export 'src/aes.dart';
export 'src/keygen.dart';
export 'src/operations.dart';
