import 'dart:convert';
import 'dart:typed_data';

import 'package:enigma/src/aes.dart';
import 'package:enigma/src/random.dart';
import 'package:pointycastle/export.dart';

/// Returns a secure random 128-bit initial vector.
/// The purpose of the IV is to ensure that encrypting the same string with the same key produces
/// different ciphertexts. This prevents attackers from recognizing patterns in the encrypted data.
/// The IV doesn't need to be kept secret, but it is crucial that a different IV is used for each
/// encryption operation with the same key.
Uint8List generateRandomIV() => getSecureRandom.nextBytes(16);

/// /// Returns a secure random key based on the specified AES key strength.
/// - This function generates a cryptographic key of a length corresponding to the AES key strength provided.
/// - The `aesKeyStrength` parameter determines the strength of the key generated, supporting AES-128, AES-192, or AES-256.
Uint8List generateRandomKey(AESKeyStrength strength) =>
    getSecureRandom.nextBytes(strength.byteLength);

/// Returns a key derived from a given passphrase using PBKDF2.
/// - The `salt` parameter is a string that modifies the key derivation to prevent rainbow table attacks.
/// - The `iterations` parameter determines the number of iterations of the hashing function.
/// A higher count increases resistance against brute force or dictionary attacks but also increases computational cost.
/// - The `aesKeyStrength` parameter is an enum that specifies the AES key strength.
/// It can be AES128, AES192, or AES256, corresponding to 128, 192, or 256 bits respectively.
/// - If unsure about these parameters, it is advisable to use their defaults.
Uint8List derivePBKDF2Key(
  String passphrase, {
  String salt = '',
  int iterations = 10000,
  AESKeyStrength strength = AESKeyStrength.aes256,
}) {
  // Uses PBKDF2 with a SHA-256 HMAC to generate the key.
  final PBKDF2KeyDerivator generator = PBKDF2KeyDerivator(HMac(SHA256Digest(), 64))
    ..init(Pbkdf2Parameters(utf8.encode(salt), iterations, strength.byteLength));

  return generator.process(utf8.encode(passphrase));
}
