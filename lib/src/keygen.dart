import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:enigma/src/aes.dart';
import 'package:pointycastle/export.dart';

/// Returns a secure random 128-bit initial vector.
/// The purpose of the IV is to ensure that encrypting the same string with the same key produces
/// different ciphertexts. This prevents attackers from recognizing patterns in the encrypted data.
/// The IV doesn't need to be kept secret, but it is crucial that a different IV is used for each
/// encryption operation with the same key.
Uint8List generateRandomIV() => _getSecureRandom.nextBytes(16);

/// Generates a secure random byte array of a specified length.
///
/// This function is essential for cryptographic operations where random data is required.
/// It uses a secure random number generator to produce a byte array of the specified length.
/// The `length` parameter allows flexibility in the size of the generated data, making it suitable
/// for various cryptographic needs like keys, salts, or nonces.
Uint8List generateRandomBytes(int length) => _getSecureRandom.nextBytes(length);

/// /// Returns a secure random key based on the specified AES key strength.
/// - This function generates a cryptographic key of a length corresponding to the AES key strength provided.
/// - The `aesKeyStrength` parameter determines the strength of the key generated, supporting AES-128, AES-192, or AES-256.
Uint8List generateRandomKey(AESKeyStrength strength) =>
    _getSecureRandom.nextBytes(strength.numBytes);

/// A getter that creates and returns a Fortuna secure random number generator.
FortunaRandom get _getSecureRandom {
  // Uses Dart's Random.secure() generator to generate a seed.
  final Random random = Random.secure();
  final List<int> seed = <int>[for (int i = 0; i < 32; i++) random.nextInt(255)];

  // Creates a Fortuna secure random number generator.
  final FortunaRandom secureRandom = FortunaRandom();
  secureRandom.seed(KeyParameter(Uint8List.fromList(seed)));
  return secureRandom;
}

/// Returns a key derived from a given passphrase using PBKDF2.
/// - The `salt` parameter is a string that modifies the key derivation to prevent rainbow table attacks.
/// - The `iterations` parameter determines the number of iterations of the hashing function.
/// A higher count increases resistance against brute force or dictionary attacks but also increases computational cost.
/// - The `aesKeyStrength` parameter is an enum that specifies the AES key strength.
/// It can be AES128, AES192, or AES256, corresponding to 128, 192, or 256 bits respectively.
/// - If unsure about these parameters, it is advisable to use their defaults.
Uint8List deriveKeyFromPassphrase(
  String passphrase, {
  String salt = '',
  int iterations = 10000,
  AESKeyStrength strength = AESKeyStrength.aes256,
}) {
  // Uses PBKDF2 with a SHA-256 HMAC to generate the key.
  final PBKDF2KeyDerivator generator = PBKDF2KeyDerivator(HMac(SHA256Digest(), 64))
    ..init(Pbkdf2Parameters(utf8.encode(salt), iterations, strength.numBytes));

  return generator.process(utf8.encode(passphrase));
}
