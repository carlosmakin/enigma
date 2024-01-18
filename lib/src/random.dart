import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/api.dart';
import 'package:pointycastle/random/fortuna_random.dart';

/// Generates a secure random byte array of a specified length.
///
/// This function is essential for cryptographic operations where random data is required.
/// It uses a secure random number generator to produce a byte array of the specified length.
/// The `length` parameter allows flexibility in the size of the generated data, making it suitable
/// for various cryptographic needs like keys, salts, or nonces.
Uint8List generateRandomBytes(int length) => getSecureRandom.nextBytes(length);

/// A getter that creates and returns a SecureRandom number generator.
SecureRandom get getSecureRandom {
  final Random random = Random.secure();
  final List<int> seed = <int>[for (int i = 0; i < 32; i++) random.nextInt(255)];
  final FortunaRandom secureRandom = FortunaRandom();
  secureRandom.seed(KeyParameter(Uint8List.fromList(seed)));
  return secureRandom;
}
