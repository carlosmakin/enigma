import 'dart:typed_data';

import 'package:enigma/src/aes.dart';
import 'package:enigma/src/keygen.dart';
import 'package:test/test.dart';

void main() {
  final Uint8List iv = generateRandomIV();

  group('Keygen functionality', () {
    test('Keygen generate random IV', () {
      expect(iv.length, equals(16));
    });

    for (final AESKeyStrength strength in AESKeyStrength.values) {
      test('Keygen generate random ${strength.bitLength}-bit key', () {
        final Uint8List key1 = generateRandomKey(strength);
        final Uint8List key2 = generateRandomKey(strength);
        expect(key1 != key2, isTrue);
        expect(key1.length, equals(strength.byteLength));
      });
    }

    for (final AESKeyStrength strength in AESKeyStrength.values) {
      test('PBKDF2 derive ${strength.bitLength}-bit key from passphrase', () {
        final Uint8List key = derivePBKDF2Key('password', iterations: 1, strength: strength);
        expect(key.length, equals(strength.byteLength));
      });
    }

    for (final AESKeyStrength strength in AESKeyStrength.values) {
      test('PBKDF2 derive ${strength.bitLength}-bit key from passphrase with salt', () {
        final Uint8List unsaltedKey =
            derivePBKDF2Key('password', iterations: 1, strength: strength);
        final Uint8List saltedKey =
            derivePBKDF2Key('password', salt: 'salt', iterations: 1, strength: strength);
        expect(saltedKey.length, equals(strength.byteLength));
        expect(saltedKey, isNot(unsaltedKey));
      });
    }

    for (final AESKeyStrength strength in AESKeyStrength.values) {
      test('PBKDF2 ${strength.bitLength}-bit key reproducibility', () {
        final Uint8List key1 = derivePBKDF2Key('password', iterations: 1, strength: strength);
        final Uint8List key2 = derivePBKDF2Key('password', iterations: 1, strength: strength);
        expect(key1, key2);
      });
    }
  });
}
