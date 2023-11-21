import 'dart:convert';
import 'dart:typed_data';

import 'package:enigma/enigma.dart';
import 'package:test/test.dart';

void main() {
  group('enigma keygen', () {
    test('generate random IV', () {
      final Uint8List iv = generateRandomIV();
      expect(iv.length, equals(16));
    });

    test('generate random key', () {
      for (final AESKeyStrength strength in AESKeyStrength.values) {
        final Uint8List key = generateRandomKey(strength);
        expect(key.length, equals(strength.numBytes));
      }
    });

    test('derive key from passphrase', () {
      for (final AESKeyStrength strength in AESKeyStrength.values) {
        final Uint8List key =
            deriveKeyFromPassphrase('password', iterations: 1, strength: strength);
        expect(key.length, equals(strength.numBytes));
      }
    });

    test('derive key from passphrase with salt', () {
      for (final AESKeyStrength strength in AESKeyStrength.values) {
        final Uint8List unsaltedKey =
            deriveKeyFromPassphrase('password', iterations: 1, strength: strength);
        final Uint8List saltedKey =
            deriveKeyFromPassphrase('password', salt: 'bae', iterations: 1, strength: strength);
        expect(saltedKey.length, equals(strength.numBytes));
        expect(saltedKey, isNot(unsaltedKey));
      }
    });

    test('key reproducibility', () {
      for (final AESKeyStrength strength in AESKeyStrength.values) {
        final Uint8List key1 =
            deriveKeyFromPassphrase('password', salt: 'bae', iterations: 1, strength: strength);
        final Uint8List key2 =
            deriveKeyFromPassphrase('password', salt: 'bae', iterations: 1, strength: strength);
        expect(key1, key2);
      }
    });
  });

  group('enigma cryptography', () {
    test('encrypt and decrypt text', () {
      const String original = 'Hello world!';

      final Uint8List iv = generateRandomIV();

      for (final AESKeyStrength strength in AESKeyStrength.values) {
        final Uint8List key = generateRandomKey(strength);
        final String encrypted = encryptText(key: key, iv: iv, text: original);
        final String decrypted = decryptText(key: key, iv: iv, text: encrypted);
        expect(decrypted, equals(original));
      }

      for (final AESKeyStrength strength in AESKeyStrength.values) {
        final Uint8List key = generateRandomKey(strength);
        final String encrypted = encryptTextWithEmbeddedIV(key: key, iv: iv, text: original);
        final String decrypted = decryptTextWithEmbeddedIV(key: key, text: encrypted);
        expect(decrypted, equals(original));
      }
    });

    test('encrypt and decrypt bytes', () {
      final Uint8List original = Uint8List.fromList(utf8.encode('data'));

      final Uint8List iv = generateRandomIV();

      for (final AESKeyStrength strength in AESKeyStrength.values) {
        final Uint8List key = generateRandomKey(strength);
        final Uint8List encrypted = encryptBytes(key: key, iv: iv, data: original);
        final Uint8List decrypted = decryptBytes(key: key, iv: iv, data: encrypted);
        expect(decrypted, equals(original));
      }

      for (final AESKeyStrength strength in AESKeyStrength.values) {
        final Uint8List key = generateRandomKey(strength);
        final Uint8List encrypted = encryptBytesWithEmbeddedIV(key: key, iv: iv, data: original);
        final Uint8List decrypted = decryptBytesWithEmbeddedIV(key: key, data: encrypted);
        expect(decrypted, equals(original));
      }
    });

    test('encrypt and decrypt bytes with isolates', () async {
      final Uint8List original = Uint8List.fromList(List<int>.filled(1024 * 1024, 64));

      final Uint8List iv = generateRandomIV();

      for (final AESKeyStrength strength in AESKeyStrength.values) {
        final Uint8List key = generateRandomKey(strength);
        final Uint8List encrypted = await encryptBytesFast(key: key, iv: iv, data: original);
        final Uint8List decrypted = await decryptBytesFast(key: key, iv: iv, data: encrypted);
        expect(decrypted, equals(original));
      }

      for (final AESKeyStrength strength in AESKeyStrength.values) {
        final Uint8List key = generateRandomKey(strength);
        final Uint8List encrypted =
            await encryptBytesWithEmbeddedIVFast(key: key, iv: iv, data: original);
        final Uint8List decrypted = await decryptBytesWithEmbeddedIVFast(key: key, data: encrypted);
        expect(decrypted, equals(original));
      }
    });
  });
}
