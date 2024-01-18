import 'dart:convert';
import 'dart:typed_data';

import 'package:enigma/enigma.dart';
import 'package:test/test.dart';

void main() {
  final Uint8List iv = generateRandomIV();

  group('enigma keygen', () {
    test('generate random IV', () {
      expect(iv.length, equals(16));
    });

    for (final AESKeyStrength strength in AESKeyStrength.values) {
      test('generate random ${strength.numBits}-bit key', () {
        final Uint8List key = generateRandomKey(strength);
        expect(key.length, equals(strength.numBytes));
      });
    }

    for (final AESKeyStrength strength in AESKeyStrength.values) {
      test('derive ${strength.numBits}-bit key from passphrase', () {
        final Uint8List key =
            deriveKeyFromPassphrase('password', iterations: 1, strength: strength);
        expect(key.length, equals(strength.numBytes));
      });
    }

    for (final AESKeyStrength strength in AESKeyStrength.values) {
      test('derive ${strength.numBits}-bit key from passphrase with salt', () {
        final Uint8List unsaltedKey =
            deriveKeyFromPassphrase('password', iterations: 1, strength: strength);
        final Uint8List saltedKey =
            deriveKeyFromPassphrase('password', salt: 'salt', iterations: 1, strength: strength);
        expect(saltedKey.length, equals(strength.numBytes));
        expect(saltedKey, isNot(unsaltedKey));
      });
    }

    for (final AESKeyStrength strength in AESKeyStrength.values) {
      test('${strength.numBits}-bit key reproducibility', () {
        final Uint8List key1 =
            deriveKeyFromPassphrase('password', salt: 'salt', iterations: 1, strength: strength);
        final Uint8List key2 =
            deriveKeyFromPassphrase('password', salt: 'salt', iterations: 1, strength: strength);
        expect(key1, key2);
      });
    }
  });

  group('enigma cryptography', () {
    const String text = 'Hello world!';
    final Uint8List smallBytes = Uint8List.fromList(utf8.encode('data'));
    final Uint8List largeBytes = Uint8List.fromList(List<int>.generate(1024 * 1024, (int i) => i));

    for (final AESKeyStrength strength in AESKeyStrength.values) {
      final Uint8List key = generateRandomKey(strength);

      test('encrypt/decrypt text with ${strength.numBits}-bit key', () {
        final String encrypted = encryptText(key: key, iv: iv, text: text);
        final String decrypted = decryptText(key: key, iv: iv, text: encrypted);
        expect(decrypted, equals(text));

        final String encryptedWithIV = encryptTextWithEmbeddedIV(key: key, iv: iv, text: text);
        final String decryptedWithIV = decryptTextWithEmbeddedIV(key: key, text: encryptedWithIV);
        expect(decryptedWithIV, equals(text));
      });
    }

    for (final AESKeyStrength strength in AESKeyStrength.values) {
      final Uint8List key = generateRandomKey(strength);

      test('encrypt/decrypt bytes with ${strength.numBits}-bit key', () {
        final Uint8List encrypted = encryptBytes(key: key, iv: iv, data: smallBytes);
        final Uint8List decrypted = decryptBytes(key: key, iv: iv, data: encrypted);
        expect(decrypted, equals(smallBytes));

        final Uint8List encryptedWithIV =
            encryptBytesWithEmbeddedIV(key: key, iv: iv, data: smallBytes);
        final Uint8List decryptedWithIV =
            decryptBytesWithEmbeddedIV(key: key, data: encryptedWithIV);
        expect(decryptedWithIV, equals(smallBytes));
      });
    }

    for (final AESKeyStrength strength in AESKeyStrength.values) {
      final Uint8List key = generateRandomKey(strength);

      test('encrypt/decrypt bytes with ${strength.numBits}-bit key concurrently', () async {
        final Uint8List encrypted = await encryptBytesFast(key: key, iv: iv, data: largeBytes);
        final Uint8List decrypted = await decryptBytesFast(key: key, iv: iv, data: encrypted);
        expect(decrypted, equals(largeBytes));

        final Uint8List encryptedWithIV =
            await encryptBytesWithEmbeddedIVFast(key: key, iv: iv, data: largeBytes);
        final Uint8List decryptedWithIV =
            await decryptBytesWithEmbeddedIVFast(key: key, data: encryptedWithIV);
        expect(decryptedWithIV, equals(largeBytes));
      });
    }
  });
}
