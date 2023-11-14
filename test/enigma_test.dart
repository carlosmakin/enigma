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
      final Uint8List aes128Key = generateRandomKey(AESKeyStrength.aes128);
      expect(aes128Key.length, equals(16));

      final Uint8List aes192Key = generateRandomKey(AESKeyStrength.aes192);
      expect(aes192Key.length, equals(24));

      final Uint8List aes256Key = generateRandomKey(AESKeyStrength.aes256);
      expect(aes256Key.length, equals(32));
    });

    test('derive key from passphrase', () {
      final Uint8List aes128Key = deriveKeyFromPassphrase('password',
          salt: 'bae', iterations: 1, strength: AESKeyStrength.aes128);
      expect(aes128Key.length, equals(16));

      final Uint8List aes192Key = deriveKeyFromPassphrase('password',
          salt: 'bae', iterations: 1, strength: AESKeyStrength.aes192);
      expect(aes192Key.length, equals(24));

      final Uint8List aes256Key = deriveKeyFromPassphrase('password',
          salt: 'bae', iterations: 1, strength: AESKeyStrength.aes256);
      expect(aes256Key.length, equals(32));
    });

    test('key reproducibility', () {
      final Uint8List aes128KeyInstance1 = deriveKeyFromPassphrase('password',
          salt: 'bae', iterations: 1, strength: AESKeyStrength.aes128);
      final Uint8List aes128KeyInstance2 = deriveKeyFromPassphrase('password',
          salt: 'bae', iterations: 1, strength: AESKeyStrength.aes128);
      expect(aes128KeyInstance1, aes128KeyInstance2);

      final Uint8List aes192KeyInstance1 = deriveKeyFromPassphrase('password',
          salt: 'bae', iterations: 1, strength: AESKeyStrength.aes192);
      final Uint8List aes192KeyInstance2 = deriveKeyFromPassphrase('password',
          salt: 'bae', iterations: 1, strength: AESKeyStrength.aes192);
      expect(aes192KeyInstance1, aes192KeyInstance2);

      final Uint8List aes256KeyInstance1 = deriveKeyFromPassphrase('password',
          salt: 'bae', iterations: 1, strength: AESKeyStrength.aes256);
      final Uint8List aes256KeyInstance2 = deriveKeyFromPassphrase('password',
          salt: 'bae', iterations: 1, strength: AESKeyStrength.aes256);
      expect(aes256KeyInstance1, aes256KeyInstance2);
    });
  });

  group('enigma cryptography', () {
    test('encrypt and decrypt bytes', () {
      final Uint8List data = Uint8List.fromList(utf8.encode('data'));

      final Uint8List iv = generateRandomIV();

      final Uint8List aes128Key = generateRandomKey(AESKeyStrength.aes128);
      final Uint8List aes128Cipher = encryptBytes(key: aes128Key, iv: iv, data: data);
      final Uint8List aes128Data = decryptBytes(key: aes128Key, iv: iv, cipher: aes128Cipher);
      expect(aes128Data, equals(data));

      final Uint8List aes192Key = generateRandomKey(AESKeyStrength.aes192);
      final Uint8List aes192Cipher = encryptBytes(key: aes192Key, iv: iv, data: data);
      final Uint8List aes192Data = decryptBytes(key: aes192Key, iv: iv, cipher: aes192Cipher);
      expect(aes192Data, equals(data));

      final Uint8List aes256Key = generateRandomKey(AESKeyStrength.aes256);
      final Uint8List aes256Cipher = encryptBytes(key: aes256Key, iv: iv, data: data);
      final Uint8List aes256Data = decryptBytes(key: aes256Key, iv: iv, cipher: aes256Cipher);
      expect(aes256Data, equals(data));
    });

    test('encrypt and decrypt text', () {
      const String data = 'Hello world!';

      final Uint8List iv = generateRandomIV();

      final Uint8List aes128Key = generateRandomKey(AESKeyStrength.aes128);
      final String aes128CipherText = encryptText(key: aes128Key, iv: iv, text: data);
      final String aes128Data = decryptText(key: aes128Key, cipherText: aes128CipherText);
      expect(aes128Data, equals(data));

      final Uint8List aes192Key = generateRandomKey(AESKeyStrength.aes192);
      final String aes192CipherText = encryptText(key: aes192Key, iv: iv, text: data);
      final String aes192Data = decryptText(key: aes192Key, cipherText: aes192CipherText);
      expect(aes192Data, equals(data));

      final Uint8List aes256Key = generateRandomKey(AESKeyStrength.aes256);
      final String aes256CipherText = encryptText(key: aes256Key, iv: iv, text: data);
      final String aes256Data = decryptText(key: aes256Key, cipherText: aes256CipherText);
      expect(aes256Data, equals(data));
    });
  });
}
