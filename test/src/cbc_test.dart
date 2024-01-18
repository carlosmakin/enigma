import 'dart:typed_data';
import 'package:enigma/src/aes.dart';
import 'package:enigma/src/cbc.dart';
import 'package:enigma/src/padding.dart';
import 'package:test/test.dart';

void main() {
  group('AES-CBC functionality', () {
    final Uint8List iv = Uint8List.fromList(List<int>.generate(16, (int i) => i));
    final Uint8List data = Uint8List.fromList(List<int>.generate(64, (int i) => i));

    for (final AESKeyStrength strength in AESKeyStrength.values) {
      test('AES-CBC encryption and decryption with ${strength.bitLength}-bit key', () {
        final Uint8List key = Uint8List.fromList(
          List<int>.generate(strength.byteLength, (int i) => i),
        );

        final Uint8List paddedData = pad(data, aesBlockSize);
        final Uint8List encryptedData = encryptAesCbc(key, iv, paddedData);
        final Uint8List decryptedData = decryptAesCbc(key, iv, encryptedData);
        final Uint8List unpaddedDecryptedData = unpad(decryptedData);

        expect(paddedData != encryptedData, isTrue);
        expect(encryptedData.length % aesBlockSize, equals(0));
        expect(decryptedData.length % aesBlockSize, equals(0));
        expect(unpaddedDecryptedData, equals(data));
      });
    }
  });
}
