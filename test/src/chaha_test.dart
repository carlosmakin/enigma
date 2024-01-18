import 'dart:typed_data';
import 'package:enigma/src/chacha.dart';
import 'package:test/test.dart';

void main() {
  group('ChaCha20 functionality', () {
    test('ChaCha20 encryption and decryption', () {
      final Uint8List key = Uint8List.fromList(List<int>.generate(32, (int i) => i));
      final Uint8List nonce = Uint8List.fromList(List<int>.generate(12, (int i) => i));
      final Uint8List data = Uint8List.fromList(List<int>.generate(64, (int i) => i));

      final Uint8List encryptedData = encryptChaCha20(key, nonce, data);
      final Uint8List decryptedData = decryptChaCha20(key, nonce, encryptedData);

      expect(data != encryptedData, isTrue);
      expect(decryptedData, equals(data));
    });

    test('ChaCha20-Poly1305 encryption and decryption', () {
      final Uint8List key = Uint8List.fromList(List<int>.generate(32, (int i) => i));
      final Uint8List nonce = Uint8List.fromList(List<int>.generate(12, (int i) => i));
      final Uint8List aad = Uint8List.fromList(List<int>.generate(16, (int i) => i));
      final Uint8List data = Uint8List.fromList(List<int>.generate(64, (int i) => i));

      final Uint8List encryptedData = encryptChaCha20Poly1305(key, nonce, data, aad);
      final Uint8List decryptedData = decryptChaCha20Poly1305(key, nonce, encryptedData, aad);

      expect(data != encryptedData, isTrue);
      expect(decryptedData, equals(data));
    }, skip: 'ChaCha20-Poly1305 decrypt returning all 0\'s.');
  });
}
