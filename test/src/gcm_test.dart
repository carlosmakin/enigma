import 'dart:typed_data';
import 'package:enigma/src/aes.dart';
import 'package:enigma/src/gcm.dart';
import 'package:test/test.dart';

void main() {
  group('AES-GCM functionality', () {
    final Uint8List nonce = Uint8List.fromList(List<int>.generate(12, (int i) => i));
    final Uint8List aad = Uint8List.fromList(List<int>.generate(16, (int i) => i));
    final Uint8List data = Uint8List.fromList(List<int>.generate(64, (int i) => i));

    for (final AESKeyStrength strength in AESKeyStrength.values) {
      test('AES-GCM encryption and decryption with ${strength.bitLength}-bit key', () {
        final Uint8List key = Uint8List.fromList(
          List<int>.generate(strength.byteLength, (int i) => i),
        );

        final Uint8List encryptedData = encryptAesGcm(key, nonce, data, aad);
        final Uint8List decryptedData = decryptAesGcm(key, nonce, encryptedData, aad);

        expect(data != encryptedData, isTrue);
        expect(decryptedData, equals(data));
      });
    }
  });
}
