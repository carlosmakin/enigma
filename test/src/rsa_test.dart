import 'dart:typed_data';
import 'package:enigma/src/random.dart';
import 'package:enigma/src/rsa.dart';
import 'package:pointycastle/api.dart';
import 'package:pointycastle/asymmetric/api.dart';
import 'package:test/test.dart';

void main() {
  group('RSA functionality', () {
    for (final RSAKeyStrength strength in RSAKeyStrength.values) {
      test('RSA key generation - ${strength.bitLength}-bit', () {
        final AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey> keyPair =
            generateRSAKeyPair(getSecureRandom, keyStrength: strength);

        expect(keyPair.publicKey.modulus!.bitLength, greaterThanOrEqualTo(strength.bitLength));
        expect(keyPair.privateKey.modulus!.bitLength, greaterThanOrEqualTo(strength.bitLength));
      });
    }

    for (final RSAKeyStrength strength in RSAKeyStrength.values) {
      test('RSA signing and verification - ${strength.bitLength}-bit', () {
        final AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey> keyPair =
            generateRSAKeyPair(getSecureRandom, keyStrength: strength);
        final Uint8List dataToSign = Uint8List.fromList(List<int>.generate(32, (int i) => i));

        final Uint8List signature = rsaSign(keyPair.privateKey, dataToSign);
        final bool isVerified = rsaVerify(keyPair.publicKey, dataToSign, signature);

        expect(isVerified, isTrue);
      });
    }

    for (final RSAKeyStrength strength in RSAKeyStrength.values) {
      test('RSA encryption and decryption - ${strength.bitLength}-bit', () {
        final AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey> keyPair =
            generateRSAKeyPair(getSecureRandom, keyStrength: strength);
        final Uint8List dataToEncrypt = Uint8List.fromList(List<int>.generate(32, (int i) => i));

        final Uint8List encryptedData = rsaEncrypt(keyPair.publicKey, dataToEncrypt);
        final Uint8List decryptedData = rsaDecrypt(keyPair.privateKey, encryptedData);

        expect(decryptedData, equals(dataToEncrypt));
      });
    }
  });
}
