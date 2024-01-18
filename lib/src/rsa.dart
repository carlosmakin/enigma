import 'dart:typed_data';
import 'package:pointycastle/export.dart';

/// Enum representing various RSA key strengths.
///
/// Provides options for different RSA key sizes, allowing flexibility
/// in balancing security requirements and computational efficiency.
enum RSAKeyStrength {
  rsa2048(2048),
  rsa3072(3072),
  rsa4096(4096);

  final int bitLength;

  const RSAKeyStrength(this.bitLength);
}

/// Generates an RSA key pair with a specified key strength.
///
/// Uses Pointy Castle's RSA key generator to create a public/private key pair.
/// SecureRandom is used to ensure cryptographic strength in key generation.
AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey> generateRSAKeyPair(
  SecureRandom secureRandom, {
  RSAKeyStrength keyStrength = RSAKeyStrength.rsa2048,
}) {
  final RSAKeyGenerator keyGen = RSAKeyGenerator()
    ..init(ParametersWithRandom<RSAKeyGeneratorParameters>(
        RSAKeyGeneratorParameters(BigInt.parse('65537'), keyStrength.bitLength, 64), secureRandom));

  final AsymmetricKeyPair<PublicKey, PrivateKey> pair = keyGen.generateKeyPair();
  final RSAPublicKey myPublic = pair.publicKey as RSAPublicKey;
  final RSAPrivateKey myPrivate = pair.privateKey as RSAPrivateKey;

  return AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey>(myPublic, myPrivate);
}

/// Signs data using a private RSA key.
///
/// The data to sign is first hashed using SHA-256, then signed with RSA.
/// The RSA signature is returned as a byte array.
Uint8List rsaSign(RSAPrivateKey privateKey, Uint8List data) {
  final RSASigner signer = RSASigner(SHA256Digest(), '0609608648016503040201');
  signer.init(true, PrivateKeyParameter<RSAPrivateKey>(privateKey));
  return signer.generateSignature(data).bytes;
}

/// Verifies an RSA signature using a public key.
///
/// Checks if the provided signature corresponds to the hash of the data,
/// confirming the data's integrity and authenticity.
bool rsaVerify(RSAPublicKey publicKey, Uint8List data, Uint8List signature) {
  final RSASigner verifier = RSASigner(SHA256Digest(), '0609608648016503040201');
  verifier.init(false, PublicKeyParameter<RSAPublicKey>(publicKey));
  return verifier.verifySignature(data, RSASignature(signature));
}

/// Encrypts data using RSA public key with OAEP padding.
///
/// Splits the data into blocks and processes each using RSA OAEP encryption.
/// Returns the concatenated encrypted blocks.
Uint8List rsaEncrypt(RSAPublicKey publicKey, Uint8List data) {
  final OAEPEncoding encryptor = OAEPEncoding(RSAEngine())
    ..init(true, PublicKeyParameter<RSAPublicKey>(publicKey));
  return encryptor.process(data);
}

/// Decrypts data using RSA private key with OAEP padding.
///
/// Splits the encrypted data into blocks and processes each using RSA OAEP decryption.
/// Returns the concatenated decrypted blocks.
Uint8List rsaDecrypt(RSAPrivateKey privateKey, Uint8List data) {
  final OAEPEncoding decryptor = OAEPEncoding(RSAEngine())
    ..init(false, PrivateKeyParameter<RSAPrivateKey>(privateKey));
  return decryptor.process(data);
}
