import 'dart:typed_data';

import 'package:enigma/enigma.dart';

void main() {
  // Generate a key and IV
  final Uint8List key = deriveKeyFromPassphrase(
    'passphrase',
    salt: 'com.domain.name',
    iterations: 30000,
    strength: AESKeyStrength.aes256,
  );
  final Uint8List iv = generateRandomIV();

  // Encrypting text
  String encrypted = encryptText(key: key, iv: iv, text: "Hello, world!");
  print("Encrypted: $encrypted");

  // Decrypting text
  String decrypted = decryptText(key: key, cipherText: encrypted);
  print("Decrypted: $decrypted");
}
