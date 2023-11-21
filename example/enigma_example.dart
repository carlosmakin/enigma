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
  final String encrypted = encryptTextWithEmbeddedIV(key: key, iv: iv, text: "Hello, world!");
  print("Encrypted: $encrypted");

  // Decrypting text
  final String decrypted = decryptTextWithEmbeddedIV(key: key, text: encrypted);
  print("Decrypted: $decrypted");
}
