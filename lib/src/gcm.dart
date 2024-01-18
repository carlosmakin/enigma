import 'dart:typed_data';

import 'package:pointycastle/export.dart';

/// Encrypts data using AES-GCM mode with the specified key, nonce, AAD, and mode (encrypt/decrypt).
Uint8List encryptAesGcm(Uint8List key, Uint8List nonce, Uint8List bytes, Uint8List? aad) {
  // Assert that the input lengths are valid.
  assert(<int>[128, 192, 256].contains(key.length * 8));
  assert(nonce.length <= 12); // nonce should not exceed 12 bytes for GCM.

  // Creates a GCM block cipher with AES, and initializes it with the key, nonce, and AAD.
  final GCMBlockCipher gcm = GCMBlockCipher(AESEngine())
    ..init(true, AEADParameters<KeyParameter>(KeyParameter(key), 128, nonce, aad ?? Uint8List(0)));

  return gcm.process(bytes);
}

/// Decrypts data using AES-GCM mode with the specified key, nonce, AAD, and mode (encrypt/decrypt).
Uint8List decryptAesGcm(Uint8List key, Uint8List nonce, Uint8List bytes, Uint8List? aad) {
  // Assert that the input lengths are valid.
  assert(<int>[128, 192, 256].contains(key.length * 8));
  assert(nonce.length <= 12); // nonce should not exceed 12 bytes for GCM.

  // Creates a GCM block cipher with AES, and initializes it with the key, nonce, and AAD.
  final GCMBlockCipher gcm = GCMBlockCipher(AESEngine())
    ..init(false, AEADParameters<KeyParameter>(KeyParameter(key), 128, nonce, aad ?? Uint8List(0)));

  return gcm.process(bytes);
}
