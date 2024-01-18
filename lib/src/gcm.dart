import 'dart:typed_data';

import 'package:pointycastle/export.dart';

/// Encrypts or decrypts data using AES-GCM mode with the specified key, IV, AAD, and mode (encrypt/decrypt).
Uint8List processAesGcm(
  Uint8List key,
  Uint8List iv,
  Uint8List bytes,
  Uint8List? aad,
  bool encrypt,
) {
  // Assert that the input lengths are valid.
  assert(<int>[128, 192, 256].contains(key.length * 8));
  assert(iv.length <= 12); // IV should not exceed 12 bytes for GCM.

  // Creates a GCM block cipher with AES, and initializes it with the key, IV, and AAD.
  final GCMBlockCipher gcm = GCMBlockCipher(AESEngine());
  gcm.init(encrypt, AEADParameters<KeyParameter>(KeyParameter(key), 128, iv, aad ?? Uint8List(0)));

  // Allocates space for the output result.
  Uint8List output = Uint8List(gcm.getOutputSize(bytes.length));

  // Processes the bytes.
  int len = gcm.processBytes(bytes, 0, bytes.length, output, 0);
  len += gcm.doFinal(output, len);

  return output.sublist(0, len);
}
