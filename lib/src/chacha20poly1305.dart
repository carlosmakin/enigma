// Poly1305

import 'dart:typed_data';

import 'package:enigma/src/chacha20.dart';
import 'package:enigma/src/equality.dart';
import 'package:enigma/src/poly1305.dart';

Uint8List poly1305KeyGen(Uint8List key, Uint8List nonce) {
  return chacha20Block(key.buffer.asUint32List(), 0, nonce.buffer.asUint32List()).sublist(0, 32);
}

/// Encrypts data using ChaCha20 and authenticates with Poly1305 as specified in RFC 8439
Uint8List chacha20Poly1305Encrypt(
  Uint8List key,
  Uint8List nonce,
  Uint8List data, [
  Uint8List? aad,
]) {
  // Generate the Poly1305 one-time-key using the ChaCha20 block function with a counter of 0
  final Uint8List otk = poly1305KeyGen(key, nonce);

  // Encrypt the data using ChaCha20
  final Uint8List ciphertext = chacha20(key, nonce, data, 1);

  // Create the Poly1305 message for MAC tag calculation
  aad ??= Uint8List(0);
  final int padLen = (16 - (data.length % 16)) % 16;
  final int aadPadLen = (16 - (aad.length % 16)) % 16;

  final Uint8List macData = Uint8List(aad.length + aadPadLen + ciphertext.length + padLen + 16);
  macData.setAll(0, aad);
  macData.setAll(aad.length + aadPadLen, ciphertext);

  final ByteData lenData = ByteData(16);
  lenData.setUint64(0, aad.length, Endian.little);
  lenData.setUint64(8, data.length, Endian.little);

  macData.setAll(
    aad.length + aadPadLen + ciphertext.length + padLen,
    lenData.buffer.asUint8List(),
  );

  // Calculate the MAC tag using Poly1305
  final Uint8List tag = poly1305Mac(macData, otk);

  // The output from the AEAD is the concatenation of:
  // - A ciphertext of the same length as the plaintext
  // - A 128-bit tag, which is the output of the Poly1305 function
  final Uint8List result = Uint8List(ciphertext.length + 16);
  result.setAll(0, ciphertext);
  result.setAll(ciphertext.length, tag);

  return result;
}

/// Decrypts data using ChaCha20 and authenticates with Poly1305 as specified in RFC 8439
Uint8List chacha20Poly1305Decrypt(
  Uint8List key,
  Uint8List nonce,
  Uint8List data, [
  Uint8List? aad,
]) {
  if (data.length < 16) {
    throw Exception('Invalid encrypted data length.');
  }

  // Generate the Poly1305 one-time-key using the ChaCha20 block function with a counter of 0
  final Uint8List otk = poly1305KeyGen(key, nonce);

  // Separate the encrypted data and the MAC tag
  final Uint8List ciphertext = Uint8List.view(data.buffer, 0, data.length - 16);
  final Uint8List tag = Uint8List.view(data.buffer, data.length - 16);

  // Recreate the Poly1305 message for MAC tag verification
  aad ??= Uint8List(0);
  final int padLen = (16 - (ciphertext.length % 16)) % 16;
  final int aadPadLen = (16 - (aad.length % 16)) % 16;

  final Uint8List macData = Uint8List(aad.length + aadPadLen + ciphertext.length + padLen + 16);
  macData.setAll(0, aad);
  macData.setAll(aad.length + aadPadLen, ciphertext);

  final ByteData lenData = ByteData(16);
  lenData.setUint64(0, aad.length, Endian.little);
  lenData.setUint64(8, ciphertext.length, Endian.little);

  macData.setAll(
    aad.length + aadPadLen + ciphertext.length + padLen,
    lenData.buffer.asUint8List(),
  );

  // Calculate and verify the MAC tag
  if (!secureEquals(tag, poly1305Mac(macData, otk))) {
    throw Exception('MAC verification failed.');
  }

  // Decrypt the data using ChaCha20
  return chacha20(key, nonce, ciphertext);
}
