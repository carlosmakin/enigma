// Poly1305

import 'dart:typed_data';

import 'package:enigma/src/chacha20.dart';
import 'package:enigma/src/equality.dart';
import 'package:enigma/src/poly1305.dart';

Uint8List poly1305KeyGen(Uint8List key, Uint8List nonce) {
  return chacha20Block(key.buffer.asUint32List(), 0, nonce.buffer.asUint32List()).sublist(0, 32);
}

/// Encrypts data using ChaCha20 and authenticates with Poly1305 as specified in RFC 7539.
Uint8List chacha20Poly1305Rfc7539Encrypt(
  Uint8List key,
  Uint8List nonce,
  Uint8List data, [
  Uint8List? aad,
]) {
  // Encrypt the data using ChaCha20
  final Uint8List encryptedData = chacha20(key, nonce, data);

  // Generate the Poly1305 key using the ChaCha20 block function with a counter of 0
  final Uint8List poly1305Key = poly1305KeyGen(key, nonce);

  // Create the Poly1305 message for MAC calculation
  aad ??= Uint8List(0);
  final int padLen = (16 - (data.length % 16)) % 16;
  final int aadPadLen = (16 - (aad.length % 16)) % 16;
  final Uint8List macData = Uint8List(aad.length + aadPadLen + encryptedData.length + padLen + 16);
  macData.setAll(0, aad);
  macData.setAll(aad.length + aadPadLen, encryptedData);
  final ByteData lenData = ByteData(16);
  lenData.setUint64(0, aad.length, Endian.little);
  lenData.setUint64(8, data.length, Endian.little);
  macData.setAll(
    aad.length + aadPadLen + encryptedData.length + padLen,
    lenData.buffer.asUint8List(),
  );

  // Calculate the MAC using Poly1305
  Uint8List mac = poly1305Mac(macData, poly1305Key);

  // Append the MAC to the encrypted data
  Uint8List result = Uint8List(encryptedData.length + mac.length);
  result.setAll(0, encryptedData);
  result.setAll(encryptedData.length, mac);

  return result;
}

Uint8List chacha20Poly1305Rfc7539Decrypt(
  Uint8List key,
  Uint8List nonce,
  Uint8List encryptedDataWithMac, [
  Uint8List? aad,
]) {
  if (encryptedDataWithMac.length < 16) {
    throw Exception('Invalid encrypted data length.');
  }

  // Separate the encrypted data and the MAC
  int macStartIndex = encryptedDataWithMac.length - 16;
  Uint8List encryptedData = encryptedDataWithMac.sublist(0, macStartIndex);
  Uint8List mac = encryptedDataWithMac.sublist(macStartIndex);

  // Generate the Poly1305 key using the ChaCha20 block function with a counter of 0
  Uint8List poly1305Key = poly1305KeyGen(key, nonce);

  // Recreate the Poly1305 message for MAC verification
  aad ??= Uint8List(0);
  int padLen = (16 - (encryptedData.length % 16)) % 16;
  int aadPadLen = (16 - (aad.length % 16)) % 16;
  Uint8List macData = Uint8List(aad.length + aadPadLen + encryptedData.length + padLen + 16);
  macData.setAll(0, aad);
  macData.setAll(aad.length + aadPadLen, encryptedData);
  ByteData lenData = ByteData(16);
  lenData.setUint64(0, aad.length, Endian.little);
  lenData.setUint64(8, encryptedData.length, Endian.little);
  macData.setAll(
    aad.length + aadPadLen + encryptedData.length + padLen,
    lenData.buffer.asUint8List(),
  );

  // Calculate and verify the MAC
  final Uint8List calculatedMac = poly1305Mac(macData, poly1305Key);
  if (!secureEquals(mac, calculatedMac)) {
    throw Exception('MAC verification failed.');
  }

  // Decrypt the data using ChaCha20
  return chacha20(key, nonce, encryptedData);
}
