import 'dart:convert';
import 'dart:typed_data';

import 'package:enigma/src/aes.dart';
import 'package:enigma/src/cbc.dart';

/// Returns a base64-encoded ciphertext from the given plaintext for easier transmission and storage.
String encryptText({required Uint8List key, required Uint8List iv, required String text}) {
  return base64.encode(
    encryptBytes(key: key, iv: iv, data: utf8.encode(text) as Uint8List),
  );
}

/// Returns decrypted plaintext from the given ciphertext.
String decryptText({required Uint8List key, required Uint8List iv, required String text}) {
  return utf8.decode(
    decryptBytes(key: key, iv: iv, data: base64.decode(text)),
  );
}

/// Returns a base64-encoded cipher from the given plaintext for easier transmission and storage.
String encryptTextWithEmbeddedIV(
    {required Uint8List key, required Uint8List iv, required String text}) {
  return base64.encode(
    encryptBytesWithEmbeddedIV(key: key, iv: iv, data: utf8.encode(text) as Uint8List),
  );
}

/// Returns decrypted plaintext from the given ciphertext.
String decryptTextWithEmbeddedIV({required Uint8List key, required String text}) {
  return utf8.decode(
    decryptBytesWithEmbeddedIV(key: key, data: base64.decode(text)),
  );
}

/// Returns encrypted data using AES-CBC mode with the specified key and IV.
Uint8List encryptBytes({
  required Uint8List key,
  required Uint8List iv,
  required Uint8List data,
}) {
  final Uint8List paddedBytes = pad(data, aesBlockSize);
  return processAesCbc(key, iv, paddedBytes, true);
}

/// Returns decrypted data using AES-CBC mode with the specified key and IV.
Uint8List decryptBytes({
  required Uint8List key,
  required Uint8List iv,
  required Uint8List data,
}) {
  return unpad(processAesCbc(key, iv, data, false));
}

/// Returns encrypted data using AES-CBC mode with the specified key and IV.
Uint8List encryptBytesWithEmbeddedIV({
  required Uint8List key,
  required Uint8List iv,
  required Uint8List data,
}) {
  final Uint8List paddedBytes = pad(data, aesBlockSize);
  final Uint8List cipher = processAesCbc(key, iv, paddedBytes, true);
  return Uint8List(iv.length + cipher.length)
    ..setRange(0, iv.length, iv)
    ..setRange(iv.length, iv.length + cipher.length, cipher);
}

/// Returns decrypted data using AES-CBC mode with the specified key and embedded IV.
Uint8List decryptBytesWithEmbeddedIV({
  required Uint8List key,
  required Uint8List data,
}) {
  final Uint8List iv = data.sublist(0, 16);
  final Uint8List cipher = data.sublist(16);
  return unpad(processAesCbc(key, iv, cipher, false));
}

/// Returns encrypted data using AES-CBC mode with the specified key and IV.
Future<Uint8List> encryptBytesFast({
  required Uint8List key,
  required Uint8List iv,
  required Uint8List data,
}) async {
  final Uint8List paddedBytes = pad(data, aesBlockSize);
  return processAesCbcWithIsolates(key, iv, paddedBytes, true);
}

/// Returns decrypted data using AES-CBC mode with the specified key and IV.
Future<Uint8List> decryptBytesFast({
  required Uint8List key,
  required Uint8List iv,
  required Uint8List data,
}) async {
  return unpad(await processAesCbcWithIsolates(key, iv, data, false));
}

/// Returns encrypted data using AES-CBC mode with the specified key and IV.
Future<Uint8List> encryptBytesWithEmbeddedIVFast({
  required Uint8List key,
  required Uint8List iv,
  required Uint8List data,
}) async {
  final Uint8List paddedBytes = pad(data, aesBlockSize);
  final Uint8List cipher = await processAesCbcWithIsolates(key, iv, paddedBytes, true);
  return Uint8List(iv.length + cipher.length)
    ..setRange(0, iv.length, iv)
    ..setRange(iv.length, iv.length + cipher.length, cipher);
}

/// Returns decrypted data using AES-CBC mode with the specified key and IV.
Future<Uint8List> decryptBytesWithEmbeddedIVFast({
  required Uint8List key,
  required Uint8List data,
}) async {
  final Uint8List iv = data.sublist(0, 16);
  final Uint8List cipher = data.sublist(16);
  return unpad(await processAesCbcWithIsolates(key, iv, cipher, false));
}
