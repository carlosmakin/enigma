import 'dart:convert';
import 'dart:typed_data';

import 'package:enigma/src/base.dart';

/// Returns a base64-encoded cipher from the given plaintext for easier transmission and storage.
String encryptText({required Uint8List key, required Uint8List iv, required String text}) {
  final Uint8List cipher = encryptBytes(key: key, iv: iv, data: utf8.encode(text) as Uint8List);
  return '${base64.encode(iv)}:${base64.encode(cipher)}';
}

/// Returns decrypted plaintext from the given ciphertext.
String decryptText({required Uint8List key, required String cipherText}) {
  assert(cipherText.contains(':'));
  final List<String> parts = cipherText.split(':');
  return utf8.decode(
    decryptBytes(key: key, iv: base64.decode(parts[0]), cipher: base64.decode(parts[1])),
  );
}

/// Returns an encrypted cipher from the given data.
Uint8List encryptBytes({
  required Uint8List key,
  required Uint8List iv,
  required Uint8List data,
}) {
  final Uint8List paddedBytes = pad(data, aesBlockSize);
  return process(key, iv, paddedBytes, true);
}

/// Returns decrypted data from the given cipher.
Uint8List decryptBytes({
  required Uint8List key,
  required Uint8List iv,
  required Uint8List cipher,
}) {
  return unpad(process(key, iv, cipher, false));
}

/// Returns an encrypted cipher from the given data.
Future<Uint8List> encryptBytesWithIsolates({
  required Uint8List key,
  required Uint8List iv,
  required Uint8List data,
}) async {
  final Uint8List paddedBytes = pad(data, aesBlockSize);
  return processWithIsolates(key, iv, paddedBytes, true);
}

/// Returns decrypted data from the given cipher.
Future<Uint8List> decryptBytesWithIsolates({
  required Uint8List key,
  required Uint8List iv,
  required Uint8List cipher,
}) async {
  return unpad(await processWithIsolates(key, iv, cipher, false));
}
