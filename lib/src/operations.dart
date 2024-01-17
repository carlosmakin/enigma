import 'dart:convert';
import 'dart:typed_data';

import 'package:enigma/src/aes.dart';
import 'package:enigma/src/cbc.dart';

/// Encrypts plaintext using AES-CBC mode and returns a base64-encoded ciphertext without embedded IV.
///
/// Ideal for scenarios where you handle the IV separately and prefer external control over the IV.
String encryptText({required Uint8List key, required Uint8List iv, required String text}) {
  return base64.encode(
    encryptBytes(key: key, iv: iv, data: utf8.encode(text)),
  );
}

/// Decrypts base64-encoded ciphertext without embedded IV using AES-CBC mode and returns the original plaintext.
///
/// Ideal for scenarios where you handle the IV separately and prefer external control over the IV.
String decryptText({required Uint8List key, required Uint8List iv, required String text}) {
  return utf8.decode(
    decryptBytes(key: key, iv: iv, data: base64.decode(text)),
  );
}

/// Encrypts plaintext using AES-CBC mode and returns a base64-encoded ciphertext with embedded IV.
///
/// Automatically manages the IV in the encrypted data for seamless encryption and decryption.
String encryptTextWithEmbeddedIV(
    {required Uint8List key, required Uint8List iv, required String text}) {
  return base64.encode(
    encryptBytesWithEmbeddedIV(key: key, iv: iv, data: utf8.encode(text)),
  );
}

/// Decrypts base64-encoded ciphertext with embedded IV using AES-CBC mode and returns the original plaintext.
///
/// Automatically manages the IV in the encrypted data for seamless encryption and decryption.
String decryptTextWithEmbeddedIV({required Uint8List key, required String text}) {
  return utf8.decode(
    decryptBytesWithEmbeddedIV(key: key, data: base64.decode(text)),
  );
}

/// Encrypts data using AES-CBC mode and returns cipher data without embedded IV.
///
/// Ideal for scenarios where you handle the IV separately and prefer external control over the IV.
Uint8List encryptBytes({
  required Uint8List key,
  required Uint8List iv,
  required Uint8List data,
}) {
  final Uint8List paddedBytes = pad(data, aesBlockSize);
  return processAesCbc(key, iv, paddedBytes, true);
}

/// Decrypts cipher without embedded IV using AES-CBC mode and returns the original data.
///
/// Ideal for scenarios where you handle the IV separately and prefer external control over the IV.
Uint8List decryptBytes({
  required Uint8List key,
  required Uint8List iv,
  required Uint8List data,
}) {
  return unpad(processAesCbc(key, iv, data, false));
}

/// Encrypts data using AES-CBC mode and returns cipher data with embedded IV.
///
/// Automatically manages the IV in the encrypted data for seamless encryption and decryption.
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

/// Decrypts cipher with embedded IV using AES-CBC mode and returns the original data.
///
/// Automatically manages the IV in the encrypted data for seamless encryption and decryption.
Uint8List decryptBytesWithEmbeddedIV({
  required Uint8List key,
  required Uint8List data,
}) {
  final Uint8List iv = data.sublist(0, 16);
  final Uint8List cipher = data.sublist(16);
  return unpad(processAesCbc(key, iv, cipher, false));
}

/// Encrypts data using AES-CBC mode and returns cipher data without embedded IV.
///
/// Ideal for scenarios where you handle the IV separately and prefer external control over the IV.
Future<Uint8List> encryptBytesFast({
  required Uint8List key,
  required Uint8List iv,
  required Uint8List data,
}) async {
  final Uint8List paddedBytes = pad(data, aesBlockSize);
  return processAesCbcWithIsolates(key, iv, paddedBytes, true);
}

/// Decrypts cipher without embedded IV using AES-CBC mode and returns the original data.
///
/// Ideal for scenarios where you handle the IV separately and prefer external control over the IV.
Future<Uint8List> decryptBytesFast({
  required Uint8List key,
  required Uint8List iv,
  required Uint8List data,
}) async {
  return unpad(await processAesCbcWithIsolates(key, iv, data, false));
}

/// Encrypts data using AES-CBC mode and returns cipher data with embedded IV.
///
/// Automatically manages the IV in the encrypted data for seamless encryption and decryption.
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

/// Decrypts cipher with embedded IV using AES-CBC mode and returns the original data.
///
/// Automatically manages the IV in the encrypted data for seamless encryption and decryption.
Future<Uint8List> decryptBytesWithEmbeddedIVFast({
  required Uint8List key,
  required Uint8List data,
}) async {
  final Uint8List iv = data.sublist(0, 16);
  final Uint8List cipher = data.sublist(16);
  return unpad(await processAesCbcWithIsolates(key, iv, cipher, false));
}
