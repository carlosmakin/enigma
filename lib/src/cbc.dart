import 'dart:io';
import 'dart:isolate';
import 'dart:typed_data';

import 'package:enigma/src/aes.dart';
import 'package:pointycastle/export.dart';

/// Encrypts data using AES-CBC mode with the specified key, IV, and mode (encrypt/decrypt).
Uint8List encryptAesCbc(Uint8List key, Uint8List iv, Uint8List bytes) {
  // Assert that the input lengths are valid.
  assert(<int>[128, 192, 256].contains(key.length * 8));
  assert(128 == iv.length * 8);
  assert(bytes.length % aesBlockSize == 0);

  // Creates a CBC block cipher with AES, and initializes it with the key and IV.
  final CBCBlockCipher cbc = CBCBlockCipher(AESEngine())
    ..init(true, ParametersWithIV<CipherParameters?>(KeyParameter(key), iv));

  // Allocates space for the output result.
  final Uint8List output = Uint8List(bytes.length);

  // Processes the bytes block-by-block.
  int offset = 0;
  while (offset < bytes.length) {
    offset += cbc.processBlock(bytes, offset, output, offset);
  }
  assert(offset == bytes.length);

  return output;
}

/// Decrypts data using AES-CBC mode with the specified key, IV, and mode (encrypt/decrypt).
Uint8List decryptAesCbc(Uint8List key, Uint8List iv, Uint8List bytes) {
  // Assert that the input lengths are valid.
  assert(<int>[128, 192, 256].contains(key.length * 8));
  assert(128 == iv.length * 8);
  assert(bytes.length % aesBlockSize == 0);

  // Creates a CBC block cipher with AES, and initializes it with the key and IV.
  final CBCBlockCipher cbc = CBCBlockCipher(AESEngine())
    ..init(false, ParametersWithIV<CipherParameters?>(KeyParameter(key), iv));

  // Allocates space for the output result.
  final Uint8List output = Uint8List(bytes.length);

  // Processes the bytes block-by-block.
  int offset = 0;
  while (offset < bytes.length) {
    offset += cbc.processBlock(bytes, offset, output, offset);
  }
  assert(offset == bytes.length);

  return output;
}

/// Processes AES-CBC encryption in parallel using isolates for large data sets.
Future<Uint8List> encryptAesCbcWithIsolates(Uint8List key, Uint8List iv, Uint8List bytes) async {
  // Total data length.
  final int inputLength = bytes.length;

  // Number of isolates to spawn based on the available processors.
  final int numIsolates = Platform.numberOfProcessors;

  // Threshold based on the number of isolates and 64kb blocks.
  final int threshold = numIsolates * 64000;

  // Process data without isolates if it's less than or equal to 1MB.
  if (inputLength <= threshold) return encryptAesCbc(key, iv, bytes);

  // Data chunk size per isolate, aligned with block size.
  final int chunkSize = (inputLength / numIsolates).floor();
  final int adjustedChunkSize = chunkSize - (chunkSize % aesBlockSize);

  // Residual data chunk length to add to last chunk size.
  final int residualLength = inputLength % (adjustedChunkSize * numIsolates);

  // List of all pending asynchronous isolate processing operations.
  final List<Future<Uint8List>> isolates = <Future<Uint8List>>[];

  // Data chunk to isolate distribution loop.
  for (int i = 0; i < numIsolates; i++) {
    // Calculate where each chunk of data should start and end.
    final int start = i * adjustedChunkSize;
    int end = start + adjustedChunkSize;

    // On last chunk add residual chunk length.
    if (i == numIsolates - 1) end += residualLength;

    // Extract the chunk of data that isolate will work on.
    final Uint8List chunk = bytes.sublist(start, end);
    isolates.add(Isolate.run(() => encryptAesCbc(key, iv, chunk)));
  }

  // Wait for all isolates to finish processing.
  final List<Uint8List> results = await Future.wait(isolates);

  // Create output bytes with the same length as the input bytes.
  final Uint8List output = Uint8List(inputLength);

  // Merge results from all isolates into output byte result.
  int offset = 0;
  for (final Uint8List result in results) {
    output.setRange(offset, offset + result.length, result);
    offset += result.length;
  }
  assert(offset == inputLength);

  return output;
}

/// Processes AES-CBC decryption in parallel using isolates for large data sets.
Future<Uint8List> decryptAesCbcWithIsolates(Uint8List key, Uint8List iv, Uint8List bytes) async {
  // Total data length.
  final int inputLength = bytes.length;

  // Number of isolates to spawn based on the available processors.
  final int numIsolates = Platform.numberOfProcessors;

  // Threshold based on the number of isolates and 64kb blocks.
  final int threshold = numIsolates * 64000;

  // Process data without isolates if it's less than or equal to 1MB.
  if (inputLength <= threshold) return decryptAesCbc(key, iv, bytes);

  // Data chunk size per isolate, aligned with block size.
  final int chunkSize = (inputLength / numIsolates).floor();
  final int adjustedChunkSize = chunkSize - (chunkSize % aesBlockSize);

  // Residual data chunk length to add to last chunk size.
  final int residualLength = inputLength % (adjustedChunkSize * numIsolates);

  // List of all pending asynchronous isolate processing operations.
  final List<Future<Uint8List>> isolates = <Future<Uint8List>>[];

  // Data chunk to isolate distribution loop.
  for (int i = 0; i < numIsolates; i++) {
    // Calculate where each chunk of data should start and end.
    final int start = i * adjustedChunkSize;
    int end = start + adjustedChunkSize;

    // On last chunk add residual chunk length.
    if (i == numIsolates - 1) end += residualLength;

    // Extract the chunk of data that isolate will work on.
    final Uint8List chunk = bytes.sublist(start, end);
    isolates.add(Isolate.run(() => decryptAesCbc(key, iv, chunk)));
  }

  // Wait for all isolates to finish processing.
  final List<Uint8List> results = await Future.wait(isolates);

  // Create output bytes with the same length as the input bytes.
  final Uint8List output = Uint8List(inputLength);

  // Merge results from all isolates into output byte result.
  int offset = 0;
  for (final Uint8List result in results) {
    output.setRange(offset, offset + result.length, result);
    offset += result.length;
  }
  assert(offset == inputLength);

  return output;
}
