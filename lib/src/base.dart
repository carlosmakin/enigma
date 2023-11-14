import 'dart:typed_data';

import 'package:pointycastle/export.dart';

/// AES processing block size.
const int aesBlockSize = 16;

/// Returns the source data padded to the specified block size.
Uint8List pad(Uint8List bytes, int blockSizeBytes) {
  // The PKCS #7 padding just fills the extra bytes with the same value.
  // That value is the number of bytes of padding there is.
  //
  // For example, something that requires 3 bytes of padding with append
  // [0x03, 0x03, 0x03] to the bytes. If the bytes is already a multiple of the
  // block size, a full block of padding is added.

  final int padLength = blockSizeBytes - (bytes.length % blockSizeBytes);
  final Uint8List padded = Uint8List(bytes.length + padLength)..setAll(0, bytes);
  PKCS7Padding().addPadding(padded, bytes.length);

  return padded;
}

/// Returns the source data that is unpadded.
Uint8List unpad(Uint8List padded) {
  return padded.sublist(0, padded.length - PKCS7Padding().padCount(padded));
}

Uint8List process(Uint8List key, Uint8List iv, Uint8List bytes, bool encrypt) {
  // Assert that the input lengths are valid.
  assert(<int>[128, 192, 256].contains(key.length * 8));
  assert(128 == iv.length * 8);
  assert(bytes.length % aesBlockSize == 0);

  // Creates a CBC block cipher with AES, and initializes it with the key and IV.
  final CBCBlockCipher cbc = CBCBlockCipher(AESEngine())
    ..init(encrypt, ParametersWithIV<CipherParameters?>(KeyParameter(key), iv));

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
