import 'dart:typed_data';

import 'package:pointycastle/paddings/pkcs7.dart';

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
