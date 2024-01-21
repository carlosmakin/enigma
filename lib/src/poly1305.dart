import 'dart:typed_data';

// Convert a list of bytes in little-endian order to a BigInt
BigInt leBytesToBigInt(Uint8List bytes) {
  BigInt result = BigInt.zero;
  for (int i = 0; i < bytes.length; i++) {
    result |= BigInt.from(bytes[i]) << (8 * i);
  }
  return result;
}

// Convert a BigInt to a list of 16 bytes in little-endian order
Uint8List bigIntTo16LeBytes(BigInt num) {
  final Uint8List bytes = Uint8List(16);
  final BigInt mask = BigInt.from(0xff);
  for (int i = 0; i < 16; i++) {
    bytes[i] = (num >> (8 * i) & mask).toInt();
  }
  return bytes;
}

// Clamp function as specified in RFC 8439
void clamp(Uint8List r) {
  assert(r.length == 16);

  r[3] &= 15;
  r[7] &= 15;
  r[11] &= 15;
  r[15] &= 15;
  r[4] &= 252;
  r[8] &= 252;
  r[12] &= 252;
}

/// Poly1305 MAC function algorithm as specified in RFC 8439
Uint8List poly1305Mac(Uint8List msg, Uint8List key) {
  final Uint8List rBytes = key.sublist(0, 16);
  clamp(rBytes);

  final BigInt r = leBytesToBigInt(rBytes);
  final BigInt s = leBytesToBigInt(key.sublist(16, 32));

  BigInt accumulator = BigInt.zero;
  final BigInt p = (BigInt.one << 130) - BigInt.from(5); // 2^130 - 5

  // Preallocate buffer for performance
  final Uint8List block = Uint8List(17);
  block[16] = 1; // Add one bit beyond the number of bytes for all full blocks

  // Process all full 16-byte blocks
  final int fullBlockEnd = msg.length - (msg.length % 16);
  for (int i = 0; i < fullBlockEnd; i += 16) {
    for (int j = 0; j < 16; j++) {
      block[j] = msg[i + j];
    }
    final BigInt n = leBytesToBigInt(block);
    accumulator = (accumulator + n) * r % p;
  }

  // Process the final block, if there is any remainder
  if (fullBlockEnd < msg.length) {
    final int finalBlockLen = msg.length - fullBlockEnd;
    for (int j = 0; j < finalBlockLen; j++) {
      block[j] = msg[fullBlockEnd + j];
    }
    block[finalBlockLen] = 1;
    for (int j = finalBlockLen + 1; j < 17; j++) {
      block[j] = 0;
    }
    final BigInt n = leBytesToBigInt(block);
    accumulator = (accumulator + n) * r % p;
  }

  // Zero out the block for security
  for (int j = 0; j < 17; j++) {
    block[j] = 0;
  }

  accumulator = (accumulator + s) % p;
  return bigIntTo16LeBytes(accumulator);
}
