import 'dart:typed_data';

BigInt leBytesToBigInt(Uint8List bytes) {
  BigInt result = BigInt.zero;
  for (int i = 0; i < bytes.length; i++) {
    result += BigInt.from(bytes[i]) << (8 * i);
  }
  return result;
}

Uint8List bigIntTo16LeBytes(BigInt num) {
  final Uint8List bytes = Uint8List(16);
  for (int i = 0; i < 16; i++) {
    bytes[i] = ((num >> (8 * i)) & BigInt.from(0xff)).toInt();
  }
  return bytes;
}

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

Uint8List poly1305Mac(Uint8List msg, Uint8List key) {
  final Uint8List rBytes = key.sublist(0, 16);
  clamp(rBytes);
  final BigInt r = leBytesToBigInt(rBytes); // $
  final BigInt s = leBytesToBigInt(key.sublist(16, 32));

  BigInt accumulator = BigInt.zero; // $
  final BigInt p = (BigInt.one << 130) - BigInt.from(5);

  for (int i = 0; i < msg.length; i += 16) {
    final int blockLen = i + 16 <= msg.length ? 16 : msg.length - i;
    final Uint8List block = Uint8List(17);

    block.setRange(0, blockLen, msg.sublist(i, i + blockLen));
    block[blockLen] = 1; // Add one bit beyond the number of bytes.

    final BigInt n = leBytesToBigInt(block);
    accumulator += n;
    accumulator = (r * accumulator) % p;
  }

  accumulator = (accumulator + s) % p;
  return bigIntTo16LeBytes(accumulator);
}
