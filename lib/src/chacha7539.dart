import 'dart:typed_data';

/// Ensures that the elements of the given [Uint32List] are in little-endian format.
/// If the host system is big-endian, this function flips the endianness of each element.
void ensureLittleEndian(Uint32List list) {
  if (Endian.host == Endian.little) {
    return; // No action needed if the system is already little-endian
  }

  final ByteData byteData = ByteData.view(list.buffer, list.offsetInBytes, list.lengthInBytes);
  for (int i = 0; i < list.length; i++) {
    list[i] = byteData.getUint32(i * 4, Endian.little);
  }
}

/// Rotates the left bits of a 32-bit unsigned integer.
int _rotateLeft32(int value, int shift) {
  return ((value << shift) & 0xFFFFFFFF) | (value >> (32 - shift));
}

/// Performs the quarter round operation on the ChaCha state.
/// The basic operation of the ChaCha algorithm is the quarter round. It
/// operates on four 32-bit unsigned integers, denoted a, b, c, and d.
/// The operation is as follows (in C-like notation):
///
/// 1.  a += b; d ^= a; d <<<= 16;
/// 2.  c += d; b ^= c; b <<<= 12;
/// 3.  a += b; d ^= a; d <<<= 8;
/// 4.  c += d; b ^= c; b <<<= 7;
///
/// Where "+" denotes integer addition modulo 2^32, "^" denotes a bitwise
/// Exclusive OR (XOR), and "<<< n" denotes an n-bit left rotation
/// (towards the high bits).
void quarterRound(Uint32List state, int a, int b, int c, int d) {
  state[a] += state[b];
  state[d] = _rotateLeft32(state[d] ^ state[a], 16);
  state[c] += state[d];
  state[b] = _rotateLeft32(state[b] ^ state[c], 12);
  state[a] += state[b];
  state[d] = _rotateLeft32(state[d] ^ state[a], 8);
  state[c] += state[d];
  state[b] = _rotateLeft32(state[b] ^ state[c], 7);
}

/// The ChaCha20 block function is the core of the ChaCha20 algorithm.
/// The function transforms a ChaCha state by running multiple quarter rounds.
///
/// The inputs to ChaCha20 are:
///
/// - A 256-bit key, treated as a concatenation of eight 32-bit little-endian integers.
/// - A 96-bit nonce, treated as a concatenation of three 32-bit little-endian integers
/// - A 32-bit block count parameter, treated as a 32-bit little-endian integer.
///
///The output is 64 random-looking bytes.
Uint8List chacha20Block(Uint8List key, int counter, Uint8List nonce) {
  assert(key.length == 32, 'Invalid key');
  assert(nonce.length == 12, 'Invalid nonce');

  // Initialize the state with the constants, key, counter, and nonce
  final Uint32List state = Uint32List(16);
  state[0] = 0x61707865;
  state[1] = 0x3320646e;
  state[2] = 0x79622d32;
  state[3] = 0x6b206574;
  state.setAll(4, key.buffer.asUint32List());
  state[12] = counter;
  state.setAll(13, nonce.buffer.asUint32List());

  // Flip endianness only if the system is big-endian
  ensureLittleEndian(state);

  // Working state
  Uint32List workingState = Uint32List.fromList(state);

  // Perform 20 rounds (10 column rounds followed by 10 diagonal rounds)
  for (int i = 0; i < 10; i++) {
    // Column rounds
    quarterRound(workingState, 0, 4, 8, 12);
    quarterRound(workingState, 1, 5, 9, 13);
    quarterRound(workingState, 2, 6, 10, 14);
    quarterRound(workingState, 3, 7, 11, 15);

    // Diagonal rounds
    quarterRound(workingState, 0, 5, 10, 15);
    quarterRound(workingState, 1, 6, 11, 12);
    quarterRound(workingState, 2, 7, 8, 13);
    quarterRound(workingState, 3, 4, 9, 14);
  }

  // Add the original state to the working state
  for (int i = 0; i < 16; i++) {
    workingState[i] += state[i];
  }

  // Convert the working state to bytes
  Uint8List output = Uint8List(64);
  ByteData outputData = ByteData.sublistView(output);
  for (int i = 0; i < 16; i++) {
    outputData.setUint32(i * 4, workingState[i], Endian.little);
  }

  return output;
}

/// Encrypts or decrypts data using the ChaCha20 algorithm as specified in RFC 7539.
Uint8List chacha20Rfc7539(Uint8List key, Uint8List nonce, Uint8List data, [int counter = 1]) {
  final int dataSize = data.length;
  final Uint8List outputData = Uint8List(dataSize);

  for (int j = 0; j < dataSize / 64; ++j) {
    Uint8List keyStream = chacha20Block(key, counter + j, nonce);
    int blockStart = j * 64;
    int blockEnd = blockStart + 64;

    for (int i = blockStart; i < blockEnd && i < dataSize; ++i) {
      outputData[i] = data[i] ^ keyStream[i - blockStart];
    }
  }

  if (dataSize % 64 != 0) {
    Uint8List keyStream = chacha20Block(key, counter + (dataSize / 64).floor(), nonce);
    int blockStart = (dataSize / 64).floor() * 64;

    for (int i = blockStart; i < dataSize; ++i) {
      outputData[i] = data[i] ^ keyStream[i - blockStart];
    }
  }

  return outputData;
}
