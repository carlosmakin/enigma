import 'dart:typed_data';

/// Ensures that the elements of the given `Uint32List` are in little-endian format.
/// If the host system is big-endian, this function flips the endianness of each element.
void ensureLittleEndian(Uint32List list) {
  if (Endian.host == Endian.little) return;

  final ByteData byteData = ByteData.view(list.buffer, list.offsetInBytes, list.lengthInBytes);
  for (int i = 0; i < list.length; i++) {
    list[i] = byteData.getUint32(i * 4, Endian.little);
  }
}

/// Rotates the left bits of a 32-bit unsigned integer.
int _rotateLeft32(int value, int shift) {
  return ((value << shift)) | (value >> (32 - shift));
}

/// Performs the core rounds of the ChaCha20 block cipher.
///
/// The ChaCha20 algorithm operates by performing a series of rounds, each
/// consisting of "quarter-round" transformations. This function performs
/// these transformations directly on the state, modifying it in place.
///
/// The state undergoes 20 rounds in total, comprising 10 cycles of
/// "column rounds" followed by "diagonal rounds." Each round updates the state
/// using modular addition, bitwise XOR, and left rotation operations.
void chacha20BlockRounds(Uint32List state) {
  for (int i = 0; i < 10; i++) {
    // Column rounds

    // Quarter round on (0, 4, 8, 12)
    state[0] = (state[0] + state[4]);
    state[12] = _rotateLeft32(state[12] ^ state[0], 16);
    state[8] = (state[8] + state[12]);
    state[4] = _rotateLeft32(state[4] ^ state[8], 12);
    state[0] = (state[0] + state[4]);
    state[12] = _rotateLeft32(state[12] ^ state[0], 8);
    state[8] = (state[8] + state[12]);
    state[4] = _rotateLeft32(state[4] ^ state[8], 7);

    // Quarter round on (1, 5, 9, 13)
    state[1] = (state[1] + state[5]);
    state[13] = _rotateLeft32(state[13] ^ state[1], 16);
    state[9] = (state[9] + state[13]);
    state[5] = _rotateLeft32(state[5] ^ state[9], 12);
    state[1] = (state[1] + state[5]);
    state[13] = _rotateLeft32(state[13] ^ state[1], 8);
    state[9] = (state[9] + state[13]);
    state[5] = _rotateLeft32(state[5] ^ state[9], 7);

    // Quarter round on (2, 6, 10, 14)
    state[2] = (state[2] + state[6]);
    state[14] = _rotateLeft32(state[14] ^ state[2], 16);
    state[10] = (state[10] + state[14]);
    state[6] = _rotateLeft32(state[6] ^ state[10], 12);
    state[2] = (state[2] + state[6]);
    state[14] = _rotateLeft32(state[14] ^ state[2], 8);
    state[10] = (state[10] + state[14]);
    state[6] = _rotateLeft32(state[6] ^ state[10], 7);

    // Quarter round on (3, 7, 11, 15)
    state[3] = (state[3] + state[7]);
    state[15] = _rotateLeft32(state[15] ^ state[3], 16);
    state[11] = (state[11] + state[15]);
    state[7] = _rotateLeft32(state[7] ^ state[11], 12);
    state[3] = (state[3] + state[7]);
    state[15] = _rotateLeft32(state[15] ^ state[3], 8);
    state[11] = (state[11] + state[15]);
    state[7] = _rotateLeft32(state[7] ^ state[11], 7);

    // Diagonal rounds

    // Quarter round on (0, 5, 10, 15)
    state[0] = (state[0] + state[5]);
    state[15] = _rotateLeft32(state[15] ^ state[0], 16);
    state[10] = (state[10] + state[15]);
    state[5] = _rotateLeft32(state[5] ^ state[10], 12);
    state[0] = (state[0] + state[5]);
    state[15] = _rotateLeft32(state[15] ^ state[0], 8);
    state[10] = (state[10] + state[15]);
    state[5] = _rotateLeft32(state[5] ^ state[10], 7);

    // Quarter round on (1, 6, 11, 12)
    state[1] = (state[1] + state[6]);
    state[12] = _rotateLeft32(state[12] ^ state[1], 16);
    state[11] = (state[11] + state[12]);
    state[6] = _rotateLeft32(state[6] ^ state[11], 12);
    state[1] = (state[1] + state[6]);
    state[12] = _rotateLeft32(state[12] ^ state[1], 8);
    state[11] = (state[11] + state[12]);
    state[6] = _rotateLeft32(state[6] ^ state[11], 7);

    // Quarter round on (2, 7, 8, 13)
    state[2] = (state[2] + state[7]);
    state[13] = _rotateLeft32(state[13] ^ state[2], 16);
    state[8] = (state[8] + state[13]);
    state[7] = _rotateLeft32(state[7] ^ state[8], 12);
    state[2] = (state[2] + state[7]);
    state[13] = _rotateLeft32(state[13] ^ state[2], 8);
    state[8] = (state[8] + state[13]);
    state[7] = _rotateLeft32(state[7] ^ state[8], 7);

    // Quarter round on (3, 4, 9, 14)
    state[3] = (state[3] + state[4]);
    state[14] = _rotateLeft32(state[14] ^ state[3], 16);
    state[9] = (state[9] + state[14]);
    state[4] = _rotateLeft32(state[4] ^ state[9], 12);
    state[3] = (state[3] + state[4]);
    state[14] = _rotateLeft32(state[14] ^ state[3], 8);
    state[9] = (state[9] + state[14]);
    state[4] = _rotateLeft32(state[4] ^ state[9], 7);
  }
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

  // final buffer = ByteBuffer (64);
  final Uint32List state = Uint32List(16);

  // Initialize the state with the constants, key, counter, and nonce
  state[0] = 0x61707865;
  state[1] = 0x3320646e;
  state[2] = 0x79622d32;
  state[3] = 0x6b206574;
  state.setAll(4, key.buffer.asUint32List());
  state[12] = counter;
  state.setAll(13, nonce.buffer.asUint32List());

  // Flip endianness only if the system is big-endian
  ensureLittleEndian(state);

  // Initialize working state
  final Uint32List workingState = Uint32List.fromList(state);

  // Perform block function
  chacha20BlockRounds(workingState);

  // Add the original state to the working state
  for (int i = 0; i < 16; i++) {
    workingState[i] = (workingState[i] + state[i]);
  }

  return workingState.buffer.asUint8List();
}

/// Encrypts or decrypts data using the ChaCha20 algorithm as specified in RFC 7539.
Uint8List chacha20Rfc7539(Uint8List key, Uint8List nonce, Uint8List data, [int counter = 1]) {
  final int dataSize = data.length;
  final Uint8List outputData = Uint8List(dataSize);

  for (int j = 0; j < dataSize / 64; ++j) {
    final Uint8List keyStream = chacha20Block(key, counter + j, nonce);
    final int blockStart = j * 64;
    final int blockEnd = blockStart + 64;

    for (int i = blockStart; i < blockEnd && i < dataSize; ++i) {
      outputData[i] = data[i] ^ keyStream[i - blockStart];
    }
  }

  if (dataSize % 64 != 0) {
    final Uint8List keyStream = chacha20Block(key, counter + (dataSize / 64).floor(), nonce);
    final int blockStart = (dataSize / 64).floor() * 64;

    for (int i = blockStart; i < dataSize; ++i) {
      outputData[i] = data[i] ^ keyStream[i - blockStart];
    }
  }

  return outputData;
}
