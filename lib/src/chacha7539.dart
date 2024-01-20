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
Uint32List chacha20Block(Uint32List key, int counter, Uint32List nonce) {
  // final buffer = ByteBuffer (64);
  final Uint32List state = Uint32List(16);

  // Initialize the state with the constants, key, counter, and nonce
  state[00] = 0x61707865;
  state[01] = 0x3320646e;
  state[02] = 0x79622d32;
  state[03] = 0x6b206574;
  state[04] = key[0];
  state[05] = key[1];
  state[06] = key[2];
  state[07] = key[3];
  state[08] = key[4];
  state[09] = key[5];
  state[10] = key[6];
  state[11] = key[7];
  state[12] = counter;
  state[13] = nonce[0];
  state[14] = nonce[1];
  state[15] = nonce[2];

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

  return workingState;
}

/// Encrypts or decrypts data using the ChaCha20 algorithm as specified in RFC 7539.
Uint8List chacha20(Uint8List key, Uint8List nonce, Uint8List data, [int counter = 1]) {
  assert(key.length == 32, 'Invalid key');
  assert(nonce.length == 12, 'Invalid nonce');

  final int dataSize = data.lengthInBytes;
  final Uint32List key32Bit = Uint32List.view(key.buffer);
  final Uint32List nonce32Bit = Uint32List.view(nonce.buffer);

  final ByteData outputBytes = ByteData(dataSize);

  final Uint32List outputData = Uint32List.view(outputBytes.buffer);
  final Uint32List inputData = Uint32List.view(data.buffer);

  final int blocks = dataSize ~/ 64;
  for (int i = 0; i < blocks; ++i) {
    final Uint32List keyStream = chacha20Block(key32Bit, counter + i, nonce32Bit);
    final int blockStartInts = i * 16;

    for (int j = 0; j < 16; ++j) {
      outputData[blockStartInts + j] = inputData[blockStartInts + j] ^ keyStream[j];
    }
  }

  if (dataSize % 64 != 0) {
    final Uint32List keyStream = chacha20Block(key32Bit, counter + blocks, nonce32Bit);
    final int blockStartInts = blocks * 16;
    final int remainingBytes = dataSize % 64;
    final int fullInts = remainingBytes ~/ 4; // Number of full 32-bit integers
    final int extraBytes = remainingBytes % 4; // Number of extra bytes after full 32-bit integers

    // Process full 32-bit integers
    for (int i = 0; i < fullInts; i++) {
      outputData[blockStartInts + i] = inputData[blockStartInts + i] ^ keyStream[i];
    }

    // Process any extra bytes
    if (extraBytes > 0) {
      final int startExtraByteIndex = blockStartInts * 4 + fullInts * 4;
      for (int i = 0; i < extraBytes; i++) {
        final int byteIndex = startExtraByteIndex + i;
        outputBytes.setUint8(
          byteIndex,
          data[byteIndex] ^ keyStream.buffer.asUint8List()[fullInts * 4 + i],
        );
      }
    }
  }

  return outputBytes.buffer.asUint8List();
}
