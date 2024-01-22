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
int rotateLeft32By16(int value) => (value << 16) | (value >> 16);
int rotateLeft32By12(int value) => (value << 12) | (value >> 20);
int rotateLeft32By8(int value) => (value << 8) | (value >> 24);
int rotateLeft32By7(int value) => (value << 7) | (value >> 25);

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
    state[0] = state[0] + state[4];
    state[12] = rotateLeft32By16(state[12] ^ state[0]);
    state[8] = state[8] + state[12];
    state[4] = rotateLeft32By12(state[4] ^ state[8]);
    state[0] = state[0] + state[4];
    state[12] = rotateLeft32By8(state[12] ^ state[0]);
    state[8] = state[8] + state[12];
    state[4] = rotateLeft32By7(state[4] ^ state[8]);

    // Quarter round on (1, 5, 9, 13)
    state[1] = state[1] + state[5];
    state[13] = rotateLeft32By16(state[13] ^ state[1]);
    state[9] = state[9] + state[13];
    state[5] = rotateLeft32By12(state[5] ^ state[9]);
    state[1] = state[1] + state[5];
    state[13] = rotateLeft32By8(state[13] ^ state[1]);
    state[9] = state[9] + state[13];
    state[5] = rotateLeft32By7(state[5] ^ state[9]);

    // Quarter round on (2, 6, 10, 14)
    state[2] = state[2] + state[6];
    state[14] = rotateLeft32By16(state[14] ^ state[2]);
    state[10] = state[10] + state[14];
    state[6] = rotateLeft32By12(state[6] ^ state[10]);
    state[2] = state[2] + state[6];
    state[14] = rotateLeft32By8(state[14] ^ state[2]);
    state[10] = state[10] + state[14];
    state[6] = rotateLeft32By7(state[6] ^ state[10]);

    // Quarter round on (3, 7, 11, 15)
    state[3] = state[3] + state[7];
    state[15] = rotateLeft32By16(state[15] ^ state[3]);
    state[11] = state[11] + state[15];
    state[7] = rotateLeft32By12(state[7] ^ state[11]);
    state[3] = state[3] + state[7];
    state[15] = rotateLeft32By8(state[15] ^ state[3]);
    state[11] = state[11] + state[15];
    state[7] = rotateLeft32By7(state[7] ^ state[11]);

    // Diagonal rounds

    // Quarter round on (0, 5, 10, 15)
    state[0] = state[0] + state[5];
    state[15] = rotateLeft32By16(state[15] ^ state[0]);
    state[10] = state[10] + state[15];
    state[5] = rotateLeft32By12(state[5] ^ state[10]);
    state[0] = state[0] + state[5];
    state[15] = rotateLeft32By8(state[15] ^ state[0]);
    state[10] = state[10] + state[15];
    state[5] = rotateLeft32By7(state[5] ^ state[10]);

    // Quarter round on (1, 6, 11, 12)
    state[1] = state[1] + state[6];
    state[12] = rotateLeft32By16(state[12] ^ state[1]);
    state[11] = state[11] + state[12];
    state[6] = rotateLeft32By12(state[6] ^ state[11]);
    state[1] = state[1] + state[6];
    state[12] = rotateLeft32By8(state[12] ^ state[1]);
    state[11] = state[11] + state[12];
    state[6] = rotateLeft32By7(state[6] ^ state[11]);

    // Quarter round on (2, 7, 8, 13)
    state[2] = state[2] + state[7];
    state[13] = rotateLeft32By16(state[13] ^ state[2]);
    state[8] = state[8] + state[13];
    state[7] = rotateLeft32By12(state[7] ^ state[8]);
    state[2] = state[2] + state[7];
    state[13] = rotateLeft32By8(state[13] ^ state[2]);
    state[8] = state[8] + state[13];
    state[7] = rotateLeft32By7(state[7] ^ state[8]);

    // Quarter round on (3, 4, 9, 14)
    state[3] = state[3] + state[4];
    state[14] = rotateLeft32By16(state[14] ^ state[3]);
    state[9] = state[9] + state[14];
    state[4] = rotateLeft32By12(state[4] ^ state[9]);
    state[3] = state[3] + state[4];
    state[14] = rotateLeft32By8(state[14] ^ state[3]);
    state[9] = state[9] + state[14];
    state[4] = rotateLeft32By7(state[4] ^ state[9]);
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
Uint8List chacha20Block(Uint32List key, int counter, Uint32List nonce) {
  // Initialize the state with the constants, key, counter, and nonce
  final Uint32List state = Uint32List(16);

  state[0] = 0x61707865;
  state[1] = 0x3320646e;
  state[2] = 0x79622d32;
  state[3] = 0x6b206574;
  state[4] = key[0];
  state[5] = key[1];
  state[6] = key[2];
  state[7] = key[3];
  state[8] = key[4];
  state[9] = key[5];
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
    workingState[i] += state[i];
  }

  return workingState.buffer.asUint8List();
}

/// Encrypts or decrypts data using the ChaCha20 algorithm as specified in RFC 8439
Uint8List chacha20(Uint8List key, Uint8List nonce, Uint8List data, [int counter = 1]) {
  if (key.length != 32) throw ArgumentError('Invalid key');
  if (nonce.length != 12) throw ArgumentError('Invalid nonce');
  if (data.length >= 274877906880) throw ArgumentError('Maximum size reached');

  final int dataSize = data.lengthInBytes;
  final Uint8List output = Uint8List(dataSize);

  final Uint32List key32Bit = Uint32List.view(key.buffer);
  final Uint32List nonce32Bit = Uint32List.view(nonce.buffer);

  // Encrypt each full block
  final int fullBlocks = dataSize ~/ 64;
  for (int j = 0; j < fullBlocks; j++) {
    final Uint8List keyStream = chacha20Block(key32Bit, counter + j, nonce32Bit);
    for (int i = 0; i < 64; i++) {
      output[j * 64 + i] = data[j * 64 + i] ^ keyStream[i];
    }
  }

  // Handle any remaining partial block
  final int remaining = dataSize % 64;
  if (remaining != 0) {
    final Uint8List keyStream = chacha20Block(key32Bit, counter + fullBlocks, nonce32Bit);
    final int start = fullBlocks * 64;
    for (int i = 0; i < remaining; i++) {
      output[start + i] = data[start + i] ^ keyStream[i];
    }
  }

  return output;
}
