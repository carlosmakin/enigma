import 'dart:typed_data';

/// Rotates the left bits of a 32-bit unsigned integer.
int _rotateLeft32(int value, int shift) {
  return ((value << shift) & 0xFFFFFFFF) | (value >> (32 - shift));
}

/// Performs the quarter round operation on the ChaCha state.
void _quarterRound(Uint32List state, int a, int b, int c, int d) {
  state[a] += state[b];
  state[d] = _rotateLeft32(state[d] ^ state[a], 16);
  state[c] += state[d];
  state[b] = _rotateLeft32(state[b] ^ state[c], 12);
  state[a] += state[b];
  state[d] = _rotateLeft32(state[d] ^ state[a], 8);
  state[c] += state[d];
  state[b] = _rotateLeft32(state[b] ^ state[c], 7);
}

/// The ChaCha20 block function. This is the core of the ChaCha20 algorithm.
Uint8List chacha20Block(Uint8List key, int counter, Uint8List nonce) {
  assert(key.length == 32);
  assert(nonce.length == 12);

  const String sigma = 'expand 32-byte k';
  Uint32List state = Uint32List(16);

  // Initialize the state with the constants, key, counter, and nonce
  ByteData sigmaData = ByteData.sublistView(Uint8List.fromList(sigma.codeUnits));
  for (int i = 0; i < 4; i++) {
    state[i] = sigmaData.getUint32(i * 4, Endian.little);
  }
  ByteData keyData = ByteData.sublistView(key);
  for (int i = 0; i < 8; i++) {
    state[i + 4] = keyData.getUint32(i * 4, Endian.little);
  }
  state[12] = counter;
  ByteData nonceData = ByteData.sublistView(nonce);
  for (int i = 0; i < 3; i++) {
    state[i + 13] = nonceData.getUint32(i * 4, Endian.little);
  }

  // Working state
  Uint32List workingState = Uint32List.fromList(state);

  // Perform 20 rounds (10 column rounds followed by 10 diagonal rounds)
  for (int i = 0; i < 10; i++) {
    // Column rounds
    _quarterRound(workingState, 0, 4, 8, 12);
    _quarterRound(workingState, 1, 5, 9, 13);
    _quarterRound(workingState, 2, 6, 10, 14);
    _quarterRound(workingState, 3, 7, 11, 15);
    // Diagonal rounds
    _quarterRound(workingState, 0, 5, 10, 15);
    _quarterRound(workingState, 1, 6, 11, 12);
    _quarterRound(workingState, 2, 7, 8, 13);
    _quarterRound(workingState, 3, 4, 9, 14);
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
  Uint8List outputData = Uint8List(dataSize);

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
