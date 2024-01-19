import 'dart:typed_data';
import 'package:pointycastle/export.dart';

/// Encrypts data using ChaCha20 as specified in RFC 7539.
Uint8List encryptChaCha20(Uint8List key, Uint8List nonce, Uint8List data) {
  // Validate key and nonce lengths (256 bits for key, 96 bits for nonce)
  assert(key.length == 32);
  assert(nonce.length == 12);

  final ChaCha7539Engine chacha = ChaCha7539Engine()
    ..init(true, ParametersWithIV<KeyParameter>(KeyParameter(key), nonce));

  final Uint8List output = Uint8List(data.length);
  chacha.processBytes(data, 0, data.length, output, 0);

  return output;
}

/// Decrypts data using ChaCha20 as specified in RFC 7539.
Uint8List decryptChaCha20(Uint8List key, Uint8List nonce, Uint8List data) {
  // Validate key and nonce lengths (256 bits for key, 96 bits for nonce)
  assert(key.length == 32);
  assert(nonce.length == 12);

  final ChaCha7539Engine chacha = ChaCha7539Engine()
    ..init(false, ParametersWithIV<KeyParameter>(KeyParameter(key), nonce));

  final Uint8List output = Uint8List(data.length);
  chacha.processBytes(data, 0, data.length, output, 0);

  return output;
}

/// Encrypts data using ChaCha20-Poly1305 as specified in RFC 7539.
Uint8List encryptChaCha20Poly1305(
  Uint8List key,
  Uint8List nonce,
  Uint8List data, [
  Uint8List? aad,
]) {
  // Validate key and nonce lengths (256 bits for key, 96 bits for nonce)
  assert(key.length == 32);
  assert(nonce.length == 12);

  final ChaCha20Poly1305 chacha = ChaCha20Poly1305(ChaCha7539Engine(), Poly1305())
    ..init(true, AEADParameters<KeyParameter>(KeyParameter(key), 128, nonce, aad ?? Uint8List(0)));

  return chacha.process(data);
}

/// Decrypts data using ChaCha20-Poly1305 as specified in RFC 7539.
Uint8List decryptChaCha20Poly1305(
  Uint8List key,
  Uint8List nonce,
  Uint8List data, [
  Uint8List? aad,
]) {
  // Validate key and nonce lengths (256 bits for key, 96 bits for nonce)
  assert(key.length == 32);
  assert(nonce.length == 12);

  final ChaCha20Poly1305 chacha = ChaCha20Poly1305(ChaCha7539Engine(), Poly1305())
    ..init(false, AEADParameters<KeyParameter>(KeyParameter(key), 128, nonce, aad ?? Uint8List(0)));

  return chacha.process(data);
}
