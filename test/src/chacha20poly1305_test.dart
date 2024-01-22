import 'dart:typed_data';
import 'package:enigma/src/chacha20poly1305.dart';
import 'package:test/test.dart';

import 'parser.dart';

typedef Poly1305KeyGenTestVector = Map<String, String>;

void main() {
  for (int i = 0; i < poly1305KeyGenTestVectors.length; i++) {
    final Poly1305KeyGenTestVector testVector = poly1305KeyGenTestVectors[i];
    test('Poly1305 Key Generation Using ChaCha20 Test Vector ${(i + 1)}', () {
      final Uint8List key = parseBlockHexString(testVector['key']!);
      final Uint8List nonce = parseBlockHexString(testVector['nonce']!);

      final Uint8List otk = poly1305KeyGen(key, nonce);
      final Uint8List expected = parseBlockHexString(testVector['otk']!);

      expect(otk, equals(expected));
    });
  }
}

const List<Poly1305KeyGenTestVector> poly1305KeyGenTestVectors = <Poly1305KeyGenTestVector>[
  // Test Vector #1
  <String, String>{
    'key': '''
      00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
      00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
      ''',
    'nonce': '00 00 00 00 00 00 00 00 00 00 00 00',
    'otk': '''
      76 b8 e0 ad a0 f1 3d 90 40 5d 6a e5 53 86 bd 28 
      bd d2 19 b8 a0 8d ed 1a a8 36 ef cc 8b 77 0d c7
      ''',
  },
  // Test Vector #2
  <String, String>{
    'key': '''
      00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
      00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01
      ''',
    'nonce': '00 00 00 00 00 00 00 00 00 00 00 02',
    'otk': '''
      ec fa 25 4f 84 5f 64 74 73 d3 cb 14 0d a9 e8 76 
      06 cb 33 06 6c 44 7b 87 bc 26 66 dd e3 fb b7 39
      ''',
  },
  // Test Vector #3
  <String, String>{
    'key': '''
      1c 92 40 a5 eb 55 d3 8a f3 33 88 86 04 f6 b5 f0 
      47 39 17 c1 40 2b 80 09 9d ca 5c bc 20 70 75 c0
      ''',
    'nonce': '00 00 00 00 00 00 00 00 00 00 00 02',
    'otk': '''
      96 5e 3b c6 f9 ec 7e d9 56 08 08 f4 d2 29 f9 4b 
      13 7f f2 75 ca 9b 3f cb dd 59 de aa d2 33 10 ae
      ''',
  },
];
