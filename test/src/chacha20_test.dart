import 'dart:typed_data';
import 'package:enigma/src/chacha20.dart';
import 'package:test/test.dart';

import 'parser.dart';

typedef Chacha20TestVector = Map<String, dynamic>;

void main() {
  for (int i = 0; i < testVectors.length; i++) {
    final Chacha20TestVector testVector = testVectors[i];
    test('The ChaCha20 Block Functions Test Vector ${(i + 1)}', () {
      final Uint32List key = parseBlockHexString(testVector['key']!).buffer.asUint32List();
      final Uint32List nonce = parseBlockHexString(testVector['nonce']!).buffer.asUint32List();
      final int counter = testVector['counter']! as int;

      final Uint8List keyStream = chacha20Block(key, counter, nonce);
      final Uint8List expected = parseBlockHexString(testVector['keyStream']!);

      expect(keyStream, equals(expected));
    });
  }
}

const List<Chacha20TestVector> testVectors = <Chacha20TestVector>[
  // Test Vector #1
  <String, dynamic>{
    'key':
        '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00',
    'nonce': '00 00 00 00 00 00 00 00 00 00 00 00',
    'counter': 0,
    'keyStream':
        '76 b8 e0 ad a0 f1 3d 90 40 5d 6a e5 53 86 bd 28 bd d2 19 b8 a0 8d ed 1a a8 36 ef cc 8b 77 0d c7 da 41 59 7c 51 57 48 8d 77 24 e0 3f b8 d8 4a 37 6a 43 b8 f4 15 18 a1 1c c3 87 b6 69 b2 ee 65 86',
  },
  // Test Vector #2
  <String, dynamic>{
    'key':
        '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00',
    'nonce': '00 00 00 00 00 00 00 00 00 00 00 00',
    'counter': 1,
    'keyStream':
        '9f 07 e7 be 55 51 38 7a 98 ba 97 7c 73 2d 08 0d cb 0f 29 a0 48 e3 65 69 12 c6 53 3e 32 ee 7a ed 29 b7 21 76 9c e6 4e 43 d5 71 33 b0 74 d8 39 d5 31 ed 1f 28 51 0a fb 45 ac e1 0a 1f 4b 79 4d 6f',
  },
  // Test Vector #3
  <String, dynamic>{
    'key':
        '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01',
    'nonce': '00 00 00 00 00 00 00 00 00 00 00 00',
    'counter': 1,
    'keyStream':
        '3a eb 52 24 ec f8 49 92 9b 9d 82 8d b1 ce d4 dd 83 20 25 e8 01 8b 81 60 b8 22 84 f3 c9 49 aa 5a 8e ca 00 bb b4 a7 3b da d1 92 b5 c4 2f 73 f2 fd4e 27 36 44 c8 b3 61 25 a6 4a dd eb 00 6c 13 a0',
  },
  // Test Vector #4
  <String, dynamic>{
    'key':
        '00 ff 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00',
    'nonce': '00 00 00 00 00 00 00 00 00 00 00 00',
    'counter': 2,
    'keyStream':
        '72 d5 4d fb f1 2e c4 4b 36 26 92 df 94 13 7f 32 8f ea 8d a7 39 90 26 5e c1 bb be a1 ae 9a f0 ca 13 b2 5a a2 6c b4 a6 48 cb 9b 9d 1b e6 5b 2c 09 24 a6 6c 54 d5 45 ec 1b 73 74 f4 87 2e 99 f0 96',
  },
  // Test Vector #5
  <String, dynamic>{
    'key':
        '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00',
    'nonce': '00 00 00 00 00 00 00 00 00 00 00 02',
    'counter': 0,
    'keyStream':
        'c2 c6 4d 37 8c d5 36 37 4a e2 04 b9 ef 93 3f cd 1a 8b 22 88 b3 df a4 96 72 ab 76 5b 54 ee 27 c7 8a 97 0e 0e 95 5c 14 f3 a8 8e 74 1b 97 c2 86 f7 5f 8f c2 99 e8 14 83 62 fa 19 8a 39 53 1b ed 6d',
  },
];
