import 'dart:typed_data';
import 'package:enigma/src/chacha20.dart';
import 'package:test/test.dart';

import 'parser.dart';

typedef Chacha20TestVector = Map<String, dynamic>;

void main() {
  for (int i = 0; i < chaha20BlockTestVectors.length; i++) {
    final Chacha20TestVector testVector = chaha20BlockTestVectors[i];
    test('The ChaCha20 Block Functions Test Vector ${(i + 1)}', () {
      final Uint32List key = parseBlockHexString(testVector['key']!).buffer.asUint32List();
      final Uint32List nonce = parseBlockHexString(testVector['nonce']!).buffer.asUint32List();
      final int counter = testVector['counter']! as int;

      final Uint8List keyStream = chacha20Block(key, counter, nonce);
      final Uint8List expected = parseBlockHexString(testVector['keyStream']!);

      expect(keyStream, equals(expected));
    });
  }

  for (int i = 0; i < chaha20EncryptionTestVectors.length; i++) {
    final Chacha20TestVector testVector = chaha20EncryptionTestVectors[i];
    test('The ChaCha20 Encryption Test Vector ${(i + 1)}', () {
      final Uint8List key = parseBlockHexString(testVector['key']!);
      final Uint8List nonce = parseBlockHexString(testVector['nonce']!);
      final Uint8List plaintext = parseBlockHexString(testVector['plaintext']!);
      final int counter = testVector['counter']! as int;

      final Uint8List keyStream = chacha20(key, nonce, plaintext, counter);
      final Uint8List expected = parseBlockHexString(testVector['ciphertext']!);

      expect(keyStream, equals(expected));
    });
  }
}

const List<Chacha20TestVector> chaha20BlockTestVectors = <Chacha20TestVector>[
  // Test Vector #1
  <String, dynamic>{
    'key': '''
      00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
      00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
      ''',
    'nonce': '00 00 00 00 00 00 00 00 00 00 00 00',
    'counter': 0,
    'keyStream': '''
      76 b8 e0 ad a0 f1 3d 90 40 5d 6a e5 53 86 bd 28 
      bd d2 19 b8 a0 8d ed 1a a8 36 ef cc 8b 77 0d c7 
      da 41 59 7c 51 57 48 8d 77 24 e0 3f b8 d8 4a 37 
      6a 43 b8 f4 15 18 a1 1c c3 87 b6 69 b2 ee 65 86
      ''',
  },
  // Test Vector #2
  <String, dynamic>{
    'key': '''
      00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
      00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
      ''',
    'nonce': '00 00 00 00 00 00 00 00 00 00 00 00',
    'counter': 1,
    'keyStream': '''
      9f 07 e7 be 55 51 38 7a 98 ba 97 7c 73 2d 08 0d 
      cb 0f 29 a0 48 e3 65 69 12 c6 53 3e 32 ee 7a ed 
      29 b7 21 76 9c e6 4e 43 d5 71 33 b0 74 d8 39 d5 
      31 ed 1f 28 51 0a fb 45 ac e1 0a 1f 4b 79 4d 6f
      ''',
  },
  // Test Vector #3
  <String, dynamic>{
    'key': '''
      00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
      00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01
      ''',
    'nonce': '00 00 00 00 00 00 00 00 00 00 00 00',
    'counter': 1,
    'keyStream': '''
      3a eb 52 24 ec f8 49 92 9b 9d 82 8d b1 ce d4 dd 
      83 20 25 e8 01 8b 81 60 b8 22 84 f3 c9 49 aa 5a 
      8e ca 00 bb b4 a7 3b da d1 92 b5 c4 2f 73 f2 fd 
      4e 27 36 44 c8 b3 61 25 a6 4a dd eb 00 6c 13 a0
      ''',
  },
  // Test Vector #4
  <String, dynamic>{
    'key': '''
      00 ff 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
      00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
      ''',
    'nonce': '00 00 00 00 00 00 00 00 00 00 00 00',
    'counter': 2,
    'keyStream': '''
      72 d5 4d fb f1 2e c4 4b 36 26 92 df 94 13 7f 32 
      8f ea 8d a7 39 90 26 5e c1 bb be a1 ae 9a f0 ca 
      13 b2 5a a2 6c b4 a6 48 cb 9b 9d 1b e6 5b 2c 09 
      24 a6 6c 54 d5 45 ec 1b 73 74 f4 87 2e 99 f0 96
      ''',
  },
  // Test Vector #5
  <String, dynamic>{
    'key': '''
      00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
      00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
      ''',
    'nonce': '00 00 00 00 00 00 00 00 00 00 00 02',
    'counter': 0,
    'keyStream': '''
      c2 c6 4d 37 8c d5 36 37 4a e2 04 b9 ef 93 3f cd 
      1a 8b 22 88 b3 df a4 96 72 ab 76 5b 54 ee 27 c7 
      8a 97 0e 0e 95 5c 14 f3 a8 8e 74 1b 97 c2 86 f7 
      5f 8f c2 99 e8 14 83 62 fa 19 8a 39 53 1b ed 6d
      ''',
  },
];

const List<Chacha20TestVector> chaha20EncryptionTestVectors = <Chacha20TestVector>[
  // Test Vector #1
  <String, dynamic>{
    'key': '''
      00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
      00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
      ''',
    'nonce': '00 00 00 00 00 00 00 00 00 00 00 00',
    'counter': 0,
    'plaintext': '''
      00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
      00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
      00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
      00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
      ''',
    'ciphertext': '''
      76 b8 e0 ad a0 f1 3d 90 40 5d 6a e5 53 86 bd 28 
      bd d2 19 b8 a0 8d ed 1a a8 36 ef cc 8b 77 0d c7 
      da 41 59 7c 51 57 48 8d 77 24 e0 3f b8 d8 4a 37 
      6a 43 b8 f4 15 18 a1 1c c3 87 b6 69 b2 ee 65 86
      ''',
  },
  // Test Vector #2
  <String, dynamic>{
    'key': '''
      00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
      00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01
      ''',
    'nonce': '00 00 00 00 00 00 00 00 00 00 00 02',
    'counter': 1,
    'plaintext': '''
      41 6e 79 20 73 75 62 6d 69 73 73 69 6f 6e 20 74 
      6f 20 74 68 65 20 49 45 54 46 20 69 6e 74 65 6e 
      64 65 64 20 62 79 20 74 68 65 20 43 6f 6e 74 72 
      69 62 75 74 6f 72 20 66 6f 72 20 70 75 62 6c 69 
      63 61 74 69 6f 6e 20 61 73 20 61 6c 6c 20 6f 72 
      20 70 61 72 74 20 6f 66 20 61 6e 20 49 45 54 46 
      20 49 6e 74 65 72 6e 65 74 2d 44 72 61 66 74 20 
      6f 72 20 52 46 43 20 61 6e 64 20 61 6e 79 20 73 
      74 61 74 65 6d 65 6e 74 20 6d 61 64 65 20 77 69 
      74 68 69 6e 20 74 68 65 20 63 6f 6e 74 65 78 74 
      20 6f 66 20 61 6e 20 49 45 54 46 20 61 63 74 69 
      76 69 74 79 20 69 73 20 63 6f 6e 73 69 64 65 72 
      65 64 20 61 6e 20 22 49 45 54 46 20 43 6f 6e 74 
      72 69 62 75 74 69 6f 6e 22 2e 20 53 75 63 68 20 
      73 74 61 74 65 6d 65 6e 74 73 20 69 6e 63 6c 75 
      64 65 20 6f 72 61 6c 20 73 74 61 74 65 6d 65 6e 
      74 73 20 69 6e 20 49 45 54 46 20 73 65 73 73 69 
      6f 6e 73 2c 20 61 73 20 77 65 6c 6c 20 61 73 20 
      77 72 69 74 74 65 6e 20 61 6e 64 20 65 6c 65 63 
      74 72 6f 6e 69 63 20 63 6f 6d 6d 75 6e 69 63 61 
      74 69 6f 6e 73 20 6d 61 64 65 20 61 74 20 61 6e 
      79 20 74 69 6d 65 20 6f 72 20 70 6c 61 63 65 2c 
      20 77 68 69 63 68 20 61 72 65 20 61 64 64 72 65 
      73 73 65 64 20 74 6f
      ''',
    'ciphertext': '''
      a3 fb f0 7d f3 fa 2f de 4f 37 6c a2 3e 82 73 70
      41 60 5d 9f 4f 4f 57 bd 8c ff 2c 1d 4b 79 55 ec
      2a 97 94 8b d3 72 29 15 c8 f3 d3 37 f7 d3 70 05
      0e 9e 96 d6 47 b7 c3 9f 56 e0 31 ca 5e b6 25 0d
      40 42 e0 27 85 ec ec fa 4b 4b b5 e8 ea d0 44 0e
      20 b6 e8 db 09 d8 81 a7 c6 13 2f 42 0e 52 79 50
      42 bd fa 77 73 d8 a9 05 14 47 b3 29 1c e1 41 1c
      68 04 65 55 2a a6 c4 05 b7 76 4d 5e 87 be a8 5a
      d0 0f 84 49 ed 8f 72 d0 d6 62 ab 05 26 91 ca 66
      42 4b c8 6d 2d f8 0e a4 1f 43 ab f9 37 d3 25 9d
      c4 b2 d0 df b4 8a 6c 91 39 dd d7 f7 69 66 e9 28
      e6 35 55 3b a7 6c 5c 87 9d 7b 35 d4 9e b2 e6 2b
      08 71 cd ac 63 89 39 e2 5e 8a 1e 0e f9 d5 28 0f
      a8 ca 32 8b 35 1c 3c 76 59 89 cb cf 3d aa 8b 6c
      cc 3a af 9f 39 79 c9 2b 37 20 fc 88 dc 95 ed 84
      a1 be 05 9c 64 99 b9 fd a2 36 e7 e8 18 b0 4b 0b
      c3 9c 1e 87 6b 19 3b fe 55 69 75 3f 88 12 8c c0
      8a aa 9b 63 d1 a1 6f 80 ef 25 54 d7 18 9c 41 1f
      58 69 ca 52 c5 b8 3f a3 6f f2 16 b9 c1 d3 00 62
      be bc fd 2d c5 bc e0 91 19 34 fd a7 9a 86 f6 e6
      98 ce d7 59 c3 ff 9b 64 77 33 8f 3d a4 f9 cd 85
      14 ea 99 82 cc af b3 41 b2 38 4d d9 02 f3 d1 ab
      7a c6 1d d2 9c 6f 21 ba 5b 86 2f 37 30 e3 7c fd
      c4 fd 80 6c 22 f2 21
      ''',
  },
  // Test Vector #3
  <String, dynamic>{
    'key': '''
      1c 92 40 a5 eb 55 d3 8a f3 33 88 86 04 f6 b5 f0 
      47 39 17 c1 40 2b 80 09 9d ca 5c bc 20 70 75 c0
      ''',
    'nonce': '00 00 00 00 00 00 00 00 00 00 00 02',
    'counter': 42,
    'plaintext': '''
      27 54 77 61 73 20 62 72 69 6c 6c 69 67 2c 20 61 
      6e 64 20 74 68 65 20 73 6c 69 74 68 79 20 74 6f 
      76 65 73 0a 44 69 64 20 67 79 72 65 20 61 6e 64 
      20 67 69 6d 62 6c 65 20 69 6e 20 74 68 65 20 77 
      61 62 65 3a 0a 41 6c 6c 20 6d 69 6d 73 79 20 77 
      65 72 65 20 74 68 65 20 62 6f 72 6f 67 6f 76 65 
      73 2c 0a 41 6e 64 20 74 68 65 20 6d 6f 6d 65 20 
      72 61 74 68 73 20 6f 75 74 67 72 61 62 65 2e
      ''',
    'ciphertext': '''
      62 e6 34 7f 95 ed 87 a4 5f fa e7 42 6f 27 a1 df 
      5f b6 91 10 04 4c 0d 73 11 8e ff a9 5b 01 e5 cf 
      16 6d 3d f2 d7 21 ca f9 b2 1e 5f b1 4c 61 68 71 
      fd 84 c5 4f 9d 65 b2 83 19 6c 7f e4 f6 05 53 eb 
      f3 9c 64 02 c4 22 34 e3 2a 35 6b 3e 76 43 12 a6 
      1a 55 32 05 57 16 ea d6 96 25 68 f8 7d 3f 3f 77 
      04 c6 a8 d1 bc d1 bf 4d 50 d6 15 4b 6d a7 31 b1 
      87 b5 8d fd 72 8a fa 36 75 7a 79 7a c1 88 d1
      ''',
  },
];
