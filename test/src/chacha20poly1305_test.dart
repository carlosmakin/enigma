import 'dart:typed_data';
import 'package:enigma/src/chacha20poly1305.dart';
import 'package:test/test.dart';

import 'parser.dart';

typedef Poly1305TestVector = Map<String, String>;

void main() {
  for (int i = 0; i < poly1305KeyGenTestVectors.length; i++) {
    final Poly1305TestVector testVector = poly1305KeyGenTestVectors[i];
    test('Poly1305 Key Generation Using ChaCha20 Test Vector $i', () {
      final Uint8List key = parseBlockHexString(testVector['key']!);
      final Uint8List nonce = parseBlockHexString(testVector['nonce']!);

      final Uint8List result = poly1305KeyGen(key, nonce);
      final Uint8List expected = parseBlockHexString(testVector['otk']!);

      expect(result, equals(expected));
    });
  }

  for (int i = 0; i < chachaPoly1305TestVectors.length; i++) {
    final Poly1305TestVector testVector = chachaPoly1305TestVectors[i];
    test('Poly1305 Key Generation Using ChaCha20 Test Vector $i', () {
      final Uint8List key = parseBlockHexString(testVector['key']!);
      final Uint8List nonce = parseBlockHexString(testVector['nonce']!);
      final Uint8List data = parseBlockHexString(testVector['plaintext']!);
      final Uint8List aad = parseBlockHexString(testVector['aad']!);

      final Uint8List result = chacha20Poly1305Encrypt(key, nonce, data, aad);

      final Uint8List ciphertext1 = Uint8List.view(result.buffer, 0, result.length - 16);
      final Uint8List expectedCiphertext = parseBlockHexString(testVector['ciphertext']!);

      final Uint8List tag = Uint8List.view(result.buffer, result.length - 16);
      final Uint8List expectedTag = parseBlockHexString(testVector['tag']!);

      expect(ciphertext1, equals(expectedCiphertext));
      expect(tag, equals(expectedTag));
    });
  }
}

const List<Poly1305TestVector> poly1305KeyGenTestVectors = <Poly1305TestVector>[
  // Test Vector #0
  <String, String>{
    'key': '''
      80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f 
      90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f
      ''',
    'nonce': '00 00 00 00 00 01 02 03 04 05 06 07',
    'otk': '''
      8a d5 a0 8b 90 5f 81 cc 81 50 40 27 4a b2 94 71 
      a8 33 b6 37 e3 fd 0d a5 08 db b8 e2 fd d1 a6 46
      ''',
  },
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

const List<Poly1305TestVector> chachaPoly1305TestVectors = <Poly1305TestVector>[
  // Test Vector #0
  <String, String>{
    'key': '''
      80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f 
      90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f
      ''',
    'nonce': '07 00 00 00 40 41 42 43 44 45 46 47',
    'otk': '''
      7b ac 2b 25 2d b4 47 af 09 b6 7a 55 a4 e9 55 84 
      0a e1 d6 73 10 75 d9 eb 2a 93 75 78 3e d5 53 ff
      ''',
    'aad': '50 51 52 53 c0 c1 c2 c3 c4 c5 c6 c7',
    'plaintext': '''
      4c 61 64 69 65 73 20 61 6e 64 20 47 65 6e 74 6c 
      65 6d 65 6e 20 6f 66 20 74 68 65 20 63 6c 61 73 
      73 20 6f 66 20 27 39 39 3a 20 49 66 20 49 20 63 
      6f 75 6c 64 20 6f 66 66 65 72 20 79 6f 75 20 6f 
      6e 6c 79 20 6f 6e 65 20 74 69 70 20 66 6f 72 20 
      74 68 65 20 66 75 74 75 72 65 2c 20 73 75 6e 73 
      63 72 65 65 6e 20 77 6f 75 6c 64 20 62 65 20 69 
      74 2e
      ''',
    'ciphertext': '''
      d3 1a 8d 34 64 8e 60 db 7b 86 af bc 53 ef 7e c2 
      a4 ad ed 51 29 6e 08 fe a9 e2 b5 a7 36 ee 62 d6 
      3d be a4 5e 8c a9 67 12 82 fa fb 69 da 92 72 8b 
      1a 71 de 0a 9e 06 0b 29 05 d6 a5 b6 7e cd 3b 36 
      92 dd bd 7f 2d 77 8b 8c 98 03 ae e3 28 09 1b 58 
      fa b3 24 e4 fa d6 75 94 55 85 80 8b 48 31 d7 bc 
      3f f4 de f0 8e 4b 7a 9d e5 76 d2 65 86 ce c6 4b 
      61 16
      ''',
    'aead': '''
      50 51 52 53 c0 c1 c2 c3 c4 c5 c6 c7 00 00 00 00 
      d3 1a 8d 34 64 8e 60 db 7b 86 af bc 53 ef 7e c2 
      a4 ad ed 51 29 6e 08 fe a9 e2 b5 a7 36 ee 62 d6 
      3d be a4 5e 8c a9 67 12 82 fa fb 69 da 92 72 8b 
      1a 71 de 0a 9e 06 0b 29 05 d6 a5 b6 7e cd 3b 36 
      92 dd bd 7f 2d 77 8b 8c 98 03 ae e3 28 09 1b 58 
      fa b3 24 e4 fa d6 75 94 55 85 80 8b 48 31 d7 bc 
      3f f4 de f0 8e 4b 7a 9d e5 76 d2 65 86 ce c6 4b 
      61 16 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
      0c 00 00 00 00 00 00 00 72 00 00 00 00 00 00 00
      ''',
    'tag': '1a e1 0b 59 4f 09 e2 6a 7e 90 2e cb d0 60 06 91',
  },
];
