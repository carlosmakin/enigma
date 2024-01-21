import 'dart:typed_data';
import 'package:enigma/src/chacha7539.dart';
import 'package:test/test.dart';

void main() {
  // test('ChaCha20 RFC 7539 2.1.1 Test Vector for the ChaCha Quarter Round', () {
  //   // Initialize 32-bit unsigned integer list
  //   final Uint32List state = Uint32List(16);

  //   // Test vector input
  //   state[0] = 0x11111111; // A
  //   state[1] = 0x01020304; // B
  //   state[2] = 0x9b8d6f43; // C
  //   state[3] = 0x01234567; // D

  //   // Test vector expected output
  //   const int expectedA = 0xea2a92f4;
  //   const int expectedB = 0xcb1cf8ce;
  //   const int expectedC = 0x4581472e;
  //   const int expectedD = 0x5881c4bb;

  //   // Running the ChaCha quarter round
  //   quarterRound(state, 0, 1, 2, 3);

  //   // Asserting that the function's output matches the expected output
  //   expect(state[0], equals(expectedA));
  //   expect(state[1], equals(expectedB));
  //   expect(state[2], equals(expectedC));
  //   expect(state[3], equals(expectedD));
  // });

  // test('ChaCha20 RFC 7539 2.2.1 Test Vector for the Quarter Round on the ChaCha State', () {
  //   // Initial 32-bit unsigned integer list state
  //   final Uint32List state = Uint32List.fromList(<int>[
  //     0x879531e0,
  //     0xc5ecf37d,
  //     0x516461b1,
  //     0xc9a62f8a,
  //     0x44c20ef3,
  //     0x3390af7f,
  //     0xd9fc690b,
  //     0x2a5f714c,
  //     0x53372767,
  //     0xb00a5631,
  //     0x974c541a,
  //     0x359e9963,
  //     0x5c971061,
  //     0x3d631689,
  //     0x2098d9d6,
  //     0x91dbd320
  //   ]);

  //   // Expected output after applying quarterRound(2,7,8,13)
  //   const List<int> expectedState = <int>[
  //     0x879531e0,
  //     0xc5ecf37d,
  //     0xbdb886dc,
  //     0xc9a62f8a,
  //     0x44c20ef3,
  //     0x3390af7f,
  //     0xd9fc690b,
  //     0xcfacafd2,
  //     0xe46bea80,
  //     0xb00a5631,
  //     0x974c541a,
  //     0x359e9963,
  //     0x5c971061,
  //     0xccc07c79,
  //     0x2098d9d6,
  //     0x91dbd320
  //   ];

  //   // Running the ChaCha quarteRound on indices 2, 7, 8, 13
  //   quarterRound(state, 2, 7, 8, 13);

  //   // Asserting that the function's output matches the expected output for all elements
  //   for (int i = 0; i < state.length; i++) {
  //     expect(state[i], equals(expectedState[i]), reason: 'Mismatch at position $i');
  //   }
  // });

  test('ChaCha20 RFC 7539 2.4.2. Example and Test Vector', () {
    final Uint8List key = parseColonSeparatedHexString(keyHexString);
    final Uint8List nonce = parseColonSeparatedHexString(nonceHexString);

    final Uint8List input = parseBlockHexString(inputHexString);
    final Uint8List output = chacha20(key, nonce, input);
    final Uint8List expected = parseBlockHexString(outputhexString);

    expect(output, equals(expected));
  });
}

const String keyHexString = '''
00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f
''';
const String nonceHexString = '''
00:00:00:00:00:00:00:4a:00:00:00:00
''';

const String inputHexString = '''
4c 61 64 69 65 73 20 61 6e 64 20 47 65 6e 74 6c
65 6d 65 6e 20 6f 66 20 74 68 65 20 63 6c 61 73
73 20 6f 66 20 27 39 39 3a 20 49 66 20 49 20 63
6f 75 6c 64 20 6f 66 66 65 72 20 79 6f 75 20 6f
6e 6c 79 20 6f 6e 65 20 74 69 70 20 66 6f 72 20
74 68 65 20 66 75 74 75 72 65 2c 20 73 75 6e 73
63 72 65 65 6e 20 77 6f 75 6c 64 20 62 65 20 69
74 2e
''';

const String outputhexString = '''
6e 2e 35 9a 25 68 f9 80 41 ba 07 28 dd 0d 69 81
e9 7e 7a ec 1d 43 60 c2 0a 27 af cc fd 9f ae 0b
f9 1b 65 c5 52 47 33 ab 8f 59 3d ab cd 62 b3 57
16 39 d6 24 e6 51 52 ab 8f 53 0c 35 9f 08 61 d8
07 ca 0d bf 50 0d 6a 61 56 a3 8e 08 8a 22 b6 5e
52 bc 51 4d 16 cc f8 06 81 8c e9 1a b7 79 37 36
5a f9 0b bf 74 a3 5b e6 b4 0b 8e ed f2 78 5e 42
87 4d
''';

Uint8List parseColonSeparatedHexString(String hexString) {
  final List<String> hexValues = hexString.replaceAll(' ', '').split(':');
  final List<int> intList = hexValues.map((String hex) => int.parse(hex, radix: 16)).toList();
  return Uint8List.fromList(intList);
}

Uint8List parseBlockHexString(String hexString) {
  final String continuousHex = hexString.replaceAll(RegExp(r'\s+'), '');
  final List<String> hexBytes = <String>[];
  for (int i = 0; i < continuousHex.length; i += 2) {
    hexBytes.add(continuousHex.substring(i, i + 2));
  }
  return Uint8List.fromList(
    hexBytes.map((String byte) => int.parse(byte, radix: 16)).toList(),
  );
}
