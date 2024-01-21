import 'dart:typed_data';
import 'package:enigma/src/poly1305.dart';
import 'package:test/test.dart';

void main() {
  test('ChaCha20 RFC 7539 2.5.2. Poly1305 Example and Test Vector', () {
    print(parseColonSeparatedHexString('01:03:80:8a:fb:0d:b2:fd:4a:bf:f6:af:41:49:f5:1b'));
    final Uint8List key = parseColonSeparatedHexString(keyHexString);
    final Uint8List message = parseBlockHexString(messageHexString);

    final Uint8List tag = poly1305Mac(message, key);
    final Uint8List expected = parseColonSeparatedHexString(taghexString);

    expect(tag, equals(expected));
  });
}

const String keyHexString =
    '85:d6:be:78:57:55:6d:33:7f:44:52:fe:42:d5:06:a8:01:03:80:8a:fb:0d:b2:fd:4a:bf:f6:af:41:49:f5:1b';

const String messageHexString =
    '43 72 79 70 74 6f 67 72 61 70 68 69 63 20 46 6f 72 75 6d 20 52 65 73 65 61 72 63 68 20 47 72 6f 75 70';

const String taghexString = 'a8:06:1d:c1:30:51:36:c6:c2:2b:8b:af:0c:01:27:a9';

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
