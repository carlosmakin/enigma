

## Enigma Dart Package

A minimal package for basic cryptographic operations in Dart.

## Key Features

- **AES Key Strengths**: Supports AES-128, AES-192, AES-256.
- **AES Key Derivation**: Implements PBKDF2 with SHA-256 HMAC (industry-standard method for password-based key derivation) for robust passphrase-based key generation.
- **Random Generation**: Securely generates random cryptographic keys and initial vectors using Fortuna algorithm (industry-standard CSPRNG).
- **AES Encryption / Decryption Utilities**: Offers functions to encrypt and decrypt both bytes and textual data using AES encryption with Cipher Block Chaining (CBC) mode (widely-adopted symmetric encryption standard).

## Getting Started

To start using the Enigma package, add it as a dependency in your Dart project's `pubspec.yaml` file.

## Usage

Here's a basic example of using the Enigma package to encrypt and decrypt text:

```dart
import 'package:enigma/enigma.dart';

void main() {
  final Uint8List key = deriveKeyFromPassphrase(
    'passphrase',
    salt: 'com.domain.name',
    iterations: 30000,
    strength: AESKeyStrength.aes256,
  );
  final Uint8List iv = generateRandomIV();

  String encrypted = encryptText(key: key, iv: iv, text: "Hello, world!");
  print("Encrypted: $encrypted");

  String decrypted = decryptText(key: key, cipherText: encrypted);
  print("Decrypted: $decrypted");
}
```

For more examples, refer to the `/example` folder in the package.

## Dependencies

- [`pointycastle`](https://pub.dev/packages/pointycastle) - For cryptographic operations.

## Additional Information

Contributions are welcome. For questions or issues, please open an issue on the repository.
