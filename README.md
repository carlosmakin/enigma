## Enigma Dart Package

A minimal package for basic cryptographic operations in Dart.

## Key Features

- **AES Key Strengths**: Supports AES-128, AES-192, AES-256 for diverse security requirements.
- **AES Key Derivation**: Implements PBKDF2 with SHA-256 HMAC for robust passphrase-based key generation, adhering to industry standards.
- **Random Generation**: Utilizes the Fortuna algorithm, a well-recognized CSPRNG, for generating cryptographically secure random keys and initial vectors.
- **AES-CBC for Encryption / Decryption**: Provides encryption and decryption capabilities for byte data using AES in Cipher Block Chaining (CBC) mode, a widely-used symmetric encryption standard.
- **AES-GCM for Authenticated Encryption / Decryption**: Includes support for AES in Galois/Counter Mode (GCM), offering both encryption and built-in data integrity checks.
- **ChaCha20 and ChaCha20-Poly1305**: Offers encryption with ChaCha20 (RFC 7539 compliant) and ChaCha20-Poly1305 for high-speed, secure stream encryption and authenticated encryption respectively.
- **RSA Key Generation and Utilization**: Facilitates RSA key pair generation and provides utilities for data encryption, decryption, signing, and signature verification, suitable for secure key exchange and digital signatures.

## Getting Started

To start using the Enigma package, add it as a dependency in your Dart project's `pubspec.yaml` file.

## Usage

This section provides real-world scenarios to demonstrate comprehensive usage of cryptographic functions, including encryption, key exchange, and digital signature integration.

### Secure File Transfer with AES-CBC and RSA Key Exchange

**Scenario**: Securely sending a large file over an insecure network using AES-CBC for file encryption and RSA for key exchange.

```dart
import 'package:enigma/enigma.dart';
import 'dart:io';

// Encrypts the file with AES-CBC
void encryptFileForTransfer(String filePath, String outputPath, RSAPublicKey recipientPublicKey) async {
  // Generating AES key and IV
  final key = generateRandomKey(AESKeyStrength.aes256);
  final iv = generateRandomIV();

  // Reading and encrypting file data
  final fileData = await File(filePath).readAsBytes();
  final encryptedData = encryptAesCbc(key, iv, fileData);

  // Encrypting AES key with recipient's RSA public key
  final encryptedKey = rsaEncrypt(recipientPublicKey, key);

  // Combining encrypted key, IV, and data for output
  final outputData = encryptedKey + iv + encryptedData;
  File(outputPath).writeAsBytesSync(outputData);
}

// Decrypts the received file
void decryptReceivedFile(String encryptedFilePath, String outputPath, RSAPrivateKey privateKey) {
  // Reading encrypted file data
  final encryptedFileData = File(encryptedFilePath).readAsBytesSync();

  // Extracting encrypted key, IV, and encrypted file data
  final encryptedKey = encryptedFileData.sublist(0, 256); // Assuming RSA-2048
  final iv = encryptedFileData.sublist(256, 272); // IV is 16 bytes
  final encryptedData = encryptedFileData.sublist(272);

  // Decrypting AES key and file data
  final key = rsaDecrypt(privateKey, encryptedKey);
  final decryptedData = decryptAesCbc(key, iv, encryptedData);

  // Writing decrypted data to file
  File(outputPath).writeAsBytesSync(decryptedData);
}
```

### Secure Messaging with AES-GCM and Digital Signatures

**Scenario**: Sending confidential and tamper-proof messages using AES-GCM for encryption and RSA for digital signatures.

```dart
import 'package:enigma/enigma.dart';

// Encrypts and signs a message
Map<String, Uint8List> encryptAndSignMessage(String message, RSAPrivateKey senderPrivateKey, RSAPublicKey recipientPublicKey) {
  // Generating AES key and nonce for GCM
  final key = generateRandomKey(AESKeyStrength.aes256);
  final nonce = generateRandomBytes(12);

  // Encrypting the message
  final encryptedData = encryptAesGcm(key, nonce, Uint8List.fromList(message.codeUnits), null);

  // Encrypting AES key with recipient's public key
  final encryptedKey = rsaEncrypt(recipientPublicKey, key);

  // Signing the encrypted data
  final signature = rsaSign(senderPrivateKey, encryptedData);

  // Returning the components of the encrypted and signed message
  return {'encryptedKey': encryptedKey, 'nonce': nonce, 'encryptedData': encryptedData, 'signature': signature};
}

// Verifies and decrypts the received message
String verifyAndDecryptMessage(Map<String, Uint8List> messageComponents, RSAPublicKey senderPublicKey, RSAPrivateKey recipientPrivateKey) {
  // Extracting message components
  final encryptedKey = messageComponents['encryptedKey']!;
  final nonce = messageComponents['nonce']!;
  final encryptedData = messageComponents['encryptedData']!;
  final signature = messageComponents['signature']!;

  // Verifying the signature
  if (!rsaVerify(senderPublicKey, encryptedData, signature)) {
    throw Exception('Signature verification failed');
  }

  // Decrypting AES key and message
  final key = rsaDecrypt(recipientPrivateKey, encryptedKey);
  final decryptedData = decryptAesGcm(key, nonce, encryptedData, null);

  // Returning decrypted message
  return String.fromCharCodes(decryptedData);
}
```

### Secure Streaming Data Processing with ChaCha20

**Scenario**: Real-time encryption and decryption of streaming data, ideal for secure audio or video streaming services.

```dart
import 'package:enigma/enigma.dart';
import 'dart:async';

// Encrypts streaming data using ChaCha20
Stream<Uint8List> encryptStreamingData(Stream<Uint8List> inputStream, Uint8List key, Uint8List nonce) {
  int nonceCounter = 0;
  return inputStream.map((data) {
    final updatedNonce = updateNonce(nonce, nonceCounter++);
    return encryptChaCha20(key, updatedNonce, data);
  });
}

// Decrypts streaming data using ChaCha20
Stream<Uint8List> decryptStreamingData(Stream<Uint8List> encryptedStream, Uint8List key, Uint8List nonce) {
  int nonceCounter = 0;
  return encryptedStream.map((data) {
    final updatedNonce = updateNonce(nonce, nonceCounter++);
    return decryptChaCha20(key, updatedNonce

, data);
  });
}

// Updates nonce for each data block
Uint8List updateNonce(Uint8List nonce, int counter) {
  final counterBytes = BigInt.from(counter).toBytes();
  return Uint8List.fromList(nonce.take(nonce.length - counterBytes.length).toList() + counterBytes);
}
```

### Secure File Download with ChaCha20-Poly1305

**Scenario**: Securely downloading files from untrusted sources with integrity and confidentiality checks using ChaCha20-Poly1305.

```dart
import 'package:enigma/enigma.dart';
import 'dart:io';
import 'dart:async';

// Downloads and decrypts a file using ChaCha20-Poly1305
Future<void> downloadAndDecryptFile(String url, Uint8List key, Uint8List nonce, Uint8List? aad, String outputPath) async {
  final httpClient = HttpClient();
  final request = await httpClient.getUrl(Uri.parse(url));
  final response = await request.close();

  // Processing each chunk of the downloaded file
  await for (var encryptedChunk in response) {
    final decryptedChunk = decryptChaCha20Poly1305(key, nonce, encryptedChunk, aad);
    await File(outputPath).writeAsBytes(decryptedChunk, mode: FileMode.append);
  }
}
```

## Dependencies

- [`pointycastle`](https://pub.dev/packages/pointycastle) - For cryptographic operations.

## Additional Information

Contributions are welcome. For questions or issues, please open an issue on the repository.
