### 3.0.0

#### New Features:
1. **RSA Cryptography**: 
   - Introduced RSA key generation, encryption, decryption, signing, and verification functions.
   - Supports RSA key strengths: RSA-2048, RSA-3072, RSA-4096.

2. **AES-GCM Mode**:
   - Added support for AES encryption in Galois/Counter Mode (GCM) with integrated authentication.

3. **ChaCha20 and ChaCha20-Poly1305**:
   - Implemented ChaCha20 encryption and decryption as per RFC 7539.
   - Added ChaCha20-Poly1305 for authenticated encryption and decryption.

4. **Unit Test Enhancements**:
   - Updated and extended unit tests to cover new cryptographic functions.
   - Improved test coverage for robustness and reliability.

5. **Code Organization**:
   - Refactored and better organized cryptographic functions for improved readability and maintainability.

#### Breaking Changes:
- Removed functions: `encryptText`, `decryptText`, `encryptTextWithEmbeddedIV`, and `decryptTextWithEmbeddedIV`.
- Removed functions: `encryptBytes`, `decryptBytes`, `encryptBytesWithEmbeddedIV`, and `decryptBytesWithEmbeddedIV`.
- Removed functions: `encryptBytesFast`, `decryptBytesFast`, `encryptBytesWithEmbeddedIVFast`, and `decryptBytesWithEmbeddedIVFast`.
- Removed splitting/joining of IV and cipher data in base64-encoded strings.

#### General Improvements:
- Enhanced clarity and consistency in function naming and code documentation.
- Expanded descriptions and usage examples for better user guidance.

## 2.0.0

#### Modified Functions:
1. **`encryptText`** and **`decryptText`**:
   - Updated to return base64-encoded ciphertext directly from `encryptBytes` and plaintext directly from `decryptBytes`, respectively.
   - Removed splitting and joining of IV and cipher data in the base64-encoded string.

2. **`encryptBytes`** and **`decryptBytes`**:
   - No changes.

3. **`encryptBytesWithIsolates`** and **`decryptBytesWithIsolates`** (Renamed to `encryptBytesFast` and `decryptBytesFast`):
   - Renamed for clarity and to reflect performance improvements.
   - Functionality remains unchanged.

#### Added Functions:
1. **`encryptTextWithEmbeddedIV`** and **`decryptTextWithEmbeddedIV`**:
   - Newly added functions to handle text encryption/decryption where IV is embedded within the cipher data.

2. **`encryptBytesWithEmbeddedIV`** and **`decryptBytesWithEmbeddedIV`**:
   - Newly added functions for encrypting/decrypting byte data where IV is embedded within the cipher data.
   - This approach simplifies the handling of IVs by combining them with cipher data, improving ease of use.

3. **`encryptBytesWithEmbeddedIVFast`** and **`decryptBytesWithEmbeddedIVFast`**:
   - Newly added functions for encrypting/decrypting byte data with embedded IVs using isolates for improved performance.
   - These functions are optimized for handling larger datasets more efficiently.

## 1.0.0

- Initial version.
