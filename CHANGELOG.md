## 1.0.0

- Initial version.

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
