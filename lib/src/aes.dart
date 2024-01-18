/// Standard AES 128-bit block size.
const int aesBlockSize = 16;

/// Enum representing AES key strength.
///
/// Each enum value corresponds to a specific key strength for the AES (Advanced Encryption Standard) algorithm.
/// The AES algorithm can operate with different key strengths, and each key strength provides a different level of security.
enum AESKeyStrength {
  /// AES-128: Offers a good balance of strong security and high performance..
  aes128(128, 16),

  /// AES-192: Provides enhanced security over AES-128, balancing security and performance.
  aes192(192, 24),

  /// AES-256: Delivers the highest security level among standard AES keys.
  aes256(256, 32);

  final int bitLength;
  final int byteLength;

  const AESKeyStrength(this.bitLength, this.byteLength);
}
