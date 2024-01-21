/// Compares two lists of integers (`left` and `right`) for equality in a constant-time manner.
/// This approach mitigates timing attacks in cryptographic contexts by ensuring the
/// execution time depends only on the length of the lists, not the data they contain.
///
/// Returns `true` if the lists are equal, `false` otherwise.
bool secureEquals(List<int> left, List<int> right) {
  // Return false immediately if lengths differ, as the lists can't be equal.
  if (left.length != right.length) return false;

  int result = 0;
  // Compare elements using XOR; accumulate any differences in `result`.
  for (int i = 0; i < left.length; i++) {
    result |= (left[i] ^ right[i]);
  }

  // If `result` is 0, all elements matched; otherwise, at least one pair differed.
  return result == 0;
}
