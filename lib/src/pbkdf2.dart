import 'dart:typed_data';
import 'package:crypto/crypto.dart';

/// Password-Based Key Derivation Function 2 (PBKDF2) (RFC 8018).
///
/// This class implements PBKDF2, a widely-used method for deriving cryptographic keys from passwords.
/// PBKDF2 applies a pseudorandom function, such as HMAC, to the input password along with a salt value
/// and repeats the process multiple times to produce a derived key, which can then be used for secure
/// data encryption.
abstract class PBKDF2 {
  /// Derives a cryptographic key from a password, salt, iteration count, and desired key length.
  ///
  /// The function uses a pseudorandom function (default: SHA-256) and repeats it a specified number
  /// of times (iterations) to increase the computational difficulty for attackers. The salt should be
  /// unique and randomly generated for each derivation to prevent rainbow table attacks. The length
  /// parameter determines the desired length of the derived key.
  ///
  /// Throws ArgumentError if the requested key length is too long.
  static Uint8List deriveKey(
    Uint8List password,
    Uint8List salt,
    int iterations,
    int length, [
    Hash hash = sha256,
  ]) {
    final int hashLen = hash.convert(<int>[]).bytes.length;

    if (length > ((2 ^ 32) - 1) * hashLen) {
      throw ArgumentError('Requested derived key too long.');
    }

    final Hmac prf = Hmac(hash, password);
    final Uint8List si = Uint8List(salt.length + 4)..setAll(0, salt);
    final Uint8List u = Uint8List(hashLen), result = Uint8List(length);

    int offset = 0;
    final int blocks = length ~/ hashLen;
    for (int i = 1; i <= blocks; ++i, offset += hashLen) {
      si.buffer.asByteData(salt.length).setUint32(0, i);
      result.setAll(offset, u..setAll(0, prf.convert(si).bytes));
      for (int j = 1; j < iterations; ++j) {
        u.setAll(0, prf.convert(u).bytes);
        for (int k = 0; k < hashLen; ++k) {
          result[offset + k] ^= u[k];
        }
      }
    }

    final int remainder = length % hashLen;
    if (remainder > 0) {
      si.buffer.asByteData(salt.length).setUint32(0, blocks + 1);
      result.setRange(offset, length, u..setAll(0, prf.convert(si).bytes));
      for (int j = 1; j < iterations; ++j) {
        u.setAll(0, prf.convert(u).bytes);
        for (int k = 0; k < remainder; ++k) {
          result[offset + k] ^= u[k];
        }
      }
    }

    return result;
  }
}
