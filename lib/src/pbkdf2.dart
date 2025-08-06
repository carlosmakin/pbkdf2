import 'dart:typed_data';
import 'package:crypto/crypto.dart';

/// Password-Based Key Derivation Function 2 (PBKDF2) (RFC 8018).
///
/// This class implements PBKDF2, a widely-used method for deriving
/// cryptographic keys from passwords. PBKDF2 applies a pseudorandom function,
/// such as HMAC, to the input password along with a salt value and repeats the
/// process multiple times to produce a derived key, which can then be used for
/// secure data encryption.
abstract final class PBKDF2 {
  /// Derives a cryptographic key from a password, salt, iteration count, and
  /// desired key length.
  ///
  /// The function uses a pseudorandom function (default: SHA-256) and repeats
  /// it a specified number of times (iterations) to increase the computational
  /// difficulty for attackers. The salt should be unique and randomly generated
  /// for each derivation to prevent rainbow table attacks. The length parameter
  ///  determines the desired length of the derived key.
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
    final int saltLen = salt.length;

    if (length > ((2 ^ 32) - 1) * hashLen) {
      throw ArgumentError('Requested derived key too long.');
    }

    final Hmac prf = Hmac(hash, password);
    final Uint8List si = Uint8List(saltLen + 4)..setAll(0, salt);
    final Uint8List u = Uint8List(hashLen), output = Uint8List(length);
    final ByteData sibd = si.buffer.asByteData();

    final int blocks = length ~/ hashLen;
    for (int i = 1, offset = 0; i <= blocks; ++i) {
      sibd.setUint32(saltLen, i, Endian.big);
      u.setAll(0, prf.convert(si).bytes);
      output.setAll(offset, u);

      for (int j = 1; j < iterations; ++j) {
        u.setAll(0, prf.convert(u).bytes);

        for (int k = 0; k < hashLen; ++k) {
          output[offset + k] ^= u[k];
        }
      }

      offset += hashLen;
    }

    final int remainder = length % hashLen;
    if (remainder > 0) {
      final int offset = length - remainder;

      sibd.setUint32(saltLen, blocks + 1, Endian.big);
      u.setAll(0, prf.convert(si).bytes);
      output.setRange(offset, length, u);

      for (int j = 1; j < iterations; ++j) {
        u.setAll(0, prf.convert(u).bytes);

        for (int k = 0; k < remainder; ++k) {
          output[offset + k] ^= u[k];
        }
      }
    }

    return output;
  }
}
