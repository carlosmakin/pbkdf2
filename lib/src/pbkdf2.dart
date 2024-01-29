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
      throw ArgumentError('Requested derived key too long');
    }

    final int l = (length / hashLen).ceil();
    final Hmac prf = Hmac(hash, password);
    final Uint8List buffer = Uint8List(hashLen);
    final Uint8List result = Uint8List(length);

    int offset = 0;
    for (int i = 1; i <= l; i++) {
      final Uint8List block = _f(salt, iterations, i, prf, buffer);

      final int blockSize = (i == l) ? length - offset : hashLen;
      result.setRange(offset, offset + blockSize, block);
      offset += blockSize;
    }

    return result;
  }
}

/// Internal function to calculate the T_i blocks in the PBKDF2 function.
///
/// It takes the salt, iteration count, index, pseudorandom function (PRF), and a buffer.
/// For each block, it applies the PRF to the concatenated salt and index and then XORs the result
/// over the specified number of iterations. The resulting value is used in the derivation of the final key.
Uint8List _f(
  Uint8List salt,
  int iterations,
  int index,
  Hmac prf,
  Uint8List buffer,
) {
  List<int> u = prf.convert(salt + _intToBigEndian(index)).bytes;
  for (int i = 0; i < buffer.length; i++) {
    buffer[i] = u[i];
  }

  for (int i = 1; i < iterations; i++) {
    u = prf.convert(u).bytes;
    for (int j = 0; j < buffer.length; j++) {
      buffer[j] ^= u[j];
    }
  }

  return buffer;
}

/// Converts an integer to its big-endian representation.
///
/// This is used to convert the block index to a big-endian format as required by the PBKDF2 specification.
/// The function takes an integer and returns a Uint8List representing the integer in big-endian byte order.
Uint8List _intToBigEndian(int i) {
  final ByteData bytes = ByteData(4);
  bytes.setUint32(0, i, Endian.big);
  return bytes.buffer.asUint8List();
}
