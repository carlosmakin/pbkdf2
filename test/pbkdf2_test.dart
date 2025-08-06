import 'dart:convert';

import 'package:crypto/crypto.dart';
import 'package:pbkdf2/src/pbkdf2.dart';
import 'package:test/test.dart';
import 'dart:typed_data';

typedef PBKDF2TestVector = Map<String, dynamic>;

void main() {
  group('PBKDF2 RFC 8018', () {
    for (int i = 0; i < pbkdf2TestVectors.length; i++) {
      final PBKDF2TestVector testVector = pbkdf2TestVectors[i];
      test('Test Vector ${(i + 1)}', () {
        final Hash hash = testVector['hash'];
        final Uint8List password = utf8.encode(testVector['password']);
        final Uint8List salt = utf8.encode(testVector['salt']);
        final int iterations = testVector['iterations'];
        final int length = testVector['length'];

        final Uint8List expected = parseBlockHexString(testVector['key'])!;

        final Uint8List key = PBKDF2.deriveKey(
          password,
          salt,
          iterations,
          length,
          hash,
        );

        expect(key, equals(expected));
      });
    }
  });
}

const List<PBKDF2TestVector> pbkdf2TestVectors = <PBKDF2TestVector>[
  // Test Vector #1
  <String, dynamic>{
    'hash': sha1,
    'password': 'password',
    'salt': 'salt',
    'iterations': 1,
    'length': 20,
    'key': '''
      0c 60 c8 0f 96 1f 0e 71
      f3 a9 b5 24 af 60 12 06
      2f e0 37 a6
      ''',
  },
  // Test Vector #2
  <String, dynamic>{
    'hash': sha1,
    'password': 'password',
    'salt': 'salt',
    'iterations': 2,
    'length': 20,
    'key': '''
      ea 6c 01 4d c7 2d 6f 8c
      cd 1e d9 2a ce 1d 41 f0
      d8 de 89 57
      ''',
  },
  // Test Vector #3
  <String, dynamic>{
    'hash': sha1,
    'password': 'password',
    'salt': 'salt',
    'iterations': 4096,
    'length': 20,
    'key': '''
      4b 00 79 01 b7 65 48 9a
      be ad 49 d9 26 f7 21 d0
      65 a4 29 c1
      ''',
  },
  // Test Vector #4
  <String, dynamic>{
    'hash': sha1,
    'password': 'password',
    'salt': 'salt',
    'iterations': 16777216,
    'length': 20,
    'key': '''
      ee fe 3d 61 cd 4d a4 e4
      e9 94 5b 3d 6b a2 15 8c
      26 34 e9 84
      ''',
  },
  // Test Vector #5
  <String, dynamic>{
    'hash': sha1,
    'password': 'passwordPASSWORDpassword',
    'salt': 'saltSALTsaltSALTsaltSALTsaltSALTsalt',
    'iterations': 4096,
    'length': 25,
    'key': '''
      3d 2e ec 4f e4 1c 84 9b
      80 c8 d8 36 62 c0 e4 4a
      8b 29 1a 96 4c f2 f0 70
      38
      ''',
  },
  // Test Vector #6
  <String, dynamic>{
    'hash': sha1,
    'password': 'pass\u0000word',
    'salt': 'sa\u0000lt',
    'iterations': 4096,
    'length': 16,
    'key': '''
      56 fa 6a a7 55 48 09 9d
      cc 37 d7 f0 34 25 e0 c3
      ''',
  },
];

Uint8List? parseBlockHexString(String? hexString) {
  if (hexString == null) return null;
  final String continuousHex = hexString.replaceAll(RegExp(r'\s+'), '');
  final List<String> hexBytes = <String>[];
  for (int i = 0; i < continuousHex.length; i += 2) {
    hexBytes.add(continuousHex.substring(i, i + 2));
  }
  return Uint8List.fromList(
    hexBytes.map((String byte) => int.parse(byte, radix: 16)).toList(),
  );
}
