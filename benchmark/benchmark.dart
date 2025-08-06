import 'dart:typed_data';

import 'package:benchmark_harness/benchmark_harness.dart';
import 'package:crypto/crypto.dart';

import 'pbkdf2_benchmark.dart' as pbkdf2;

void main() => pbkdf2.main();

const int numRuns = 10;

const int length = 32;
const Hash hash = sha256;
const int iterations = 10000;
final Uint8List password = Uint8List.fromList('password'.codeUnits);
final Uint8List salt = Uint8List.fromList('salt'.codeUnits);

const BenchmarkEmitter emitter = BenchmarkEmitter();

final class BenchmarkEmitter implements ScoreEmitter {
  const BenchmarkEmitter();

  @override
  void emit(String testName, double value) {
    final double microseconds = value / numRuns;

    print(
      'Benchmark Results for $testName:\n'
      '  Runs         : $numRuns x\n'
      '  Password     : ${password.lengthInBytes} bytes\n'
      '  Salt         : ${salt.lengthInBytes} bytes\n'
      '  Length       : $length bytes\n'
      '  Hash         : ${hash.runtimeType}\n'
      '  Iterations   : $iterations x\n'
      '  Runtime us   : ${microseconds.toStringAsFixed(2)} us\n',
    );
  }
}
