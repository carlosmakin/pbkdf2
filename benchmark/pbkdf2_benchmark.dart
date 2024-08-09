import 'package:benchmark_harness/benchmark_harness.dart';
import 'package:pbkdf2/export.dart';

import 'benchmark.dart';

class PBKDF2Benchmark extends BenchmarkBase {
  const PBKDF2Benchmark() : super('pbkdf2', emitter: emitter);

  static void main() => PBKDF2Benchmark().report();

  @override
  void run() => PBKDF2.deriveKey(password, salt, iterations, length, hash);

  @override
  void exercise() {
    for (int i = 0; i < numRuns; ++i) {
      run();
    }
  }
}

void main() => PBKDF2Benchmark.main();
