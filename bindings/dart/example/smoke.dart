/// Smoke test for the NEXUS-Q Dart SDK.
///
/// Run from the repository root:
///   NEXUSQ_LIBRARY=target/debug/libnexusq.so dart run bindings/dart/example/smoke.dart
library;

import 'dart:io';

import 'package:nexusq/nexusq.dart';

void main() {
  print('nexusq version: ${version()}');

  final dir =
      Directory.systemTemp.createTempSync('nexusq_dart_smoke_');
  final path = '${dir.path}${Platform.pathSeparator}vault.nqv';

  final vault = Vault.create(path, 'dart-test', label: 'dart-smoke');
  if (!File(path).existsSync()) {
    stderr.writeln('vault file was not created');
    exit(1);
  }
  if (vault.path != path) {
    stderr.writeln('vault.path does not match input');
    exit(1);
  }
  if (vault.formatVersion != 1) {
    stderr.writeln('format_version must be 1, got ${vault.formatVersion}');
    exit(1);
  }
  print('vault created at ${vault.path}');
  print('vault format version: ${vault.formatVersion}');

  try {
    Vault.create('${dir.path}${Platform.pathSeparator}no${Platform.pathSeparator}parent${Platform.pathSeparator}v.nqv', 'x');
    stderr.writeln('creating a vault under a missing directory must fail');
    exit(1);
  } on NexusqException catch (e) {
    if (e.message == null || e.message!.isEmpty) {
      stderr.writeln('error without message');
      exit(1);
    }
  }
  print('error propagation: ok');
  print('smoke test passed');
}
