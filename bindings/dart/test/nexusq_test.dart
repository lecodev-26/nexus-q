import 'dart:io';

import 'package:nexusq/nexusq.dart';
import 'package:test/test.dart';

void main() {
  test('version is reported', () {
    expect(version(), startsWith('4.1.1'));
  });

  test('backend metadata is consistent', () {
    final info = backendInfo();
    expect(info['name'], isNotNull);
    expect(info['nativeAvailable'], info['name'] == 'native-experimental');
    expect(info['experimental'], info['nativeAvailable']);
  });

  test('vault create round trip', () {
    final dir = Directory.systemTemp.createTempSync('nexusq_dart_test_');
    addTearDown(() => dir.deleteSync(recursive: true));
    final path = '${dir.path}${Platform.pathSeparator}vault.nqv';
    final vault = Vault.create(path, 'dart-test', label: 'dart-test');
    expect(File(path).existsSync(), isTrue);
    expect(vault.path, path);
    expect(vault.formatVersion, 1);
  });

  test('vault create without label', () {
    final dir = Directory.systemTemp.createTempSync('nexusq_dart_test_');
    addTearDown(() => dir.deleteSync(recursive: true));
    final path = '${dir.path}${Platform.pathSeparator}vault.nqv';
    final vault = Vault.create(path, 'dart-test');
    expect(vault.formatVersion, 1);
  });

  test('failures carry library messages', () {
    final dir = Directory.systemTemp.createTempSync('nexusq_dart_test_');
    addTearDown(() => dir.deleteSync(recursive: true));
    expect(
        () => Vault.create(
            '${dir.path}${Platform.pathSeparator}no${Platform.pathSeparator}parent${Platform.pathSeparator}v.nqv',
            'x'),
        throwsA(isA<NexusqException>()
            .having((e) => e.message, 'message', isNotNull)));
  });
}
