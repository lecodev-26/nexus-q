/// NEXUS-Q Dart bindings.
///
/// This is a thin FFI wrapper over the stable C SDK. It does not reimplement
/// cryptography or business logic; every operation delegates to libnexusq.
///
/// The library is resolved from `NEXUSQ_LIBRARY` when set. Otherwise the SDK
/// downloads the version-matched release runtime on first use, verifies SHA-256,
/// and caches it per user. Supported downloads require curl and network access
/// on first use; no C compiler or manual library path is needed.
library;

import 'package:crypto/crypto.dart';
import 'package:ffi/ffi.dart';
import 'dart:ffi';
import 'dart:io';

typedef _VersionC = Pointer<Char> Function();
typedef _VersionDart = Pointer<Char> Function();

typedef _LastErrorC = Pointer<Char> Function();
typedef _LastErrorDart = Pointer<Char> Function();
typedef _BackendExperimentalC = Uint8 Function();
typedef _BackendExperimentalDart = int Function();

typedef _VaultCreateC = Int32 Function(
    Pointer<Utf8> path, Pointer<Utf8> password, Pointer<Utf8> label);
typedef _VaultCreateDart = int Function(
    Pointer<Utf8> path, Pointer<Utf8> password, Pointer<Utf8> label);

typedef _VaultFormatVersionC = Int32 Function(Pointer<Utf8> path);
typedef _VaultFormatVersionDart = int Function(Pointer<Utf8> path);

const String _runtimeVersion = '4.1.1';

final DynamicLibrary _lib = _openLibrary(_resolveLibrary());

String _resolveLibrary() {
  final override = Platform.environment['NEXUSQ_LIBRARY'];
  if (override != null && override.isNotEmpty) return override;

  String asset;
  String localName;
  if (Platform.isLinux) {
    if (File('/lib/ld-musl-x86_64.so.1').existsSync() ||
        File('/lib/ld-musl-aarch64.so.1').existsSync()) {
      throw StateError(
          'NEXUS-Q prebuilt Linux runtimes require glibc, not musl/Alpine.');
    }
    if (Abi.current() == Abi.linuxX64) {
      asset = 'nexusq-sdk-runtime-linux-x64.so';
      localName = 'libnexusq.so';
    } else if (Abi.current() == Abi.linuxArm64) {
      asset = 'nexusq-sdk-runtime-linux-arm64.so';
      localName = 'libnexusq.so';
    } else {
      throw UnsupportedError(
          'NEXUS-Q has no prebuilt Dart runtime for ${Abi.current()}');
    }
  } else if (Platform.isMacOS && Abi.current() == Abi.macosArm64) {
    asset = 'nexusq-sdk-runtime-macos-arm64.dylib';
    localName = 'libnexusq.dylib';
  } else if (Platform.isWindows && Abi.current() == Abi.windowsX64) {
    asset = 'nexusq-sdk-runtime-windows-x64.dll';
    localName = 'nexusq.dll';
  } else {
    throw UnsupportedError(
        'NEXUS-Q has no prebuilt Dart runtime for ${Platform.operatingSystem}/${Abi.current()}');
  }

  final home =
      Platform.environment['HOME'] ?? Platform.environment['USERPROFILE'];
  if (home == null || home.isEmpty)
    throw StateError(
        'Cannot determine user home directory for the NEXUS-Q runtime cache.');
  final cache = Directory(Platform.isWindows
      ? '${Platform.environment['LOCALAPPDATA'] ?? home}\\NexusQ\\Cache\\$_runtimeVersion'
      : '${Platform.environment['XDG_CACHE_HOME'] ?? '$home/.cache'}/nexusq/$_runtimeVersion');
  cache.createSync(recursive: true);
  final library = File('${cache.path}${Platform.pathSeparator}$localName');
  final digestFile = File('${library.path}.sha256');
  if (library.existsSync() && digestFile.existsSync()) {
    final expected = digestFile.readAsStringSync().trim().toLowerCase();
    final actual = sha256.convert(library.readAsBytesSync()).toString();
    if (expected == actual) return library.path;
    library.deleteSync();
    digestFile.deleteSync();
  }

  final base =
      '${Platform.environment['NEXUSQ_TEST_RUNTIME_BASE_URL'] ?? 'https://github.com/lecodev-26/nexus-q/releases/download/v$_runtimeVersion/'}${(Platform.environment['NEXUSQ_TEST_RUNTIME_BASE_URL'] ?? '').isNotEmpty && !(Platform.environment['NEXUSQ_TEST_RUNTIME_BASE_URL']!).endsWith('/') ? '/' : ''}';
  final sumsTemp =
      File('${cache.path}${Platform.pathSeparator}checksums.download');
  final binaryTemp = File('${library.path}.download');
  try {
    _curl('$base/NATIVE-RUNTIME-SHA256SUMS', sumsTemp.path);
    final line = sumsTemp
        .readAsLinesSync()
        .where((line) => line.trim().endsWith('  $asset'))
        .firstOrNull;
    if (line == null)
      throw StateError(
          'NEXUS-Q release $_runtimeVersion has no checksum for $asset.');
    final expected = line.trim().split(RegExp(r'\s+')).first.toLowerCase();
    _curl('$base$asset', binaryTemp.path);
    final actual = sha256.convert(binaryTemp.readAsBytesSync()).toString();
    if (actual != expected)
      throw StateError(
          'SHA-256 mismatch for NEXUS-Q runtime $asset; refusing to load it.');
    if (library.existsSync()) library.deleteSync();
    binaryTemp.renameSync(library.path);
    digestFile.writeAsStringSync('$actual\n', flush: true);
    return library.path;
  } finally {
    if (sumsTemp.existsSync()) sumsTemp.deleteSync();
    if (binaryTemp.existsSync()) binaryTemp.deleteSync();
  }
}

void _curl(String url, String destination) {
  final executable = Platform.isWindows ? 'curl.exe' : 'curl';
  final result = Process.runSync(executable, [
    '--fail',
    '--location',
    '--silent',
    '--show-error',
    '--max-time',
    '90',
    '--output',
    destination,
    url,
  ]);
  if (result.exitCode != 0) {
    throw StateError(
        'Unable to download verified NEXUS-Q runtime from $url (curl exit ${result.exitCode}). Check network access and curl availability.');
  }
}

DynamicLibrary _openLibrary(String name) {
  try {
    return DynamicLibrary.open(name);
  } catch (error) {
    throw StateError(
        'Unable to load NEXUS-Q native library "$name". Install a compatible libnexusq runtime or set NEXUSQ_LIBRARY. Original error: $error');
  }
}

final _version = _lib.lookupFunction<_VersionC, _VersionDart>('nexusq_version');
final _lastError = _lib
    .lookupFunction<_LastErrorC, _LastErrorDart>('nexusq_last_error_message');
final _backendName =
    _lib.lookupFunction<_VersionC, _VersionDart>('nexusq_backend_name');
final _backendExperimental =
    _lib.lookupFunction<_BackendExperimentalC, _BackendExperimentalDart>(
        'nexusq_backend_is_experimental');
final _vaultCreate =
    _lib.lookupFunction<_VaultCreateC, _VaultCreateDart>('nexusq_vault_create');
final _vaultFormatVersion =
    _lib.lookupFunction<_VaultFormatVersionC, _VaultFormatVersionDart>(
        'nexusq_vault_format_version');

String? _borrowed(Pointer<Char> p) {
  if (p == nullptr) return null;
  return p.cast<Utf8>().toDartString();
}

/// Returns the library version string.
String version() => _borrowed(_version())!;

/// Reports the provider compiled into the loaded library; this does not switch providers.
Map<String, Object> backendInfo() {
  final name = _borrowed(_backendName())!;
  return {
    'name': name,
    'experimental': _backendExperimental() != 0,
    'nativeAvailable': name == 'native-experimental'
  };
}

/// Returns the last error message on the calling thread, or null.
String? lastError() => _borrowed(_lastError());

/// A NEXUS-Q vault created on disk.
class Vault {
  /// Path of the vault file on disk.
  final String path;

  /// Format version byte of the vault (currently 1).
  final int formatVersion;

  Vault._(this.path, this.formatVersion);

  /// Creates a new vault at [path] with the given [password].
  /// [label] is optional and may be null.
  ///
  /// Throws [NexusqException] when the operation fails; the message is
  /// borrowed from the library's last error.
  static Vault create(String path, String password, {String? label}) {
    final pathC = path.toNativeUtf8();
    final passwordC = password.toNativeUtf8();
    final labelC = label?.toNativeUtf8() ?? nullptr;
    try {
      final rc = _vaultCreate(pathC, passwordC, labelC);
      if (rc != 0) {
        throw NexusqException(lastError());
      }
      final formatVersion = _vaultFormatVersion(pathC);
      if (formatVersion < 0) {
        throw NexusqException(lastError());
      }
      return Vault._(path, formatVersion);
    } finally {
      malloc.free(pathC);
      malloc.free(passwordC);
      if (labelC != nullptr) malloc.free(labelC);
    }
  }
}

/// Error raised when a NEXUS-Q operation fails.
class NexusqException implements Exception {
  final String? message;
  NexusqException(this.message);
  @override
  String toString() =>
      'NexusqException: ${message ?? 'NEXUS-Q operation failed'}';
}
