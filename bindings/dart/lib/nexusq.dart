/// NEXUS-Q Dart bindings.
///
/// This is a thin FFI wrapper over the stable C SDK. It does not reimplement
/// cryptography or business logic; every operation delegates to libnexusq.
///
/// The library is resolved from the `NEXUSQ_LIBRARY` environment variable when
/// set, otherwise `libnexusq.so` is used. Build the C SDK first:
/// `cargo build -p nexusq-c`.
library;


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

final DynamicLibrary _lib = () {
  final fromEnv = Platform.environment['NEXUSQ_LIBRARY'];
  if (fromEnv != null && fromEnv.isNotEmpty) return _openLibrary(fromEnv);

  if (Platform.isLinux) {
    if (File('/lib/ld-musl-x86_64.so.1').existsSync() ||
        File('/lib/ld-musl-aarch64.so.1').existsSync()) {
      throw StateError('NEXUS-Q prebuilt Linux runtimes require glibc, not musl/Alpine. Set NEXUSQ_LIBRARY to a compatible build.');
    }
    return _openLibrary('libnexusq.so');
  }
  if (Platform.isMacOS) return _openLibrary('libnexusq.dylib');
  if (Platform.isWindows) return _openLibrary('nexusq.dll');
  throw UnsupportedError('NEXUS-Q Dart FFI has no configured runtime name for ${Platform.operatingSystem}; set NEXUSQ_LIBRARY to a compatible library.');
}();

DynamicLibrary _openLibrary(String name) {
  try {
    return DynamicLibrary.open(name);
  } catch (error) {
    throw StateError('Unable to load NEXUS-Q native library "$name". Install a compatible libnexusq runtime or set NEXUSQ_LIBRARY. Original error: $error');
  }
}

final _version = _lib
    .lookupFunction<_VersionC, _VersionDart>('nexusq_version');
final _lastError = _lib
    .lookupFunction<_LastErrorC, _LastErrorDart>('nexusq_last_error_message');
final _backendName = _lib.lookupFunction<_VersionC, _VersionDart>('nexusq_backend_name');
final _backendExperimental = _lib.lookupFunction<_BackendExperimentalC, _BackendExperimentalDart>('nexusq_backend_is_experimental');
final _vaultCreate = _lib
    .lookupFunction<_VaultCreateC, _VaultCreateDart>('nexusq_vault_create');
final _vaultFormatVersion = _lib.lookupFunction<_VaultFormatVersionC,
    _VaultFormatVersionDart>('nexusq_vault_format_version');

String? _borrowed(Pointer<Char> p) {
  if (p == nullptr) return null;
  return p.cast<Utf8>().toDartString();
}

/// Returns the library version string.
String version() => _borrowed(_version())!;

/// Reports the provider compiled into the loaded library; this does not switch providers.
Map<String, Object> backendInfo() {
  final name = _borrowed(_backendName())!;
  return {'name': name, 'experimental': _backendExperimental() != 0, 'nativeAvailable': name == 'native-experimental'};
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
