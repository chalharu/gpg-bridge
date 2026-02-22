import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

class SecureStorageException implements Exception {
  SecureStorageException(this.message, {this.cause});

  final String message;
  final Object? cause;

  @override
  String toString() {
    if (cause == null) {
      return 'SecureStorageException: $message';
    }
    return 'SecureStorageException: $message ($cause)';
  }
}

abstract interface class SecureStorageBackend {
  Future<void> write({required String key, required String value});
  Future<String?> read({required String key});
  Future<void> delete({required String key});
}

class FlutterSecureStorageBackend implements SecureStorageBackend {
  FlutterSecureStorageBackend(this._storage);

  final FlutterSecureStorage _storage;

  static const AndroidOptions _androidOptions = AndroidOptions(
    encryptedSharedPreferences: true,
  );

  static const IOSOptions _iosOptions = IOSOptions(
    accessibility: KeychainAccessibility.first_unlock_this_device,
  );

  @override
  Future<void> write({required String key, required String value}) {
    return _storage.write(
      key: key,
      value: value,
      aOptions: _androidOptions,
      iOptions: _iosOptions,
    );
  }

  @override
  Future<String?> read({required String key}) {
    return _storage.read(
      key: key,
      aOptions: _androidOptions,
      iOptions: _iosOptions,
    );
  }

  @override
  Future<void> delete({required String key}) {
    return _storage.delete(
      key: key,
      aOptions: _androidOptions,
      iOptions: _iosOptions,
    );
  }
}

class SecureStorageService {
  SecureStorageService(this._backend);

  final SecureStorageBackend _backend;

  Future<void> writeValue({required String key, required String value}) async {
    try {
      await _backend.write(key: key, value: value);
    } catch (error) {
      throw SecureStorageException(
        'failed to write secure value',
        cause: error,
      );
    }
  }

  Future<String?> readValue({required String key}) async {
    try {
      return await _backend.read(key: key);
    } catch (error) {
      throw SecureStorageException('failed to read secure value', cause: error);
    }
  }

  Future<void> deleteValue({required String key}) async {
    try {
      await _backend.delete(key: key);
    } catch (error) {
      throw SecureStorageException(
        'failed to delete secure value',
        cause: error,
      );
    }
  }
}

final secureStorageProvider = Provider<SecureStorageService>((ref) {
  const storage = FlutterSecureStorage();
  return SecureStorageService(FlutterSecureStorageBackend(storage));
});
