import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

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

  Future<void> writeValue({required String key, required String value}) {
    return _backend.write(key: key, value: value);
  }

  Future<String?> readValue({required String key}) {
    return _backend.read(key: key);
  }

  Future<void> deleteValue({required String key}) {
    return _backend.delete(key: key);
  }
}

final secureStorageProvider = Provider<SecureStorageService>((ref) {
  const storage = FlutterSecureStorage();
  return SecureStorageService(FlutterSecureStorageBackend(storage));
});
