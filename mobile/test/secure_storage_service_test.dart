import 'package:flutter_test/flutter_test.dart';
import 'package:gpg_bridge_mobile/security/secure_storage_service.dart';

class InMemorySecureStorageBackend implements SecureStorageBackend {
  final Map<String, String> _values = <String, String>{};

  @override
  Future<void> write({required String key, required String value}) async {
    _values[key] = value;
  }

  @override
  Future<String?> read({required String key}) async {
    return _values[key];
  }

  @override
  Future<void> delete({required String key}) async {
    _values.remove(key);
  }
}

class ThrowingSecureStorageBackend implements SecureStorageBackend {
  @override
  Future<void> write({required String key, required String value}) async {
    throw Exception('write failed');
  }

  @override
  Future<String?> read({required String key}) async {
    throw Exception('read failed');
  }

  @override
  Future<void> delete({required String key}) async {
    throw Exception('delete failed');
  }
}

void main() {
  test('secure storage service writes reads and deletes values', () async {
    final service = SecureStorageService(InMemorySecureStorageBackend());

    await service.writeValue(key: 'token', value: 'abc123');
    expect(await service.readValue(key: 'token'), 'abc123');

    await service.deleteValue(key: 'token');
    expect(await service.readValue(key: 'token'), isNull);
  });

  test('secure storage service wraps backend errors', () async {
    final service = SecureStorageService(ThrowingSecureStorageBackend());

    await expectLater(
      () => service.writeValue(key: 'token', value: 'abc123'),
      throwsA(isA<SecureStorageException>()),
    );

    await expectLater(
      () => service.readValue(key: 'token'),
      throwsA(isA<SecureStorageException>()),
    );

    await expectLater(
      () => service.deleteValue(key: 'token'),
      throwsA(isA<SecureStorageException>()),
    );
  });
}
