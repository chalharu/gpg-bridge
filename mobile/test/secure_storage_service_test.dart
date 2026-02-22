import 'package:flutter_test/flutter_test.dart';
import 'package:gpg_bridge_mobile/security/secure_storage_service.dart';

import 'helpers/in_memory_secure_storage_backend.dart';
import 'helpers/throwing_secure_storage_backend.dart';

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

  test('secure storage exception toString includes cause when present', () {
    final error = SecureStorageException('failed', cause: Exception('boom'));

    expect(error.toString(), contains('failed'));
    expect(error.toString(), contains('boom'));
  });

  test('secure storage exception toString omits cause when absent', () {
    final error = SecureStorageException('failed');

    expect(error.toString(), 'SecureStorageException: failed');
  });
}
