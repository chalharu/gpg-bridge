import 'package:flutter_test/flutter_test.dart';
import 'package:gpg_bridge_mobile/security/secure_storage_service.dart';

import 'helpers/in_memory_secure_storage_backend.dart';

void main() {
  test('secure storage service writes reads and deletes values', () async {
    final service = SecureStorageService(InMemorySecureStorageBackend());

    await service.writeValue(key: 'token', value: 'abc123');
    expect(await service.readValue(key: 'token'), 'abc123');

    await service.deleteValue(key: 'token');
    expect(await service.readValue(key: 'token'), isNull);
  });
}
