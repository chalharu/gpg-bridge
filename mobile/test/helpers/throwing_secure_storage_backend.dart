import 'package:gpg_bridge_mobile/security/secure_storage_service.dart';

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
