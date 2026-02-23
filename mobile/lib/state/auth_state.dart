import 'package:riverpod_annotation/riverpod_annotation.dart';

import '../security/secure_storage_service.dart';

part 'auth_state.g.dart';

@riverpod
class AuthState extends _$AuthState {
  @override
  Future<bool> build() async {
    final storage = ref.read(secureStorageProvider);
    final token = await storage.readValue(key: SecureStorageKeys.deviceToken);
    return token != null && token.isNotEmpty;
  }

  Future<void> setRegistered(bool registered) async {
    state = AsyncValue.data(registered);
  }
}
