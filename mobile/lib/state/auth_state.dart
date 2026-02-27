import 'package:riverpod_annotation/riverpod_annotation.dart';

import '../security/secure_storage_service.dart';

part 'auth_state.g.dart';

@riverpod
class AuthState extends _$AuthState {
  @override
  Future<bool> build() async {
    final storage = ref.read(secureStorageProvider);
    final jwt = await storage.readValue(key: SecureStorageKeys.deviceJwt);
    return jwt != null && jwt.isNotEmpty;
  }

  Future<void> setRegistered(bool registered) async {
    state = AsyncValue.data(registered);
  }
}
