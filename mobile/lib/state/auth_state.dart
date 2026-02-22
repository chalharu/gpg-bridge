import 'package:riverpod_annotation/riverpod_annotation.dart';

part 'auth_state.g.dart';

@riverpod
class AuthState extends _$AuthState {
  @override
  bool build() => false;

  void setRegistered(bool registered) {
    state = registered;
  }
}
