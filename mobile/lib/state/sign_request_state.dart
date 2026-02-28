import 'package:riverpod_annotation/riverpod_annotation.dart';

import 'sign_request_service.dart';

export 'sign_request_types.dart';

part 'sign_request_state.g.dart';

/// Riverpod notifier managing the list of pending decrypted sign requests.
///
/// Lifecycle: FCM notification → fetch → decrypt → display → user responds.
@Riverpod(keepAlive: true)
class SignRequestState extends _$SignRequestState {
  @override
  Future<List<DecryptedSignRequest>> build() async {
    return _fetchRequests();
  }

  /// Refreshes the pending sign request list from the server.
  Future<void> refresh() async {
    state = const AsyncValue.loading();
    state = await AsyncValue.guard(_fetchRequests);
  }

  /// Removes a request by ID (e.g. after user response or cancellation).
  void dismiss(String requestId) {
    final current = state.value;
    if (current == null) return;
    state = AsyncValue.data(
      current.where((r) => r.requestId != requestId).toList(),
    );
  }

  /// Handles a user approval.
  ///
  /// GPG signing is not yet implemented — see KAN-47.
  Future<void> approve(DecryptedSignRequest request) async {
    throw UnimplementedError('GPG signing not yet implemented - see KAN-47');
  }

  /// Handles a user denial: delegates to service and removes from list.
  Future<void> deny(DecryptedSignRequest request) async {
    final service = ref.read(signRequestServiceProvider);
    await service.deny(request: request);
    dismiss(request.requestId);
  }

  /// Marks a request as unavailable and removes from list.
  Future<void> markUnavailable(DecryptedSignRequest request) async {
    final service = ref.read(signRequestServiceProvider);
    await service.markUnavailable(request: request);
    dismiss(request.requestId);
  }

  Future<List<DecryptedSignRequest>> _fetchRequests() async {
    final service = ref.read(signRequestServiceProvider);
    final requests = await service.fetchAndDecrypt();
    // Filter out expired requests.
    return requests.where((r) => !r.isExpired).toList();
  }
}
