// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'sign_request_state.dart';

// **************************************************************************
// RiverpodGenerator
// **************************************************************************

// GENERATED CODE - DO NOT MODIFY BY HAND
// ignore_for_file: type=lint, type=warning
/// Riverpod notifier managing the list of pending decrypted sign requests.
///
/// Lifecycle: FCM notification → fetch → decrypt → display → user responds.

@ProviderFor(SignRequestState)
const signRequestStateProvider = SignRequestStateProvider._();

/// Riverpod notifier managing the list of pending decrypted sign requests.
///
/// Lifecycle: FCM notification → fetch → decrypt → display → user responds.
final class SignRequestStateProvider
    extends
        $AsyncNotifierProvider<SignRequestState, List<DecryptedSignRequest>> {
  /// Riverpod notifier managing the list of pending decrypted sign requests.
  ///
  /// Lifecycle: FCM notification → fetch → decrypt → display → user responds.
  const SignRequestStateProvider._()
    : super(
        from: null,
        argument: null,
        retry: null,
        name: r'signRequestStateProvider',
        isAutoDispose: false,
        dependencies: null,
        $allTransitiveDependencies: null,
      );

  @override
  String debugGetCreateSourceHash() => _$signRequestStateHash();

  @$internal
  @override
  SignRequestState create() => SignRequestState();
}

String _$signRequestStateHash() => r'7648638954a69e959f4f18d7170943d198edb985';

/// Riverpod notifier managing the list of pending decrypted sign requests.
///
/// Lifecycle: FCM notification → fetch → decrypt → display → user responds.

abstract class _$SignRequestState
    extends $AsyncNotifier<List<DecryptedSignRequest>> {
  FutureOr<List<DecryptedSignRequest>> build();
  @$mustCallSuper
  @override
  void runBuild() {
    final created = build();
    final ref =
        this.ref
            as $Ref<
              AsyncValue<List<DecryptedSignRequest>>,
              List<DecryptedSignRequest>
            >;
    final element =
        ref.element
            as $ClassProviderElement<
              AnyNotifier<
                AsyncValue<List<DecryptedSignRequest>>,
                List<DecryptedSignRequest>
              >,
              AsyncValue<List<DecryptedSignRequest>>,
              Object?,
              Object?
            >;
    element.handleValue(ref, created);
  }
}
