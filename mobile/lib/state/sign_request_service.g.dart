// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'sign_request_service.dart';

// **************************************************************************
// RiverpodGenerator
// **************************************************************************

// GENERATED CODE - DO NOT MODIFY BY HAND
// ignore_for_file: type=lint, type=warning

@ProviderFor(signRequestService)
const signRequestServiceProvider = SignRequestServiceProvider._();

final class SignRequestServiceProvider
    extends
        $FunctionalProvider<
          SignRequestService,
          SignRequestService,
          SignRequestService
        >
    with $Provider<SignRequestService> {
  const SignRequestServiceProvider._()
    : super(
        from: null,
        argument: null,
        retry: null,
        name: r'signRequestServiceProvider',
        isAutoDispose: false,
        dependencies: null,
        $allTransitiveDependencies: null,
      );

  @override
  String debugGetCreateSourceHash() => _$signRequestServiceHash();

  @$internal
  @override
  $ProviderElement<SignRequestService> $createElement(
    $ProviderPointer pointer,
  ) => $ProviderElement(pointer);

  @override
  SignRequestService create(Ref ref) {
    return signRequestService(ref);
  }

  /// {@macro riverpod.override_with_value}
  Override overrideWithValue(SignRequestService value) {
    return $ProviderOverride(
      origin: this,
      providerOverride: $SyncValueProvider<SignRequestService>(value),
    );
  }
}

String _$signRequestServiceHash() =>
    r'e225eeae72a696c31e471786a16e53fd98d64d3d';
