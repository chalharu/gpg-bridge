// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'sign_request_api_service.dart';

// **************************************************************************
// RiverpodGenerator
// **************************************************************************

// GENERATED CODE - DO NOT MODIFY BY HAND
// ignore_for_file: type=lint, type=warning

@ProviderFor(signRequestApi)
const signRequestApiProvider = SignRequestApiProvider._();

final class SignRequestApiProvider
    extends
        $FunctionalProvider<
          SignRequestApiService,
          SignRequestApiService,
          SignRequestApiService
        >
    with $Provider<SignRequestApiService> {
  const SignRequestApiProvider._()
    : super(
        from: null,
        argument: null,
        retry: null,
        name: r'signRequestApiProvider',
        isAutoDispose: false,
        dependencies: null,
        $allTransitiveDependencies: null,
      );

  @override
  String debugGetCreateSourceHash() => _$signRequestApiHash();

  @$internal
  @override
  $ProviderElement<SignRequestApiService> $createElement(
    $ProviderPointer pointer,
  ) => $ProviderElement(pointer);

  @override
  SignRequestApiService create(Ref ref) {
    return signRequestApi(ref);
  }

  /// {@macro riverpod.override_with_value}
  Override overrideWithValue(SignRequestApiService value) {
    return $ProviderOverride(
      origin: this,
      providerOverride: $SyncValueProvider<SignRequestApiService>(value),
    );
  }
}

String _$signRequestApiHash() => r'37e72bb968070909d72f3b7f5aa8ea611ad2fa80';
