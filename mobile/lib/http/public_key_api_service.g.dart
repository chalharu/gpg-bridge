// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'public_key_api_service.dart';

// **************************************************************************
// RiverpodGenerator
// **************************************************************************

// GENERATED CODE - DO NOT MODIFY BY HAND
// ignore_for_file: type=lint, type=warning

@ProviderFor(publicKeyApi)
const publicKeyApiProvider = PublicKeyApiProvider._();

final class PublicKeyApiProvider
    extends
        $FunctionalProvider<
          PublicKeyApiService,
          PublicKeyApiService,
          PublicKeyApiService
        >
    with $Provider<PublicKeyApiService> {
  const PublicKeyApiProvider._()
    : super(
        from: null,
        argument: null,
        retry: null,
        name: r'publicKeyApiProvider',
        isAutoDispose: false,
        dependencies: null,
        $allTransitiveDependencies: null,
      );

  @override
  String debugGetCreateSourceHash() => _$publicKeyApiHash();

  @$internal
  @override
  $ProviderElement<PublicKeyApiService> $createElement(
    $ProviderPointer pointer,
  ) => $ProviderElement(pointer);

  @override
  PublicKeyApiService create(Ref ref) {
    return publicKeyApi(ref);
  }

  /// {@macro riverpod.override_with_value}
  Override overrideWithValue(PublicKeyApiService value) {
    return $ProviderOverride(
      origin: this,
      providerOverride: $SyncValueProvider<PublicKeyApiService>(value),
    );
  }
}

String _$publicKeyApiHash() => r'9603b831a4bb39271cc79e6fa9b2a6c4fb0fbdba';
