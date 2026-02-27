// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'gpg_key_api_service.dart';

// **************************************************************************
// RiverpodGenerator
// **************************************************************************

// GENERATED CODE - DO NOT MODIFY BY HAND
// ignore_for_file: type=lint, type=warning

@ProviderFor(gpgKeyApi)
const gpgKeyApiProvider = GpgKeyApiProvider._();

final class GpgKeyApiProvider
    extends
        $FunctionalProvider<
          GpgKeyApiService,
          GpgKeyApiService,
          GpgKeyApiService
        >
    with $Provider<GpgKeyApiService> {
  const GpgKeyApiProvider._()
    : super(
        from: null,
        argument: null,
        retry: null,
        name: r'gpgKeyApiProvider',
        isAutoDispose: false,
        dependencies: null,
        $allTransitiveDependencies: null,
      );

  @override
  String debugGetCreateSourceHash() => _$gpgKeyApiHash();

  @$internal
  @override
  $ProviderElement<GpgKeyApiService> $createElement($ProviderPointer pointer) =>
      $ProviderElement(pointer);

  @override
  GpgKeyApiService create(Ref ref) {
    return gpgKeyApi(ref);
  }

  /// {@macro riverpod.override_with_value}
  Override overrideWithValue(GpgKeyApiService value) {
    return $ProviderOverride(
      origin: this,
      providerOverride: $SyncValueProvider<GpgKeyApiService>(value),
    );
  }
}

String _$gpgKeyApiHash() => r'be3e1f87a3549362fc4e457681215834a72e56a1';
