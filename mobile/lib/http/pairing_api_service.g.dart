// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'pairing_api_service.dart';

// **************************************************************************
// RiverpodGenerator
// **************************************************************************

// GENERATED CODE - DO NOT MODIFY BY HAND
// ignore_for_file: type=lint, type=warning

@ProviderFor(pairingApi)
const pairingApiProvider = PairingApiProvider._();

final class PairingApiProvider
    extends
        $FunctionalProvider<
          PairingApiService,
          PairingApiService,
          PairingApiService
        >
    with $Provider<PairingApiService> {
  const PairingApiProvider._()
    : super(
        from: null,
        argument: null,
        retry: null,
        name: r'pairingApiProvider',
        isAutoDispose: false,
        dependencies: null,
        $allTransitiveDependencies: null,
      );

  @override
  String debugGetCreateSourceHash() => _$pairingApiHash();

  @$internal
  @override
  $ProviderElement<PairingApiService> $createElement(
    $ProviderPointer pointer,
  ) => $ProviderElement(pointer);

  @override
  PairingApiService create(Ref ref) {
    return pairingApi(ref);
  }

  /// {@macro riverpod.override_with_value}
  Override overrideWithValue(PairingApiService value) {
    return $ProviderOverride(
      origin: this,
      providerOverride: $SyncValueProvider<PairingApiService>(value),
    );
  }
}

String _$pairingApiHash() => r'61fe8a5deb75b73419214924d03e2f33e1b54a42';
