// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'pairing_service.dart';

// **************************************************************************
// RiverpodGenerator
// **************************************************************************

// GENERATED CODE - DO NOT MODIFY BY HAND
// ignore_for_file: type=lint, type=warning

@ProviderFor(pairingService)
const pairingServiceProvider = PairingServiceProvider._();

final class PairingServiceProvider
    extends $FunctionalProvider<PairingService, PairingService, PairingService>
    with $Provider<PairingService> {
  const PairingServiceProvider._()
    : super(
        from: null,
        argument: null,
        retry: null,
        name: r'pairingServiceProvider',
        isAutoDispose: false,
        dependencies: null,
        $allTransitiveDependencies: null,
      );

  @override
  String debugGetCreateSourceHash() => _$pairingServiceHash();

  @$internal
  @override
  $ProviderElement<PairingService> $createElement($ProviderPointer pointer) =>
      $ProviderElement(pointer);

  @override
  PairingService create(Ref ref) {
    return pairingService(ref);
  }

  /// {@macro riverpod.override_with_value}
  Override overrideWithValue(PairingService value) {
    return $ProviderOverride(
      origin: this,
      providerOverride: $SyncValueProvider<PairingService>(value),
    );
  }
}

String _$pairingServiceHash() => r'53f1344a4aa764f9e0c60e9b535588ac77e2b1d5';
