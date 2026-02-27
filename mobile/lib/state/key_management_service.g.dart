// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'key_management_service.dart';

// **************************************************************************
// RiverpodGenerator
// **************************************************************************

// GENERATED CODE - DO NOT MODIFY BY HAND
// ignore_for_file: type=lint, type=warning

@ProviderFor(keyManagement)
const keyManagementProvider = KeyManagementProvider._();

final class KeyManagementProvider
    extends
        $FunctionalProvider<
          KeyManagementService,
          KeyManagementService,
          KeyManagementService
        >
    with $Provider<KeyManagementService> {
  const KeyManagementProvider._()
    : super(
        from: null,
        argument: null,
        retry: null,
        name: r'keyManagementProvider',
        isAutoDispose: false,
        dependencies: null,
        $allTransitiveDependencies: null,
      );

  @override
  String debugGetCreateSourceHash() => _$keyManagementHash();

  @$internal
  @override
  $ProviderElement<KeyManagementService> $createElement(
    $ProviderPointer pointer,
  ) => $ProviderElement(pointer);

  @override
  KeyManagementService create(Ref ref) {
    return keyManagement(ref);
  }

  /// {@macro riverpod.override_with_value}
  Override overrideWithValue(KeyManagementService value) {
    return $ProviderOverride(
      origin: this,
      providerOverride: $SyncValueProvider<KeyManagementService>(value),
    );
  }
}

String _$keyManagementHash() => r'fee2905ad1e2ef7ab56121ce7b3b42676619da87';
