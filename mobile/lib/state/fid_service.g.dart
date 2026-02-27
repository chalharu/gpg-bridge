// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'fid_service.dart';

// **************************************************************************
// RiverpodGenerator
// **************************************************************************

// GENERATED CODE - DO NOT MODIFY BY HAND
// ignore_for_file: type=lint, type=warning
/// Provider for Firebase Installation ID.
///
/// Override this provider in tests or if a different FID source is needed.

@ProviderFor(fidService)
const fidServiceProvider = FidServiceProvider._();

/// Provider for Firebase Installation ID.
///
/// Override this provider in tests or if a different FID source is needed.

final class FidServiceProvider
    extends $FunctionalProvider<FidService, FidService, FidService>
    with $Provider<FidService> {
  /// Provider for Firebase Installation ID.
  ///
  /// Override this provider in tests or if a different FID source is needed.
  const FidServiceProvider._()
    : super(
        from: null,
        argument: null,
        retry: null,
        name: r'fidServiceProvider',
        isAutoDispose: false,
        dependencies: null,
        $allTransitiveDependencies: null,
      );

  @override
  String debugGetCreateSourceHash() => _$fidServiceHash();

  @$internal
  @override
  $ProviderElement<FidService> $createElement($ProviderPointer pointer) =>
      $ProviderElement(pointer);

  @override
  FidService create(Ref ref) {
    return fidService(ref);
  }

  /// {@macro riverpod.override_with_value}
  Override overrideWithValue(FidService value) {
    return $ProviderOverride(
      origin: this,
      providerOverride: $SyncValueProvider<FidService>(value),
    );
  }
}

String _$fidServiceHash() => r'942fc04e1788101040a96e9e90245236b1381950';
