// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'fcm_token_service.dart';

// **************************************************************************
// RiverpodGenerator
// **************************************************************************

// GENERATED CODE - DO NOT MODIFY BY HAND
// ignore_for_file: type=lint, type=warning

@ProviderFor(fcmToken)
const fcmTokenProvider = FcmTokenProvider._();

final class FcmTokenProvider
    extends
        $FunctionalProvider<FcmTokenService, FcmTokenService, FcmTokenService>
    with $Provider<FcmTokenService> {
  const FcmTokenProvider._()
    : super(
        from: null,
        argument: null,
        retry: null,
        name: r'fcmTokenProvider',
        isAutoDispose: false,
        dependencies: null,
        $allTransitiveDependencies: null,
      );

  @override
  String debugGetCreateSourceHash() => _$fcmTokenHash();

  @$internal
  @override
  $ProviderElement<FcmTokenService> $createElement($ProviderPointer pointer) =>
      $ProviderElement(pointer);

  @override
  FcmTokenService create(Ref ref) {
    return fcmToken(ref);
  }

  /// {@macro riverpod.override_with_value}
  Override overrideWithValue(FcmTokenService value) {
    return $ProviderOverride(
      origin: this,
      providerOverride: $SyncValueProvider<FcmTokenService>(value),
    );
  }
}

String _$fcmTokenHash() => r'959e74058d08ddd3b27c537f2c1a81eefee360cc';
