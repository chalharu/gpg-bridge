// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'device_assertion_jwt_service.dart';

// **************************************************************************
// RiverpodGenerator
// **************************************************************************

// GENERATED CODE - DO NOT MODIFY BY HAND
// ignore_for_file: type=lint, type=warning

@ProviderFor(deviceAssertionJwt)
const deviceAssertionJwtProvider = DeviceAssertionJwtProvider._();

final class DeviceAssertionJwtProvider
    extends
        $FunctionalProvider<
          DeviceAssertionJwtService,
          DeviceAssertionJwtService,
          DeviceAssertionJwtService
        >
    with $Provider<DeviceAssertionJwtService> {
  const DeviceAssertionJwtProvider._()
    : super(
        from: null,
        argument: null,
        retry: null,
        name: r'deviceAssertionJwtProvider',
        isAutoDispose: false,
        dependencies: null,
        $allTransitiveDependencies: null,
      );

  @override
  String debugGetCreateSourceHash() => _$deviceAssertionJwtHash();

  @$internal
  @override
  $ProviderElement<DeviceAssertionJwtService> $createElement(
    $ProviderPointer pointer,
  ) => $ProviderElement(pointer);

  @override
  DeviceAssertionJwtService create(Ref ref) {
    return deviceAssertionJwt(ref);
  }

  /// {@macro riverpod.override_with_value}
  Override overrideWithValue(DeviceAssertionJwtService value) {
    return $ProviderOverride(
      origin: this,
      providerOverride: $SyncValueProvider<DeviceAssertionJwtService>(value),
    );
  }
}

String _$deviceAssertionJwtHash() =>
    r'73ca8c622cd0583d381dcf9ded9f3971ad91543e';

@ProviderFor(keystorePlatform)
const keystorePlatformProvider = KeystorePlatformProvider._();

final class KeystorePlatformProvider
    extends
        $FunctionalProvider<
          KeystorePlatformService,
          KeystorePlatformService,
          KeystorePlatformService
        >
    with $Provider<KeystorePlatformService> {
  const KeystorePlatformProvider._()
    : super(
        from: null,
        argument: null,
        retry: null,
        name: r'keystorePlatformProvider',
        isAutoDispose: false,
        dependencies: null,
        $allTransitiveDependencies: null,
      );

  @override
  String debugGetCreateSourceHash() => _$keystorePlatformHash();

  @$internal
  @override
  $ProviderElement<KeystorePlatformService> $createElement(
    $ProviderPointer pointer,
  ) => $ProviderElement(pointer);

  @override
  KeystorePlatformService create(Ref ref) {
    return keystorePlatform(ref);
  }

  /// {@macro riverpod.override_with_value}
  Override overrideWithValue(KeystorePlatformService value) {
    return $ProviderOverride(
      origin: this,
      providerOverride: $SyncValueProvider<KeystorePlatformService>(value),
    );
  }
}

String _$keystorePlatformHash() => r'b84099af247b4238ed3e12e51a248df55d9ee5ce';
