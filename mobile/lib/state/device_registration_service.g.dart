// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'device_registration_service.dart';

// **************************************************************************
// RiverpodGenerator
// **************************************************************************

// GENERATED CODE - DO NOT MODIFY BY HAND
// ignore_for_file: type=lint, type=warning

@ProviderFor(deviceRegistration)
const deviceRegistrationProvider = DeviceRegistrationProvider._();

final class DeviceRegistrationProvider
    extends
        $FunctionalProvider<
          DeviceRegistrationService,
          DeviceRegistrationService,
          DeviceRegistrationService
        >
    with $Provider<DeviceRegistrationService> {
  const DeviceRegistrationProvider._()
    : super(
        from: null,
        argument: null,
        retry: null,
        name: r'deviceRegistrationProvider',
        isAutoDispose: false,
        dependencies: null,
        $allTransitiveDependencies: null,
      );

  @override
  String debugGetCreateSourceHash() => _$deviceRegistrationHash();

  @$internal
  @override
  $ProviderElement<DeviceRegistrationService> $createElement(
    $ProviderPointer pointer,
  ) => $ProviderElement(pointer);

  @override
  DeviceRegistrationService create(Ref ref) {
    return deviceRegistration(ref);
  }

  /// {@macro riverpod.override_with_value}
  Override overrideWithValue(DeviceRegistrationService value) {
    return $ProviderOverride(
      origin: this,
      providerOverride: $SyncValueProvider<DeviceRegistrationService>(value),
    );
  }
}

String _$deviceRegistrationHash() =>
    r'878a6a051fa7ceceb3e2d395bac77938cfafcf1e';
