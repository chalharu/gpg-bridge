// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'device_api_service.dart';

// **************************************************************************
// RiverpodGenerator
// **************************************************************************

// GENERATED CODE - DO NOT MODIFY BY HAND
// ignore_for_file: type=lint, type=warning

@ProviderFor(deviceApi)
const deviceApiProvider = DeviceApiProvider._();

final class DeviceApiProvider
    extends
        $FunctionalProvider<
          DeviceApiService,
          DeviceApiService,
          DeviceApiService
        >
    with $Provider<DeviceApiService> {
  const DeviceApiProvider._()
    : super(
        from: null,
        argument: null,
        retry: null,
        name: r'deviceApiProvider',
        isAutoDispose: false,
        dependencies: null,
        $allTransitiveDependencies: null,
      );

  @override
  String debugGetCreateSourceHash() => _$deviceApiHash();

  @$internal
  @override
  $ProviderElement<DeviceApiService> $createElement($ProviderPointer pointer) =>
      $ProviderElement(pointer);

  @override
  DeviceApiService create(Ref ref) {
    return deviceApi(ref);
  }

  /// {@macro riverpod.override_with_value}
  Override overrideWithValue(DeviceApiService value) {
    return $ProviderOverride(
      origin: this,
      providerOverride: $SyncValueProvider<DeviceApiService>(value),
    );
  }
}

String _$deviceApiHash() => r'7a1cc505f9574313513886cdfc784733ef5c21f5';
