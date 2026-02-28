// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'sign_execution_service.dart';

// **************************************************************************
// RiverpodGenerator
// **************************************************************************

// GENERATED CODE - DO NOT MODIFY BY HAND
// ignore_for_file: type=lint, type=warning

@ProviderFor(signExecutionService)
const signExecutionServiceProvider = SignExecutionServiceProvider._();

final class SignExecutionServiceProvider
    extends
        $FunctionalProvider<
          SignExecutionService,
          SignExecutionService,
          SignExecutionService
        >
    with $Provider<SignExecutionService> {
  const SignExecutionServiceProvider._()
    : super(
        from: null,
        argument: null,
        retry: null,
        name: r'signExecutionServiceProvider',
        isAutoDispose: false,
        dependencies: null,
        $allTransitiveDependencies: null,
      );

  @override
  String debugGetCreateSourceHash() => _$signExecutionServiceHash();

  @$internal
  @override
  $ProviderElement<SignExecutionService> $createElement(
    $ProviderPointer pointer,
  ) => $ProviderElement(pointer);

  @override
  SignExecutionService create(Ref ref) {
    return signExecutionService(ref);
  }

  /// {@macro riverpod.override_with_value}
  Override overrideWithValue(SignExecutionService value) {
    return $ProviderOverride(
      origin: this,
      providerOverride: $SyncValueProvider<SignExecutionService>(value),
    );
  }
}

String _$signExecutionServiceHash() =>
    r'0000000000000000000000000000000000000000';
