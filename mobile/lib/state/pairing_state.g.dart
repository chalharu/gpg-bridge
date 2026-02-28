// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'pairing_state.dart';

// **************************************************************************
// RiverpodGenerator
// **************************************************************************

// GENERATED CODE - DO NOT MODIFY BY HAND
// ignore_for_file: type=lint, type=warning
/// Pairing state notifier that manages the list of local pairing records.
///
/// Uses auto-dispose (`@riverpod`) so the pairings list is reloaded from
/// secure storage each time the pairing page becomes active, ensuring
/// fresh data.

@ProviderFor(PairingState)
const pairingStateProvider = PairingStateProvider._();

/// Pairing state notifier that manages the list of local pairing records.
///
/// Uses auto-dispose (`@riverpod`) so the pairings list is reloaded from
/// secure storage each time the pairing page becomes active, ensuring
/// fresh data.
final class PairingStateProvider
    extends $AsyncNotifierProvider<PairingState, List<PairingRecord>> {
  /// Pairing state notifier that manages the list of local pairing records.
  ///
  /// Uses auto-dispose (`@riverpod`) so the pairings list is reloaded from
  /// secure storage each time the pairing page becomes active, ensuring
  /// fresh data.
  const PairingStateProvider._()
    : super(
        from: null,
        argument: null,
        retry: null,
        name: r'pairingStateProvider',
        isAutoDispose: true,
        dependencies: null,
        $allTransitiveDependencies: null,
      );

  @override
  String debugGetCreateSourceHash() => _$pairingStateHash();

  @$internal
  @override
  PairingState create() => PairingState();
}

String _$pairingStateHash() => r'debb52eae4cd01617b24ea4d912e500b499df864';

/// Pairing state notifier that manages the list of local pairing records.
///
/// Uses auto-dispose (`@riverpod`) so the pairings list is reloaded from
/// secure storage each time the pairing page becomes active, ensuring
/// fresh data.

abstract class _$PairingState extends $AsyncNotifier<List<PairingRecord>> {
  FutureOr<List<PairingRecord>> build();
  @$mustCallSuper
  @override
  void runBuild() {
    final created = build();
    final ref =
        this.ref as $Ref<AsyncValue<List<PairingRecord>>, List<PairingRecord>>;
    final element =
        ref.element
            as $ClassProviderElement<
              AnyNotifier<AsyncValue<List<PairingRecord>>, List<PairingRecord>>,
              AsyncValue<List<PairingRecord>>,
              Object?,
              Object?
            >;
    element.handleValue(ref, created);
  }
}
