import 'package:riverpod_annotation/riverpod_annotation.dart';

import 'pairing_service.dart';

part 'pairing_state.g.dart';

/// Pairing state notifier that manages the list of local pairing records.
///
/// Uses auto-dispose (`@riverpod`) so the pairings list is reloaded from
/// secure storage each time the pairing page becomes active, ensuring
/// fresh data.
@riverpod
class PairingState extends _$PairingState {
  @override
  Future<List<PairingRecord>> build() async {
    final service = ref.read(pairingServiceProvider);
    return service.loadPairings();
  }

  Future<void> pair(String pairingJwt) async {
    final service = ref.read(pairingServiceProvider);
    await service.pair(pairingJwt: pairingJwt);
    ref.invalidateSelf();
    await future;
  }

  Future<void> unpair(String pairingId) async {
    final service = ref.read(pairingServiceProvider);
    await service.unpair(pairingId: pairingId);
    ref.invalidateSelf();
    await future;
  }
}
