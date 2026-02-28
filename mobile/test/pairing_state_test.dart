import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:gpg_bridge_mobile/state/pairing_service.dart';
import 'package:gpg_bridge_mobile/state/pairing_state.dart';

void main() {
  group('PairingState', () {
    late _MockPairingService mockService;
    late ProviderContainer container;

    setUp(() {
      mockService = _MockPairingService();
      container = ProviderContainer(
        overrides: [pairingServiceProvider.overrideWithValue(mockService)],
      );
    });

    tearDown(() => container.dispose());

    test('build loads pairings from service', () async {
      mockService.pairings = [
        PairingRecord(
          pairingId: 'p-1',
          clientId: 'c-1',
          pairedAt: DateTime.utc(2025, 6, 1),
        ),
      ];

      final result = await container.read(pairingStateProvider.future);

      expect(result, hasLength(1));
      expect(result.first.pairingId, 'p-1');
    });

    test('pair triggers state refresh on success', () async {
      mockService.pairings = [];
      // Wait for initial load.
      await container.read(pairingStateProvider.future);

      // Configure mock to return a record on pair and update pairings.
      final newRecord = PairingRecord(
        pairingId: 'p-new',
        clientId: 'c-new',
        pairedAt: DateTime.utc(2025, 7, 1),
      );
      mockService.nextPairResult = newRecord;
      mockService.pairings = [newRecord];

      await container.read(pairingStateProvider.notifier).pair('some-jwt');

      final result = await container.read(pairingStateProvider.future);
      expect(result, hasLength(1));
      expect(result.first.pairingId, 'p-new');
    });

    test('unpair triggers state refresh on success', () async {
      final existing = PairingRecord(
        pairingId: 'p-del',
        clientId: 'c-del',
        pairedAt: DateTime.utc(2025, 6, 1),
      );
      mockService.pairings = [existing];
      await container.read(pairingStateProvider.future);

      // After unpair, pairings list is empty.
      mockService.pairings = [];

      await container.read(pairingStateProvider.notifier).unpair('p-del');

      final result = await container.read(pairingStateProvider.future);
      expect(result, isEmpty);
      expect(mockService.lastUnpairedId, 'p-del');
    });

    test('error from service propagates through pair', () async {
      mockService.pairings = [];
      await container.read(pairingStateProvider.future);

      mockService.pairError = PairingException('test error');

      expect(
        () => container.read(pairingStateProvider.notifier).pair('bad-jwt'),
        throwsA(
          isA<PairingException>().having(
            (e) => e.message,
            'message',
            'test error',
          ),
        ),
      );
    });

    test('error from service propagates through unpair', () async {
      mockService.pairings = [];
      await container.read(pairingStateProvider.future);

      mockService.unpairError = PairingException('unpair error');

      expect(
        () => container.read(pairingStateProvider.notifier).unpair('some-id'),
        throwsA(
          isA<PairingException>().having(
            (e) => e.message,
            'message',
            'unpair error',
          ),
        ),
      );
    });
  });
}

class _MockPairingService implements PairingService {
  List<PairingRecord> pairings = [];
  PairingRecord? nextPairResult;
  String? lastUnpairedId;
  Exception? pairError;
  Exception? unpairError;

  @override
  Future<List<PairingRecord>> loadPairings() async => pairings;

  @override
  Future<PairingRecord> pair({required String pairingJwt}) async {
    if (pairError != null) throw pairError!;
    return nextPairResult!;
  }

  @override
  Future<void> unpair({required String pairingId}) async {
    if (unpairError != null) throw unpairError!;
    lastUnpairedId = pairingId;
  }
}
