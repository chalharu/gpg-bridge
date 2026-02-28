import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:gpg_bridge_mobile/http/pairing_api_service.dart';
import 'package:gpg_bridge_mobile/security/secure_storage_service.dart';
import 'package:gpg_bridge_mobile/state/pairing_service.dart';

import 'helpers/in_memory_secure_storage_backend.dart';

void main() {
  group('DefaultPairingService', () {
    late _MockPairingApiService mockApi;
    late SecureStorageService storageService;
    late InMemorySecureStorageBackend storageBackend;

    setUp(() {
      mockApi = _MockPairingApiService();
      storageBackend = InMemorySecureStorageBackend();
      storageService = SecureStorageService(storageBackend);
    });

    DefaultPairingService createService() {
      return DefaultPairingService(
        apiService: mockApi,
        storageService: storageService,
      );
    }

    test('loadPairings returns empty list when no pairings', () async {
      final service = createService();

      final result = await service.loadPairings();

      expect(result, isEmpty);
    });

    test('loadPairings returns stored records', () async {
      // Seed storage with a pairing record and index.
      final record = PairingRecord(
        pairingId: 'p-1',
        clientId: 'c-1',
        pairedAt: DateTime.utc(2025, 6, 1),
      );
      await storageService.writeValue(
        key: '${SecureStorageKeys.pairingPrefix}p-1',
        value: record.toJsonString(),
      );
      await storageService.writeValue(
        key: SecureStorageKeys.pairingIds,
        value: jsonEncode(['p-1']),
      );

      final service = createService();
      final result = await service.loadPairings();

      expect(result, hasLength(1));
      expect(result.first.pairingId, 'p-1');
      expect(result.first.clientId, 'c-1');
    });

    test('loadPairings skips corrupted records', () async {
      await storageService.writeValue(
        key: '${SecureStorageKeys.pairingPrefix}bad',
        value: 'not-valid-json',
      );
      await storageService.writeValue(
        key: SecureStorageKeys.pairingIds,
        value: jsonEncode(['bad']),
      );

      final service = createService();
      final result = await service.loadPairings();

      expect(result, isEmpty);
    });

    test('pair calls API and stores record', () async {
      mockApi.nextResponse = PairingResponse(
        clientId: 'new-client',
        pairingId: 'new-pair',
      );

      final service = createService();
      final record = await service.pair(pairingJwt: 'test-jwt');

      expect(record.pairingId, 'new-pair');
      expect(record.clientId, 'new-client');
      expect(mockApi.lastPairingJwt, 'test-jwt');

      // Verify stored in secure storage.
      final storedRaw = await storageService.readValue(
        key: '${SecureStorageKeys.pairingPrefix}new-pair',
      );
      expect(storedRaw, isNotNull);

      // Verify index updated.
      final idsRaw = await storageService.readValue(
        key: SecureStorageKeys.pairingIds,
      );
      final ids = jsonDecode(idsRaw!) as List<dynamic>;
      expect(ids, contains('new-pair'));
    });

    test('pair wraps API errors in PairingException', () async {
      mockApi.shouldThrow = true;

      final service = createService();

      expect(
        () => service.pair(pairingJwt: 'jwt'),
        throwsA(isA<PairingException>()),
      );
    });

    test('unpair calls API and removes record', () async {
      // Seed storage.
      final record = PairingRecord(
        pairingId: 'del-1',
        clientId: 'c-del',
        pairedAt: DateTime.utc(2025, 1, 1),
      );
      await storageService.writeValue(
        key: '${SecureStorageKeys.pairingPrefix}del-1',
        value: record.toJsonString(),
      );
      await storageService.writeValue(
        key: SecureStorageKeys.pairingIds,
        value: jsonEncode(['del-1']),
      );

      final service = createService();
      await service.unpair(pairingId: 'del-1');

      expect(mockApi.lastDeletedId, 'del-1');

      // Verify removed from storage.
      final storedRaw = await storageService.readValue(
        key: '${SecureStorageKeys.pairingPrefix}del-1',
      );
      expect(storedRaw, isNull);

      // Verify index updated.
      final idsRaw = await storageService.readValue(
        key: SecureStorageKeys.pairingIds,
      );
      final ids = jsonDecode(idsRaw!) as List<dynamic>;
      expect(ids, isNot(contains('del-1')));
    });

    test('unpair wraps API errors in PairingException', () async {
      mockApi.shouldThrow = true;

      final service = createService();

      expect(
        () => service.unpair(pairingId: 'id'),
        throwsA(isA<PairingException>()),
      );
    });
  });
}

class _MockPairingApiService implements PairingApiService {
  PairingResponse? nextResponse;
  String? lastPairingJwt;
  String? lastDeletedId;
  bool shouldThrow = false;

  @override
  Future<PairingResponse> createPairing({required String pairingJwt}) async {
    if (shouldThrow) {
      throw PairingApiException('mock error');
    }
    lastPairingJwt = pairingJwt;
    return nextResponse!;
  }

  @override
  Future<void> deletePairing({required String pairingId}) async {
    if (shouldThrow) {
      throw PairingApiException('mock error');
    }
    lastDeletedId = pairingId;
  }
}
