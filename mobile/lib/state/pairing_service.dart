import 'dart:convert';

import 'package:riverpod_annotation/riverpod_annotation.dart';

import '../http/api_exception.dart';
import '../http/pairing_api_service.dart';
import '../security/secure_storage_service.dart';
import 'pairing_types.dart';

export 'pairing_types.dart';

part 'pairing_service.g.dart';

class DefaultPairingService implements PairingService {
  DefaultPairingService({
    required PairingApiService apiService,
    required SecureStorageService storageService,
  }) : _apiService = apiService,
       _storageService = storageService;

  final PairingApiService _apiService;
  final SecureStorageService _storageService;

  @override
  Future<List<PairingRecord>> loadPairings() async {
    final ids = await _readPairingIds();
    final records = <PairingRecord>[];
    for (final id in ids) {
      final key = '${SecureStorageKeys.pairingPrefix}$id';
      final raw = await _storageService.readValue(key: key);
      if (raw == null) continue;
      try {
        final json = jsonDecode(raw) as Map<String, dynamic>;
        records.add(PairingRecord.fromJson(json));
      } on Object {
        // Skip corrupted records.
      }
    }
    return records;
  }

  // Note: The pairing_ids index uses read-modify-write which is not atomic.
  // Concurrent mutations could lose updates. This is mitigated by:
  // 1. PairingState serializes mutations via `invalidateSelf()/await future`
  // 2. loadPairings() gracefully skips missing records, self-healing stale indices
  @override
  Future<PairingRecord> pair({required String pairingJwt}) async {
    try {
      final response = await _apiService.createPairing(pairingJwt: pairingJwt);
      // A clock abstraction can be introduced later if timestamp control becomes necessary.
      final record = PairingRecord(
        pairingId: response.pairingId,
        clientId: response.clientId,
        pairedAt: DateTime.now(),
      );
      // Store the record.
      final key = '${SecureStorageKeys.pairingPrefix}${record.pairingId}';
      await _storageService.writeValue(key: key, value: record.toJsonString());
      // Update the index.
      final ids = await _readPairingIds();
      ids.add(record.pairingId);
      await _writePairingIds(ids);
      return record;
    } catch (error) {
      if (error is PairingException) rethrow;
      if (error is ApiException) {
        throw PairingException(error.message, cause: error);
      }
      throw PairingException('pairing failed', cause: error);
    }
  }

  @override
  Future<void> unpair({required String pairingId}) async {
    try {
      await _apiService.deletePairing(pairingId: pairingId);
      // Remove record from storage.
      final key = '${SecureStorageKeys.pairingPrefix}$pairingId';
      await _storageService.deleteValue(key: key);
      // Update the index.
      final ids = await _readPairingIds();
      ids.remove(pairingId);
      await _writePairingIds(ids);
    } catch (error) {
      if (error is PairingException) rethrow;
      if (error is ApiException) {
        throw PairingException(error.message, cause: error);
      }
      throw PairingException('unpairing failed', cause: error);
    }
  }

  Future<List<String>> _readPairingIds() async {
    final raw = await _storageService.readValue(
      key: SecureStorageKeys.pairingIds,
    );
    if (raw == null || raw.isEmpty) return [];
    try {
      final decoded = jsonDecode(raw) as List<dynamic>;
      return decoded.cast<String>().toList();
    } on Object {
      return [];
    }
  }

  Future<void> _writePairingIds(List<String> ids) async {
    await _storageService.writeValue(
      key: SecureStorageKeys.pairingIds,
      value: jsonEncode(ids),
    );
  }
}

@Riverpod(keepAlive: true)
PairingService pairingService(Ref ref) {
  return DefaultPairingService(
    apiService: ref.read(pairingApiProvider),
    storageService: ref.read(secureStorageProvider),
  );
}
