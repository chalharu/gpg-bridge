// Types used by the pairing service.

import 'dart:convert';

/// A single pairing record stored locally.
class PairingRecord {
  PairingRecord({
    required this.pairingId,
    required this.clientId,
    required this.pairedAt,
  });

  factory PairingRecord.fromJson(Map<String, dynamic> json) {
    final pairingId = json['pairing_id'];
    if (pairingId is! String || pairingId.isEmpty) {
      throw PairingException('invalid pairing_id in stored record');
    }
    final clientId = json['client_id'];
    if (clientId is! String || clientId.isEmpty) {
      throw PairingException('invalid client_id in stored record');
    }
    final pairedAtStr = json['paired_at'];
    if (pairedAtStr is! String) {
      throw PairingException('invalid paired_at in stored record');
    }
    final pairedAt = DateTime.tryParse(pairedAtStr);
    if (pairedAt == null) {
      throw PairingException('unparseable paired_at: $pairedAtStr');
    }
    return PairingRecord(
      pairingId: pairingId,
      clientId: clientId,
      pairedAt: pairedAt,
    );
  }

  final String pairingId;
  final String clientId;
  final DateTime pairedAt;

  Map<String, dynamic> toJson() => {
    'pairing_id': pairingId,
    'client_id': clientId,
    'paired_at': pairedAt.toIso8601String(),
  };

  String toJsonString() => jsonEncode(toJson());
}

/// Exception thrown by [PairingService] operations.
class PairingException implements Exception {
  PairingException(this.message, {this.cause});

  final String message;
  final Object? cause;

  @override
  String toString() {
    if (cause == null) return 'PairingException: $message';
    return 'PairingException: $message ($cause)';
  }
}

/// Orchestrates pairing and unpairing flows.
abstract interface class PairingService {
  Future<List<PairingRecord>> loadPairings();
  Future<PairingRecord> pair({required String pairingJwt});
  Future<void> unpair({required String pairingId});
}
