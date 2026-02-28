import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:gpg_bridge_mobile/state/pairing_types.dart';

void main() {
  group('PairingException', () {
    test('toString includes message without cause', () {
      final error = PairingException('test error');

      expect(error.toString(), 'PairingException: test error');
    });

    test('toString includes message and cause', () {
      final error = PairingException('test error', cause: Exception('inner'));

      expect(error.toString(), contains('test error'));
      expect(error.toString(), contains('inner'));
    });
  });

  group('PairingRecord', () {
    test('fromJson parses valid data', () {
      final json = {
        'pairing_id': 'p-123',
        'client_id': 'c-456',
        'paired_at': '2025-06-15T10:30:00.000Z',
      };

      final record = PairingRecord.fromJson(json);

      expect(record.pairingId, 'p-123');
      expect(record.clientId, 'c-456');
      expect(record.pairedAt.year, 2025);
      expect(record.pairedAt.month, 6);
    });

    test('fromJson throws on missing pairing_id', () {
      expect(
        () => PairingRecord.fromJson({
          'client_id': 'c-456',
          'paired_at': '2025-06-15T10:30:00.000Z',
        }),
        throwsA(isA<PairingException>()),
      );
    });

    test('fromJson throws on empty pairing_id', () {
      expect(
        () => PairingRecord.fromJson({
          'pairing_id': '',
          'client_id': 'c',
          'paired_at': '2025-06-15T10:30:00.000Z',
        }),
        throwsA(isA<PairingException>()),
      );
    });

    test('fromJson throws on missing client_id', () {
      expect(
        () => PairingRecord.fromJson({
          'pairing_id': 'p',
          'paired_at': '2025-06-15T10:30:00.000Z',
        }),
        throwsA(isA<PairingException>()),
      );
    });

    test('fromJson throws on invalid paired_at', () {
      expect(
        () => PairingRecord.fromJson({
          'pairing_id': 'p',
          'client_id': 'c',
          'paired_at': 'not-a-date',
        }),
        throwsA(isA<PairingException>()),
      );
    });

    test('fromJson throws on non-string paired_at', () {
      expect(
        () => PairingRecord.fromJson({
          'pairing_id': 'p',
          'client_id': 'c',
          'paired_at': 12345,
        }),
        throwsA(isA<PairingException>()),
      );
    });

    test('toJson serializes correctly', () {
      final record = PairingRecord(
        pairingId: 'p-1',
        clientId: 'c-2',
        pairedAt: DateTime.utc(2025, 3, 1, 12, 0),
      );

      final json = record.toJson();

      expect(json['pairing_id'], 'p-1');
      expect(json['client_id'], 'c-2');
      expect(json['paired_at'], '2025-03-01T12:00:00.000Z');
    });

    test('toJsonString returns valid JSON', () {
      final record = PairingRecord(
        pairingId: 'p-1',
        clientId: 'c-2',
        pairedAt: DateTime.utc(2025, 3, 1, 12, 0),
      );

      final jsonString = record.toJsonString();
      final decoded = jsonDecode(jsonString) as Map<String, dynamic>;

      expect(decoded['pairing_id'], 'p-1');
    });

    test('roundtrip fromJson/toJson', () {
      final original = PairingRecord(
        pairingId: 'roundtrip-id',
        clientId: 'roundtrip-client',
        pairedAt: DateTime.utc(2025, 1, 15, 8, 30),
      );

      final restored = PairingRecord.fromJson(original.toJson());

      expect(restored.pairingId, original.pairingId);
      expect(restored.clientId, original.clientId);
      expect(restored.pairedAt, original.pairedAt);
    });
  });
}
