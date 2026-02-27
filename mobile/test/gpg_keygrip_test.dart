import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:gpg_bridge_mobile/security/gpg_key_models.dart';
import 'package:gpg_bridge_mobile/security/gpg_keygrip.dart';

void main() {
  group('computeKeygrip', () {
    test('returns 40 uppercase hex characters for RSA', () {
      final params = <String, dynamic>{
        'n': BigInt.from(256),
        'e': BigInt.from(65537),
      };

      final keygrip = computeKeygrip(GpgKeyAlgorithm.rsa, params);

      expect(keygrip.length, 40);
      expect(keygrip, matches(RegExp(r'^[0-9A-F]{40}$')));
    });

    test('is deterministic for same RSA input', () {
      final params = <String, dynamic>{
        'n': BigInt.from(12345),
        'e': BigInt.from(65537),
      };

      final grip1 = computeKeygrip(GpgKeyAlgorithm.rsa, params);
      final grip2 = computeKeygrip(GpgKeyAlgorithm.rsa, params);

      expect(grip1, equals(grip2));
    });

    test('produces different output for RSA vs ECDSA inputs', () {
      final rsaParams = <String, dynamic>{
        'n': BigInt.from(12345),
        'e': BigInt.from(65537),
      };
      final ecParams = <String, dynamic>{
        'oidName': 'P-256',
        'q': Uint8List.fromList([0x04, ...List<int>.filled(64, 0x42)]),
      };

      final grip1 = computeKeygrip(GpgKeyAlgorithm.rsa, rsaParams);
      final grip2 = computeKeygrip(GpgKeyAlgorithm.ecdsa, ecParams);

      expect(grip1, isNot(equals(grip2)));
    });

    test('returns 40 uppercase hex characters for ECDSA', () {
      final q = Uint8List.fromList([0x04, ...List<int>.filled(64, 0x42)]);
      final params = <String, dynamic>{'oidName': 'P-256', 'q': q};

      final keygrip = computeKeygrip(GpgKeyAlgorithm.ecdsa, params);

      expect(keygrip.length, 40);
      expect(keygrip, matches(RegExp(r'^[0-9A-F]{40}$')));
    });

    test('computes keygrip for EdDSA', () {
      final q = Uint8List.fromList([0x40, ...List<int>.filled(32, 0xAB)]);
      final params = <String, dynamic>{'oidName': 'Ed25519', 'q': q};

      final keygrip = computeKeygrip(GpgKeyAlgorithm.eddsa, params);

      expect(keygrip.length, 40);
      expect(keygrip, matches(RegExp(r'^[0-9A-F]{40}$')));
    });

    test('computes keygrip for ECDH', () {
      final q = Uint8List.fromList([0x40, ...List<int>.filled(32, 0xCD)]);
      final params = <String, dynamic>{'oidName': 'Curve25519', 'q': q};

      final keygrip = computeKeygrip(GpgKeyAlgorithm.ecdh, params);

      expect(keygrip.length, 40);
      expect(keygrip, matches(RegExp(r'^[0-9A-F]{40}$')));
    });

    test('throws FormatException for unsupported algorithm', () {
      final params = <String, dynamic>{};

      expect(
        () => computeKeygrip(GpgKeyAlgorithm.dsa, params),
        throwsA(isA<FormatException>()),
      );
    });

    test('different algorithms produce different keygrips', () {
      final q = Uint8List.fromList([0x40, ...List<int>.filled(32, 0xAB)]);
      final eddsaParams = <String, dynamic>{'oidName': 'Ed25519', 'q': q};
      final ecdhParams = <String, dynamic>{'oidName': 'Curve25519', 'q': q};

      final grip1 = computeKeygrip(GpgKeyAlgorithm.eddsa, eddsaParams);
      final grip2 = computeKeygrip(GpgKeyAlgorithm.ecdh, ecdhParams);

      // Different curve names → different S-expression → different grip
      expect(grip1, isNot(equals(grip2)));
    });

    test('golden: pinned keygrip values for regression detection', () {
      // Deterministic inputs — if this test fails, the keygrip algorithm
      // was accidentally changed.
      final rsaParams = <String, dynamic>{
        'n': BigInt.parse(
          'B3510A2DA808523E83C8200AA3594F3B71A80C3C16B175B3B6B05B9EAF1CA7E3',
          radix: 16,
        ),
        'e': BigInt.from(65537),
      };
      final rsaGrip = computeKeygrip(GpgKeyAlgorithm.rsa, rsaParams);

      // Pin the computed value. If this assertion fails, the keygrip
      // computation was accidentally changed.
      expect(rsaGrip, hasLength(40));
      expect(rsaGrip, matches(RegExp(r'^[0-9A-F]{40}$')));
      expect(rsaGrip, equals(_goldenRsaKeygrip));

      final ecdsaParams = <String, dynamic>{
        'oidName': 'P-256',
        'q': Uint8List.fromList([0x04, ...List<int>.filled(64, 0x42)]),
      };
      final ecdsaGrip = computeKeygrip(GpgKeyAlgorithm.ecdsa, ecdsaParams);

      expect(ecdsaGrip, hasLength(40));
      expect(ecdsaGrip, matches(RegExp(r'^[0-9A-F]{40}$')));
      expect(ecdsaGrip, equals(_goldenEcdsaKeygrip));
    });
  });
}

// Golden values for regression detection. If these change, the keygrip
// algorithm was modified.
const _goldenRsaKeygrip = 'FC3D338417B54C1E22F5E906097661878FBA0523';
const _goldenEcdsaKeygrip = '2FDDDC36BE91D98D43E8BB0287F90C19880E8E85';
