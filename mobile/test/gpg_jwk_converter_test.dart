import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:gpg_bridge_mobile/security/gpg_jwk_converter.dart';
import 'package:gpg_bridge_mobile/security/gpg_key_models.dart';

void main() {
  group('keyMaterialToJwk', () {
    test('converts RSA key to JWK', () {
      final params = <String, dynamic>{
        'n': BigInt.from(256), // 0x100
        'e': BigInt.from(65537), // 0x10001
      };

      final jwk = keyMaterialToJwk(GpgKeyAlgorithm.rsa, params);

      expect(jwk['kty'], 'RSA');
      // n and e are base64url-encoded without padding
      expect(jwk['n'], isA<String>());
      expect(jwk['e'], isA<String>());
      // Decode n back: 0x100 = [0x01, 0x00]
      final nBytes = base64Url.decode(_padBase64(jwk['n'] as String));
      expect(nBytes, equals([0x01, 0x00]));
      // Decode e back: 65537 = [0x01, 0x00, 0x01]
      final eBytes = base64Url.decode(_padBase64(jwk['e'] as String));
      expect(eBytes, equals([0x01, 0x00, 0x01]));
    });

    test('converts RSA Encrypt-Only to JWK', () {
      final params = <String, dynamic>{
        'n': BigInt.from(256),
        'e': BigInt.from(3),
      };

      final jwk = keyMaterialToJwk(GpgKeyAlgorithm.rsaEncryptOnly, params);

      expect(jwk['kty'], 'RSA');
    });

    test('converts RSA Sign-Only to JWK', () {
      final params = <String, dynamic>{
        'n': BigInt.from(256),
        'e': BigInt.from(3),
      };

      final jwk = keyMaterialToJwk(GpgKeyAlgorithm.rsaSignOnly, params);

      expect(jwk['kty'], 'RSA');
    });

    test('converts ECDSA P-256 to JWK', () {
      final xBytes = List<int>.filled(32, 0x11);
      final yBytes = List<int>.filled(32, 0x22);
      final q = Uint8List.fromList([0x04, ...xBytes, ...yBytes]);
      final params = <String, dynamic>{'oidName': 'P-256', 'q': q};

      final jwk = keyMaterialToJwk(GpgKeyAlgorithm.ecdsa, params);

      expect(jwk['kty'], 'EC');
      expect(jwk['crv'], 'P-256');
      expect(jwk['x'], isA<String>());
      expect(jwk['y'], isA<String>());
      // Verify x decodes to 32 bytes of 0x11
      final decodedX = base64Url.decode(_padBase64(jwk['x'] as String));
      expect(decodedX, equals(xBytes));
    });

    test('converts EdDSA Ed25519 to JWK', () {
      final rawKey = List<int>.filled(32, 0xAA);
      final q = Uint8List.fromList([0x40, ...rawKey]);
      final params = <String, dynamic>{'oidName': 'Ed25519', 'q': q};

      final jwk = keyMaterialToJwk(GpgKeyAlgorithm.eddsa, params);

      expect(jwk['kty'], 'OKP');
      expect(jwk['crv'], 'Ed25519');
      expect(jwk['x'], isA<String>());
      final decodedX = base64Url.decode(_padBase64(jwk['x'] as String));
      expect(decodedX, equals(rawKey));
    });

    test('converts ECDH Curve25519 to JWK', () {
      final rawKey = List<int>.filled(32, 0xBB);
      final q = Uint8List.fromList([0x40, ...rawKey]);
      final params = <String, dynamic>{'oidName': 'Curve25519', 'q': q};

      final jwk = keyMaterialToJwk(GpgKeyAlgorithm.ecdh, params);

      expect(jwk['kty'], 'OKP');
      expect(jwk['crv'], 'X25519');
      expect(jwk['x'], isA<String>());
      final decodedX = base64Url.decode(_padBase64(jwk['x'] as String));
      expect(decodedX, equals(rawKey));
    });

    test('throws FormatException for invalid EC point (no 0x04 prefix)', () {
      // Invalid: no 0x04 uncompressed prefix
      final q = Uint8List.fromList([0x02, ...List<int>.filled(64, 0x11)]);
      final params = <String, dynamic>{'oidName': 'P-256', 'q': q};

      expect(
        () => keyMaterialToJwk(GpgKeyAlgorithm.ecdsa, params),
        throwsA(isA<FormatException>()),
      );
    });

    test('throws FormatException for unsupported EC curve', () {
      final q = Uint8List.fromList([0x04, ...List<int>.filled(64, 0x11)]);
      final params = <String, dynamic>{'oidName': 'Brainpool-256', 'q': q};

      expect(
        () => keyMaterialToJwk(GpgKeyAlgorithm.ecdsa, params),
        throwsA(isA<FormatException>()),
      );
    });

    test('throws FormatException for unsupported algorithm', () {
      final params = <String, dynamic>{};

      expect(
        () => keyMaterialToJwk(GpgKeyAlgorithm.dsa, params),
        throwsA(isA<FormatException>()),
      );
    });

    test('throws FormatException for unsupported EdDSA curve', () {
      final q = Uint8List.fromList([0x40, ...List<int>.filled(32, 0x01)]);
      final params = <String, dynamic>{'oidName': 'Ed448', 'q': q};

      expect(
        () => keyMaterialToJwk(GpgKeyAlgorithm.eddsa, params),
        throwsA(isA<FormatException>()),
      );
    });

    test('ECDH with NIST curve uses EC JWK format', () {
      final xBytes = List<int>.filled(32, 0x33);
      final yBytes = List<int>.filled(32, 0x44);
      final q = Uint8List.fromList([0x04, ...xBytes, ...yBytes]);
      final params = <String, dynamic>{'oidName': 'P-256', 'q': q};

      final jwk = keyMaterialToJwk(GpgKeyAlgorithm.ecdh, params);

      expect(jwk['kty'], 'EC');
      expect(jwk['crv'], 'P-256');
    });
  });

  group('computeKeyId', () {
    test('returns 16 uppercase hex characters', () {
      // Minimal V4 key packet body
      final body = Uint8List.fromList([
        0x04, // version 4
        0x00, 0x00, 0x00, 0x00, // creation time
        0x01, // RSA
        0x00, 0x09, 0x01, 0x00, // MPI n
        0x00, 0x11, 0x01, 0x00, 0x01, // MPI e
      ]);

      final keyId = computeKeyId(body);

      expect(keyId.length, 16);
      expect(keyId, matches(RegExp(r'^[0-9A-F]{16}$')));
    });

    test('is deterministic', () {
      final body = Uint8List.fromList([
        0x04,
        0x00,
        0x00,
        0x00,
        0x00,
        0x01,
        0x00,
        0x09,
        0x01,
        0x00,
        0x00,
        0x11,
        0x01,
        0x00,
        0x01,
      ]);

      expect(computeKeyId(body), equals(computeKeyId(body)));
    });

    test('different bodies produce different key IDs', () {
      final body1 = Uint8List.fromList([
        0x04,
        0x00,
        0x00,
        0x00,
        0x00,
        0x01,
        0x00,
        0x09,
        0x01,
        0x00,
        0x00,
        0x11,
        0x01,
        0x00,
        0x01,
      ]);
      final body2 = Uint8List.fromList([
        0x04,
        0x00,
        0x00,
        0x00,
        0x01,
        0x01,
        0x00,
        0x09,
        0x01,
        0x00,
        0x00,
        0x11,
        0x01,
        0x00,
        0x01,
      ]);

      expect(computeKeyId(body1), isNot(equals(computeKeyId(body2))));
    });
  });
}

/// Pads base64url string to valid length for decoding.
String _padBase64(String s) {
  switch (s.length % 4) {
    case 2:
      return '$s==';
    case 3:
      return '$s=';
    default:
      return s;
  }
}
