import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:gpg_bridge_mobile/security/crypto_utils.dart';
import 'package:gpg_bridge_mobile/security/device_assertion_jwt_service.dart';
import 'package:gpg_bridge_mobile/security/keystore_platform_service.dart';

void main() {
  group('DeviceAssertionJwtException', () {
    test('toString includes message without cause', () {
      final error = DeviceAssertionJwtException('jwt failed');

      expect(error.toString(), 'DeviceAssertionJwtException: jwt failed');
    });

    test('toString includes message and cause', () {
      final error = DeviceAssertionJwtException(
        'jwt failed',
        cause: Exception('key error'),
      );

      expect(error.toString(), contains('jwt failed'));
      expect(error.toString(), contains('key error'));
    });
  });

  group('DefaultDeviceAssertionJwtService', () {
    late _MockKeystorePlatformService mockKeystore;
    late _FixedJwtClock clock;
    late DefaultDeviceAssertionJwtService service;

    setUp(() {
      // The mock returns base64-encoded 64-byte R||S signature.
      mockKeystore = _MockKeystorePlatformService();
      clock = _FixedJwtClock(
        fixedNow: DateTime.utc(2026, 1, 15, 12, 0, 0),
        fixedJti: 'test-jti-uuid',
      );
      service = DefaultDeviceAssertionJwtService(
        keystoreService: mockKeystore,
        clock: clock,
      );
    });

    test('generates a valid JWT with three dot-separated parts', () async {
      final jwt = await service.generate(
        firebaseInstallationId: 'test-fid',
        audience: 'https://api.example.com',
        kid: 'test-kid-uuid',
      );

      final parts = jwt.split('.');
      expect(parts.length, 3, reason: 'JWT must have 3 parts');
    });

    test('header contains alg ES256 and typ JWT', () async {
      final jwt = await service.generate(
        firebaseInstallationId: 'test-fid',
        audience: 'https://api.example.com',
        kid: 'test-kid-uuid',
      );

      final header = _decodeJwtPart(jwt.split('.')[0]);

      expect(header['alg'], 'ES256');
      expect(header['typ'], 'JWT');
      expect(header['kid'], 'test-kid-uuid');
    });

    test('payload contains correct claims', () async {
      final jwt = await service.generate(
        firebaseInstallationId: 'test-fid',
        audience: 'https://api.example.com',
        kid: 'test-kid-uuid',
      );

      final payload = _decodeJwtPart(jwt.split('.')[1]);

      expect(payload['iss'], 'test-fid');
      expect(payload['sub'], 'test-fid');
      expect(payload['aud'], 'https://api.example.com');
      expect(payload['jti'], 'test-jti-uuid');

      final iat = payload['iat'] as int;
      final exp = payload['exp'] as int;
      expect(exp - iat, 60, reason: 'exp should be iat + 60 seconds');

      // Verify iat matches our fixed clock.
      final expectedIat =
          DateTime.utc(2026, 1, 15, 12, 0, 0).millisecondsSinceEpoch ~/ 1000;
      expect(iat, expectedIat);
    });

    test('signature is base64url-encoded', () async {
      final jwt = await service.generate(
        firebaseInstallationId: 'test-fid',
        audience: 'https://api.example.com',
        kid: 'test-kid-uuid',
      );

      final signaturePart = jwt.split('.')[2];

      // Should be valid base64url (no padding, no + or /).
      expect(signaturePart, isNot(contains('+')));
      expect(signaturePart, isNot(contains('/')));
      expect(signaturePart, isNot(contains('=')));

      // Should decode to 64 bytes (R||S for P-256).
      final signatureBytes = base64UrlDecode(signaturePart);
      expect(signatureBytes.length, 64);
    });

    test('signing input is passed to keystore', () async {
      await service.generate(
        firebaseInstallationId: 'test-fid',
        audience: 'https://api.example.com',
        kid: 'test-kid-uuid',
      );

      expect(mockKeystore.lastSignAlias, KeystoreAliases.deviceKey);
      expect(mockKeystore.lastSignData, isNotNull);

      // The signing input should be "header.payload" in utf8 bytes.
      final signingInput = utf8.decode(mockKeystore.lastSignData!);
      expect(signingInput.split('.').length, 2);
    });

    test('wraps keystore errors in DeviceAssertionJwtException', () async {
      final failingKeystore = _MockKeystorePlatformService(shouldFail: true);
      final failingService = DefaultDeviceAssertionJwtService(
        keystoreService: failingKeystore,
        clock: clock,
      );

      expect(
        () => failingService.generate(
          firebaseInstallationId: 'test-fid',
          audience: 'https://api.example.com',
          kid: 'test-kid-uuid',
        ),
        throwsA(isA<DeviceAssertionJwtException>()),
      );
    });
  });

  group('DefaultJwtClock', () {
    test('now returns UTC time', () {
      const clock = DefaultJwtClock();
      final now = clock.now();

      expect(now.isUtc, isTrue);
    });

    test('generateJti returns non-empty string', () {
      const clock = DefaultJwtClock();
      final jti = clock.generateJti();

      expect(jti, isNotEmpty);
    });

    test('generateJti returns unique values', () {
      const clock = DefaultJwtClock();

      final jti1 = clock.generateJti();
      final jti2 = clock.generateJti();

      expect(jti1, isNot(equals(jti2)));
    });
  });
}

Map<String, dynamic> _decodeJwtPart(String part) {
  return base64UrlDecodeJson(part);
}

class _FixedJwtClock implements JwtClock {
  _FixedJwtClock({required this.fixedNow, required this.fixedJti});

  final DateTime fixedNow;
  final String fixedJti;

  @override
  DateTime now() => fixedNow;

  @override
  String generateJti() => fixedJti;
}

class _MockKeystorePlatformService implements KeystorePlatformService {
  _MockKeystorePlatformService({this.shouldFail = false});

  final bool shouldFail;
  String? lastSignAlias;
  List<int>? lastSignData;

  // Return a fake 64-byte R||S signature as standard base64.
  static final String _fakeSignature = base64Encode(List.filled(64, 0xAB));

  @override
  Future<void> generateKeyPair({required String alias}) async {
    if (shouldFail) throw KeystorePlatformException('mock failure');
  }

  @override
  Future<String> sign({required String alias, required List<int> data}) async {
    if (shouldFail) throw KeystorePlatformException('mock sign failure');
    lastSignAlias = alias;
    lastSignData = data;
    return _fakeSignature;
  }

  @override
  Future<bool> verify({
    required String alias,
    required List<int> data,
    required String signatureBase64,
  }) async {
    return true;
  }

  @override
  Future<Map<String, String>> getPublicKeyJwk({required String alias}) async {
    if (shouldFail) throw KeystorePlatformException('mock jwk failure');
    final use = alias == KeystoreAliases.deviceKey ? 'sig' : 'enc';
    final alg = alias == KeystoreAliases.deviceKey ? 'ES256' : 'ECDH-ES+A256KW';
    return {
      'kty': 'EC',
      'crv': 'P-256',
      'use': use,
      'alg': alg,
      'x': base64UrlEncode(List.filled(32, 0x01)),
      'y': base64UrlEncode(List.filled(32, 0x02)),
    };
  }
}
