import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:gpg_bridge_mobile/http/device_jwt_checker.dart';

void main() {
  group('DeviceJwtChecker', () {
    group('parseExpiry', () {
      test('returns correct JwtExpiry for valid JWT', () {
        final jwt = _buildJwt(iat: 1000, exp: 2000);
        final result = DeviceJwtChecker.parseExpiry(jwt);

        expect(result, isNotNull);
        expect(result!.issuedAt, 1000);
        expect(result.expiresAt, 2000);
      });

      test('returns null for non-3-part JWT', () {
        expect(DeviceJwtChecker.parseExpiry('abc.def'), isNull);
        expect(DeviceJwtChecker.parseExpiry('single'), isNull);
        expect(DeviceJwtChecker.parseExpiry('a.b.c.d'), isNull);
      });

      test('returns null when iat is missing', () {
        final jwt = _buildJwtFromPayload({'exp': 2000, 'sub': 'x'});
        expect(DeviceJwtChecker.parseExpiry(jwt), isNull);
      });

      test('returns null when exp is missing', () {
        final jwt = _buildJwtFromPayload({'iat': 1000, 'sub': 'x'});
        expect(DeviceJwtChecker.parseExpiry(jwt), isNull);
      });

      test('returns null for invalid base64 payload', () {
        expect(DeviceJwtChecker.parseExpiry('a.!!!.c'), isNull);
      });

      test('returns null for non-JSON payload', () {
        final payload = base64Url.encode(utf8.encode('not-json'));
        expect(DeviceJwtChecker.parseExpiry('h.$payload.s'), isNull);
      });

      test('returns null when iat is not int', () {
        final jwt = _buildJwtFromPayload({'iat': '1000', 'exp': 2000});
        expect(DeviceJwtChecker.parseExpiry(jwt), isNull);
      });

      test('returns null when exp is not int', () {
        final jwt = _buildJwtFromPayload({'iat': 1000, 'exp': 'bad'});
        expect(DeviceJwtChecker.parseExpiry(jwt), isNull);
      });
    });

    group('needsRefresh', () {
      test('returns true when remaining < 1/3 of total', () {
        final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
        // totalValidity = 7200, remaining = 100 → 100 < 2400
        final jwt = _buildJwt(iat: now - 7100, exp: now + 100);
        expect(DeviceJwtChecker.needsRefresh(jwt), isTrue);
      });

      test('returns false when remaining >= 1/3 of total', () {
        final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
        // totalValidity = 7200, remaining = 6000 → 6000 >= 2400
        final jwt = _buildJwt(iat: now - 1200, exp: now + 6000);
        expect(DeviceJwtChecker.needsRefresh(jwt), isFalse);
      });

      test('returns false when JWT is expired', () {
        final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
        final jwt = _buildJwt(iat: now - 7200, exp: now - 100);
        expect(DeviceJwtChecker.needsRefresh(jwt), isFalse);
      });

      test('returns false for malformed JWT', () {
        expect(DeviceJwtChecker.needsRefresh('invalid'), isFalse);
      });
    });

    group('isExpired', () {
      test('returns true when exp has passed', () {
        final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
        final jwt = _buildJwt(iat: now - 7200, exp: now - 1);
        expect(DeviceJwtChecker.isExpired(jwt), isTrue);
      });

      test('returns false when still valid', () {
        final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
        final jwt = _buildJwt(iat: now - 100, exp: now + 3600);
        expect(DeviceJwtChecker.isExpired(jwt), isFalse);
      });

      test('returns true for malformed JWT', () {
        expect(DeviceJwtChecker.isExpired('bad.data'), isTrue);
      });

      test('returns true when exp equals now', () {
        final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
        final jwt = _buildJwt(iat: now - 7200, exp: now);
        expect(DeviceJwtChecker.isExpired(jwt), isTrue);
      });
    });
  });
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

String _buildJwt({required int iat, required int exp}) {
  return _buildJwtFromPayload({'iat': iat, 'exp': exp, 'sub': 'test'});
}

String _buildJwtFromPayload(Map<String, dynamic> payload) {
  final header = base64Url
      .encode(utf8.encode(jsonEncode({'alg': 'ES256', 'typ': 'JWT'})))
      .replaceAll('=', '');
  final payloadPart = base64Url
      .encode(utf8.encode(jsonEncode(payload)))
      .replaceAll('=', '');
  return '$header.$payloadPart.fake-sig';
}
