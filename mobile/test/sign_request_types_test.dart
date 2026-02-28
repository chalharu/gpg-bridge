import 'package:flutter_test/flutter_test.dart';
import 'package:gpg_bridge_mobile/http/sign_request_api_service.dart';
import 'package:gpg_bridge_mobile/security/ec_jwk.dart';
import 'package:gpg_bridge_mobile/state/sign_request_types.dart';

void main() {
  group('SignRequestException', () {
    test('toString includes message without cause', () {
      final error = SignRequestException('failed');

      expect(error.toString(), 'SignRequestException: failed');
    });

    test('toString includes message and cause', () {
      final error = SignRequestException('failed', cause: Exception('inner'));

      expect(error.toString(), contains('failed'));
      expect(error.toString(), contains('inner'));
    });
  });

  group('SignResultStatus', () {
    test('values map to correct strings', () {
      expect(SignResultStatus.approved.value, 'approved');
      expect(SignResultStatus.denied.value, 'denied');
      expect(SignResultStatus.unavailable.value, 'unavailable');
    });
  });

  group('DecryptedSignRequest', () {
    DecryptedSignRequest createRequest({DateTime? receivedAt}) {
      final detail = SignRequestDetail(
        requestId: 'req-1',
        signJwt: 'jwt',
        encryptedPayload: 'a.b.c.d.e',
        pairingId: 'pair-1',
        daemonEncPublicKey: EcPublicJwk(
          x: 'dGVzdHgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
          y: 'dGVzdHkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        ),
      );

      if (receivedAt != null) {
        return DecryptedSignRequest(
          requestId: detail.requestId,
          signJwt: detail.signJwt,
          hash: 'dGVzdCBoYXNoIHZhbHVl',
          hashAlgorithm: 'sha256',
          keyId: '0xABCD1234',
          pairingId: detail.pairingId,
          daemonEncPublicKey: detail.daemonEncPublicKey,
          receivedAt: receivedAt,
        );
      }

      return DecryptedSignRequest.fromDetail(
        detail: detail,
        hash: 'dGVzdCBoYXNoIHZhbHVl',
        hashAlgorithm: 'sha256',
        keyId: '0xABCD1234',
      );
    }

    test('fromDetail creates instance with all fields', () {
      final request = createRequest();

      expect(request.requestId, 'req-1');
      expect(request.signJwt, 'jwt');
      expect(request.hash, 'dGVzdCBoYXNoIHZhbHVl');
      expect(request.hashAlgorithm, 'sha256');
      expect(request.keyId, '0xABCD1234');
      expect(request.pairingId, 'pair-1');
    });

    test('expiresAt is 5 minutes after receivedAt', () {
      final now = DateTime.now();
      final request = createRequest(receivedAt: now);

      expect(request.expiresAt, now.add(const Duration(minutes: 5)));
    });

    test('isExpired returns false for fresh request', () {
      final request = createRequest();

      expect(request.isExpired, isFalse);
    });

    test('isExpired returns true for old request', () {
      final past = DateTime.now().subtract(const Duration(minutes: 6));
      final request = createRequest(receivedAt: past);

      expect(request.isExpired, isTrue);
    });
  });
}
