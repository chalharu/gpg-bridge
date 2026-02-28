import 'package:flutter_test/flutter_test.dart';
import 'package:gpg_bridge_mobile/fcm/fcm_message_handler.dart';

void main() {
  group('parseFcmData', () {
    test('parses sign_request message', () {
      final result = parseFcmData({
        'type': 'sign_request',
        'request_id': 'abc-123',
      });

      expect(result, isNotNull);
      expect(result!.type, FcmMessageType.signRequest);
      expect(result.requestId, 'abc-123');
    });

    test('returns null for sign_request without request_id', () {
      final result = parseFcmData({'type': 'sign_request'});

      expect(result, isNull);
    });

    test('returns null for sign_request with empty request_id', () {
      final result = parseFcmData({'type': 'sign_request', 'request_id': ''});

      expect(result, isNull);
    });

    test('parses sign_request_cancelled message', () {
      final result = parseFcmData({
        'type': 'sign_request_cancelled',
        'request_id': 'abc-456',
      });

      expect(result, isNotNull);
      expect(result!.type, FcmMessageType.signRequestCancelled);
      expect(result.requestId, 'abc-456');
    });

    test('parses sign_request_cancelled without request_id', () {
      final result = parseFcmData({'type': 'sign_request_cancelled'});

      expect(result, isNotNull);
      expect(result!.type, FcmMessageType.signRequestCancelled);
      expect(result.requestId, isNull);
    });

    test('returns null for unknown type', () {
      final result = parseFcmData({'type': 'other'});

      expect(result, isNull);
    });

    test('returns null for missing type', () {
      final result = parseFcmData({'request_id': 'abc-123'});

      expect(result, isNull);
    });

    test('returns null for empty data', () {
      final result = parseFcmData({});

      expect(result, isNull);
    });

    test('ignores extra fields in data', () {
      final result = parseFcmData({
        'type': 'sign_request',
        'request_id': 'extra-1',
        'unexpected_field': 42,
        'nested': {'a': 'b'},
      });

      expect(result, isNotNull);
      expect(result!.type, FcmMessageType.signRequest);
      expect(result.requestId, 'extra-1');
    });

    test('returns null for numeric type value', () {
      final result = parseFcmData({'type': 123});

      expect(result, isNull);
    });

    test('returns null for null type value', () {
      final result = parseFcmData({'type': null});

      expect(result, isNull);
    });
  });

  group('FcmDataMessage', () {
    test('holds type and requestId', () {
      final msg = FcmDataMessage(
        type: FcmMessageType.signRequest,
        requestId: 'req-1',
      );

      expect(msg.type, FcmMessageType.signRequest);
      expect(msg.requestId, 'req-1');
    });

    test('requestId can be null', () {
      final msg = FcmDataMessage(type: FcmMessageType.signRequestCancelled);

      expect(msg.requestId, isNull);
    });
  });
}
