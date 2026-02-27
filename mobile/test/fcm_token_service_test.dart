import 'dart:async';

import 'package:flutter_test/flutter_test.dart';
import 'package:gpg_bridge_mobile/fcm/fcm_token_service.dart';

void main() {
  group('FcmException', () {
    test('toString includes message without cause', () {
      final error = FcmException('token failed');

      expect(error.toString(), 'FcmException: token failed');
    });

    test('toString includes message and cause', () {
      final error = FcmException('token failed', cause: Exception('boom'));

      expect(error.toString(), contains('token failed'));
      expect(error.toString(), contains('boom'));
    });
  });

  group('FcmTokenProvider (mock)', () {
    test('getToken returns token from mock', () async {
      final provider = _MockFcmTokenProvider(token: 'fcm-test-token');

      final token = await provider.getToken();

      expect(token, 'fcm-test-token');
    });

    test('getToken throws FcmException when token is null', () async {
      final provider = _MockFcmTokenProvider(token: null);

      expect(() => provider.getToken(), throwsA(isA<FcmException>()));
    });

    test('onTokenRefresh emits new tokens', () async {
      final controller = StreamController<String>.broadcast();
      final provider = _MockFcmTokenProvider(
        token: 'initial',
        refreshStream: controller.stream,
      );

      final tokens = <String>[];
      final subscription = provider.onTokenRefresh.listen(tokens.add);

      controller.add('refresh-1');
      controller.add('refresh-2');

      // Allow micro-tasks to process.
      await Future<void>.delayed(Duration.zero);

      expect(tokens, ['refresh-1', 'refresh-2']);

      await subscription.cancel();
      await controller.close();
    });
  });
}

/// Minimal mock implementation for testing consumers of [FcmTokenService].
class _MockFcmTokenProvider implements FcmTokenService {
  _MockFcmTokenProvider({required this.token, Stream<String>? refreshStream})
    : _refreshStream = refreshStream ?? const Stream<String>.empty();

  final String? token;
  final Stream<String> _refreshStream;

  @override
  Future<String> getToken() async {
    if (token == null || token!.isEmpty) {
      throw FcmException('FCM token is null or empty');
    }
    return token!;
  }

  @override
  Stream<String> get onTokenRefresh => _refreshStream;
}
