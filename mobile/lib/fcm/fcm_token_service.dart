import 'dart:async';

import 'package:firebase_messaging/firebase_messaging.dart';
import 'package:riverpod_annotation/riverpod_annotation.dart';

part 'fcm_token_service.g.dart';

class FcmException implements Exception {
  FcmException(this.message, {this.cause});

  final String message;
  final Object? cause;

  @override
  String toString() {
    if (cause == null) {
      return 'FcmException: $message';
    }
    return 'FcmException: $message ($cause)';
  }
}

/// Abstraction over Firebase Cloud Messaging token management.
abstract interface class FcmTokenService {
  /// Returns the current FCM registration token.
  Future<String> getToken();

  /// Stream that emits new tokens whenever FCM refreshes the token.
  Stream<String> get onTokenRefresh;
}

/// Production implementation backed by [FirebaseMessaging].
class FirebaseFcmTokenService implements FcmTokenService {
  FirebaseFcmTokenService([FirebaseMessaging? messaging])
    : _messaging = messaging ?? FirebaseMessaging.instance;

  final FirebaseMessaging _messaging;

  @override
  Future<String> getToken() async {
    try {
      final token = await _messaging.getToken();
      if (token == null || token.isEmpty) {
        throw FcmException('FCM token is null or empty');
      }
      return token;
    } catch (error) {
      if (error is FcmException) rethrow;
      throw FcmException('failed to get FCM token', cause: error);
    }
  }

  @override
  Stream<String> get onTokenRefresh => _messaging.onTokenRefresh;
}

@Riverpod(keepAlive: true)
FcmTokenService fcmToken(Ref ref) {
  return FirebaseFcmTokenService();
}
