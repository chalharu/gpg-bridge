import 'package:dio/dio.dart';
import 'package:riverpod_annotation/riverpod_annotation.dart';

import '../security/ec_jwk.dart';
import 'api_exception.dart';
import 'auth_interceptor.dart';
import 'http_client_provider.dart';

part 'sign_request_api_service.g.dart';

class SignRequestApiException implements Exception {
  SignRequestApiException(this.message, {this.cause});

  final String message;
  final Object? cause;

  @override
  String toString() {
    if (cause == null) return 'SignRequestApiException: $message';
    return 'SignRequestApiException: $message ($cause)';
  }
}

/// A single pending sign request from the server.
class SignRequestDetail {
  SignRequestDetail({
    required this.requestId,
    required this.signJwt,
    required this.encryptedPayload,
    required this.pairingId,
    required this.daemonEncPublicKey,
  });

  factory SignRequestDetail.fromJson(Map<String, dynamic> json) {
    final requestId = json['request_id'];
    if (requestId is! String || requestId.isEmpty) {
      throw SignRequestApiException('invalid request_id in response');
    }
    final signJwt = json['sign_jwt'];
    if (signJwt is! String || signJwt.isEmpty) {
      throw SignRequestApiException('invalid sign_jwt in response');
    }
    final encryptedPayload = json['encrypted_payload'];
    if (encryptedPayload is! String || encryptedPayload.isEmpty) {
      throw SignRequestApiException('invalid encrypted_payload in response');
    }
    final pairingId = json['pairing_id'];
    if (pairingId is! String || pairingId.isEmpty) {
      throw SignRequestApiException('invalid pairing_id in response');
    }
    final daemonEncKey = json['daemon_enc_public_key'];
    if (daemonEncKey is! Map<String, dynamic>) {
      throw SignRequestApiException(
        'invalid daemon_enc_public_key in response',
      );
    }
    return SignRequestDetail(
      requestId: requestId,
      signJwt: signJwt,
      encryptedPayload: encryptedPayload,
      pairingId: pairingId,
      daemonEncPublicKey: EcPublicJwk.fromJson(daemonEncKey),
    );
  }

  final String requestId;
  final String signJwt;
  final String encryptedPayload;
  final String pairingId;
  final EcPublicJwk daemonEncPublicKey;
}

/// Response from GET /sign-request.
class SignRequestListResponse {
  SignRequestListResponse({required this.requests});

  factory SignRequestListResponse.fromJson(Map<String, dynamic> json) {
    final requests = json['requests'];
    if (requests is! List) {
      throw SignRequestApiException('invalid requests in response');
    }
    return SignRequestListResponse(
      requests: requests
          .cast<Map<String, dynamic>>()
          .map(SignRequestDetail.fromJson)
          .toList(),
    );
  }

  final List<SignRequestDetail> requests;
}

/// Abstraction for sign-request / sign-result API endpoints.
abstract interface class SignRequestApiService {
  /// GET /sign-request — fetch pending sign requests (device_assertion_jwt).
  Future<SignRequestListResponse> getSignRequests();

  /// POST /sign-result — submit approval/denial/unavailable (sign_jwt auth).
  Future<void> postSignResult({
    required String signJwt,
    required String status,
    String? signature,
  });
}

class DefaultSignRequestApiService implements SignRequestApiService {
  DefaultSignRequestApiService({required Dio dio}) : _dio = dio;

  final Dio _dio;

  @override
  Future<SignRequestListResponse> getSignRequests() async {
    try {
      final response = await _dio.get<Map<String, dynamic>>('/sign-request');
      return SignRequestListResponse.fromJson(response.data!);
    } catch (error) {
      _rethrowOrWrap(error, 'get sign requests');
    }
  }

  @override
  Future<void> postSignResult({
    required String signJwt,
    required String status,
    String? signature,
  }) async {
    try {
      final body = <String, dynamic>{'status': status, 'signature': ?signature};
      await _dio.post<void>(
        '/sign-result',
        data: body,
        options: Options(
          extra: {skipAuthExtraKey: true},
          headers: {'Authorization': 'Bearer $signJwt'},
        ),
      );
    } catch (error) {
      _rethrowOrWrap(error, 'post sign result');
    }
  }

  Never _rethrowOrWrap(Object error, String operation) {
    if (error is SignRequestApiException) throw error;
    if (error is ApiException) throw error;
    throw SignRequestApiException('failed to $operation', cause: error);
  }
}

@Riverpod(keepAlive: true)
SignRequestApiService signRequestApi(Ref ref) {
  return DefaultSignRequestApiService(dio: ref.read(httpClientProvider));
}
