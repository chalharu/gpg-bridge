import 'package:dio/dio.dart';
import 'package:riverpod_annotation/riverpod_annotation.dart';

import 'api_exception.dart';
import 'http_client_provider.dart';

part 'public_key_api_service.g.dart';

class PublicKeyApiException implements Exception {
  PublicKeyApiException(this.message, {this.cause});

  final String message;
  final Object? cause;

  @override
  String toString() {
    if (cause == null) {
      return 'PublicKeyApiException: $message';
    }
    return 'PublicKeyApiException: $message ($cause)';
  }
}

/// Response model for GET /device/public_key.
class PublicKeyListResponse {
  PublicKeyListResponse({required this.keys, required this.defaultKid});

  factory PublicKeyListResponse.fromJson(Map<String, dynamic> json) {
    final keys = json['keys'];
    if (keys is! List) {
      throw PublicKeyApiException('invalid keys in response');
    }
    final defaultKid = json['default_kid'];
    if (defaultKid is! String || defaultKid.isEmpty) {
      throw PublicKeyApiException('invalid default_kid in response');
    }
    return PublicKeyListResponse(
      keys: keys.cast<Map<String, dynamic>>(),
      defaultKid: defaultKid,
    );
  }

  /// JWK objects.
  final List<Map<String, dynamic>> keys;
  final String defaultKid;
}

/// Abstraction for public key API endpoints.
abstract interface class PublicKeyApiService {
  /// POST /device/public_key — add public keys.
  Future<void> addPublicKeys({
    required List<Map<String, dynamic>> keys,
    String? defaultKid,
  });

  /// GET /device/public_key — list all public keys.
  Future<PublicKeyListResponse> listPublicKeys();

  /// DELETE /device/public_key/{kid} — delete a public key.
  Future<void> deletePublicKey({required String kid});
}

class DefaultPublicKeyApiService implements PublicKeyApiService {
  DefaultPublicKeyApiService({required Dio dio}) : _dio = dio;

  final Dio _dio;

  @override
  Future<void> addPublicKeys({
    required List<Map<String, dynamic>> keys,
    String? defaultKid,
  }) async {
    try {
      final body = <String, dynamic>{'keys': keys, 'default_kid': ?defaultKid};
      await _dio.post<void>('/device/public_key', data: body);
    } catch (error) {
      _rethrowOrWrap(error, 'add public keys');
    }
  }

  @override
  Future<PublicKeyListResponse> listPublicKeys() async {
    try {
      final response = await _dio.get<Map<String, dynamic>>(
        '/device/public_key',
      );
      return PublicKeyListResponse.fromJson(response.data!);
    } catch (error) {
      _rethrowOrWrap(error, 'list public keys');
    }
  }

  static final _uuidPattern = RegExp(
    r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-'
    r'[0-9a-fA-F]{12}$',
  );

  @override
  Future<void> deletePublicKey({required String kid}) async {
    if (!_uuidPattern.hasMatch(kid)) {
      throw PublicKeyApiException('invalid kid format: $kid');
    }
    try {
      await _dio.delete<void>('/device/public_key/$kid');
    } catch (error) {
      _rethrowOrWrap(error, 'delete public key');
    }
  }

  Never _rethrowOrWrap(Object error, String operation) {
    if (error is PublicKeyApiException) throw error;
    if (error is ApiException) throw error;
    throw PublicKeyApiException('failed to $operation', cause: error);
  }
}

@Riverpod(keepAlive: true)
PublicKeyApiService publicKeyApi(Ref ref) {
  return DefaultPublicKeyApiService(dio: ref.read(httpClientProvider));
}
