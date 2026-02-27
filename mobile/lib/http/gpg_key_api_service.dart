import 'package:dio/dio.dart';
import 'package:riverpod_annotation/riverpod_annotation.dart';

import 'api_exception.dart';
import 'http_client_provider.dart';

part 'gpg_key_api_service.g.dart';

class GpgKeyApiException implements Exception {
  GpgKeyApiException(this.message, {this.cause});

  final String message;
  final Object? cause;

  @override
  String toString() {
    if (cause == null) {
      return 'GpgKeyApiException: $message';
    }
    return 'GpgKeyApiException: $message ($cause)';
  }
}

/// A single GPG key entry as returned/sent by the API.
class GpgKeyEntry {
  GpgKeyEntry({
    required this.keygrip,
    required this.keyId,
    required this.publicKey,
  });

  factory GpgKeyEntry.fromJson(Map<String, dynamic> json) {
    final keygrip = json['keygrip'];
    if (keygrip is! String || keygrip.isEmpty) {
      throw GpgKeyApiException('invalid keygrip in response');
    }
    final keyId = json['key_id'];
    if (keyId is! String || keyId.isEmpty) {
      throw GpgKeyApiException('invalid key_id in response');
    }
    final publicKey = json['public_key'];
    if (publicKey is! Map<String, dynamic>) {
      throw GpgKeyApiException('invalid public_key in response');
    }
    return GpgKeyEntry(keygrip: keygrip, keyId: keyId, publicKey: publicKey);
  }

  /// 40-character hex keygrip.
  final String keygrip;

  /// Hex key ID.
  final String keyId;

  /// JWK representation of the public key.
  final Map<String, dynamic> publicKey;

  Map<String, dynamic> toJson() => {
    'keygrip': keygrip,
    'key_id': keyId,
    'public_key': publicKey,
  };
}

/// Response model for GET /device/gpg_key.
class GpgKeyListResponse {
  GpgKeyListResponse({required this.gpgKeys});

  factory GpgKeyListResponse.fromJson(Map<String, dynamic> json) {
    final gpgKeys = json['gpg_keys'];
    if (gpgKeys is! List) {
      throw GpgKeyApiException('invalid gpg_keys in response');
    }
    return GpgKeyListResponse(
      gpgKeys: gpgKeys
          .cast<Map<String, dynamic>>()
          .map(GpgKeyEntry.fromJson)
          .toList(),
    );
  }

  final List<GpgKeyEntry> gpgKeys;
}

/// Abstraction for GPG key API endpoints.
abstract interface class GpgKeyApiService {
  /// POST /device/gpg_key — register GPG keys.
  Future<void> registerGpgKeys({required List<GpgKeyEntry> gpgKeys});

  /// GET /device/gpg_key — list all registered GPG keys.
  Future<GpgKeyListResponse> listGpgKeys();

  /// DELETE /device/gpg_key/{keygrip} — delete a GPG key.
  Future<void> deleteGpgKey({required String keygrip});
}

class DefaultGpgKeyApiService implements GpgKeyApiService {
  DefaultGpgKeyApiService({required Dio dio}) : _dio = dio;

  final Dio _dio;

  @override
  Future<void> registerGpgKeys({required List<GpgKeyEntry> gpgKeys}) async {
    try {
      final body = <String, dynamic>{
        'gpg_keys': gpgKeys.map((e) => e.toJson()).toList(),
      };
      await _dio.post<void>('/device/gpg_key', data: body);
    } catch (error) {
      _rethrowOrWrap(error, 'register GPG keys');
    }
  }

  @override
  Future<GpgKeyListResponse> listGpgKeys() async {
    try {
      final response = await _dio.get<Map<String, dynamic>>('/device/gpg_key');
      return GpgKeyListResponse.fromJson(response.data!);
    } catch (error) {
      _rethrowOrWrap(error, 'list GPG keys');
    }
  }

  static final _keygripPattern = RegExp(r'^[0-9a-fA-F]{40}$');

  @override
  Future<void> deleteGpgKey({required String keygrip}) async {
    if (!_keygripPattern.hasMatch(keygrip)) {
      throw GpgKeyApiException('invalid keygrip format: $keygrip');
    }
    try {
      await _dio.delete<void>('/device/gpg_key/$keygrip');
    } catch (error) {
      _rethrowOrWrap(error, 'delete GPG key');
    }
  }

  Never _rethrowOrWrap(Object error, String operation) {
    if (error is GpgKeyApiException) throw error;
    if (error is ApiException) throw error;
    throw GpgKeyApiException('failed to $operation', cause: error);
  }
}

@Riverpod(keepAlive: true)
GpgKeyApiService gpgKeyApi(Ref ref) {
  return DefaultGpgKeyApiService(dio: ref.read(httpClientProvider));
}
