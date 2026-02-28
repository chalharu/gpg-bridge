import 'package:dio/dio.dart';
import 'package:riverpod_annotation/riverpod_annotation.dart';

import 'api_exception.dart';
import 'http_client_provider.dart';

part 'pairing_api_service.g.dart';

class PairingApiException implements Exception {
  PairingApiException(this.message, {this.cause});

  final String message;
  final Object? cause;

  @override
  String toString() {
    if (cause == null) {
      return 'PairingApiException: $message';
    }
    return 'PairingApiException: $message ($cause)';
  }
}

/// Response from POST /pairing.
class PairingResponse {
  PairingResponse({required this.clientId, required this.pairingId});

  factory PairingResponse.fromJson(Map<String, dynamic> json) {
    final clientId = json['client_id'];
    if (clientId is! String || clientId.isEmpty) {
      throw PairingApiException('invalid client_id in response');
    }
    final pairingId = json['pairing_id'];
    if (pairingId is! String || pairingId.isEmpty) {
      throw PairingApiException('invalid pairing_id in response');
    }
    return PairingResponse(clientId: clientId, pairingId: pairingId);
  }

  final String clientId;
  final String pairingId;
}

/// Abstraction for pairing API endpoints.
abstract interface class PairingApiService {
  /// POST /pairing — create a new pairing (device_assertion_jwt auth).
  Future<PairingResponse> createPairing({required String pairingJwt});

  /// DELETE /pairing/{pairing_id} — remove a pairing.
  Future<void> deletePairing({required String pairingId});
}

class DefaultPairingApiService implements PairingApiService {
  DefaultPairingApiService({required Dio dio}) : _dio = dio;

  final Dio _dio;

  @override
  Future<PairingResponse> createPairing({required String pairingJwt}) async {
    try {
      final response = await _dio.post<Map<String, dynamic>>(
        '/pairing',
        data: {'pairing_jwt': pairingJwt},
      );
      return PairingResponse.fromJson(response.data!);
    } catch (error) {
      _rethrowOrWrap(error, 'create pairing');
    }
  }

  @override
  Future<void> deletePairing({required String pairingId}) async {
    try {
      await _dio.delete<void>('/pairing/$pairingId');
    } catch (error) {
      _rethrowOrWrap(error, 'delete pairing');
    }
  }

  Never _rethrowOrWrap(Object error, String operation) {
    if (error is PairingApiException) throw error;
    if (error is ApiException) throw error;
    throw PairingApiException('failed to $operation', cause: error);
  }
}

@Riverpod(keepAlive: true)
PairingApiService pairingApi(Ref ref) {
  return DefaultPairingApiService(dio: ref.read(httpClientProvider));
}
