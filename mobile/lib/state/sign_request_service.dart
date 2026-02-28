import 'dart:convert';
import 'dart:typed_data';

import 'package:riverpod_annotation/riverpod_annotation.dart';

import '../http/sign_request_api_service.dart';
import '../security/jwe_service.dart';
import '../security/secure_storage_service.dart';
import 'key_management_service.dart';
import 'sign_request_types.dart';

export 'sign_request_types.dart';

part 'sign_request_service.g.dart';

/// Orchestrates sign request fetch → decrypt → respond flow.
abstract interface class SignRequestService {
  /// Fetches pending sign requests and decrypts their payloads.
  Future<List<DecryptedSignRequest>> fetchAndDecrypt();

  /// Submits an approval result with an encrypted signature.
  Future<void> approve({
    required DecryptedSignRequest request,
    required Uint8List signatureBytes,
  });

  /// Submits a denial result.
  Future<void> deny({required DecryptedSignRequest request});

  /// Submits an unavailable result (key not found).
  Future<void> markUnavailable({required DecryptedSignRequest request});
}

class DefaultSignRequestService implements SignRequestService {
  DefaultSignRequestService({
    required SignRequestApiService apiService,
    required SecureStorageService storageService,
    required KeyManagementService keyManagementService,
    JweService? jweService,
  }) : _apiService = apiService,
       _storageService = storageService,
       _keyManagementService = keyManagementService,
       _jweService = jweService ?? JweService();

  final SignRequestApiService _apiService;
  final SecureStorageService _storageService;
  final KeyManagementService _keyManagementService;
  final JweService _jweService;

  @override
  Future<List<DecryptedSignRequest>> fetchAndDecrypt() async {
    try {
      final response = await _apiService.getSignRequests();
      final privateKey = await _loadE2ePrivateKey();
      if (privateKey == null) return [];

      final results = <DecryptedSignRequest>[];
      for (final detail in response.requests) {
        final decrypted = _decryptDetail(detail, privateKey);
        if (decrypted != null) results.add(decrypted);
      }
      return results;
    } catch (error) {
      _rethrowOrWrap(error, 'fetch and decrypt sign requests');
    }
  }

  @override
  Future<void> approve({
    required DecryptedSignRequest request,
    required Uint8List signatureBytes,
  }) async {
    try {
      final encrypted = _jweService.encrypt(
        plaintext: signatureBytes,
        recipientPublicKey: request.daemonEncPublicKey,
      );
      await _apiService.postSignResult(
        signJwt: request.signJwt,
        status: SignResultStatus.approved.value,
        signature: encrypted,
      );
    } catch (error) {
      _rethrowOrWrap(error, 'approve sign request');
    }
  }

  @override
  Future<void> deny({required DecryptedSignRequest request}) async {
    try {
      await _apiService.postSignResult(
        signJwt: request.signJwt,
        status: SignResultStatus.denied.value,
      );
    } catch (error) {
      _rethrowOrWrap(error, 'deny sign request');
    }
  }

  @override
  Future<void> markUnavailable({required DecryptedSignRequest request}) async {
    try {
      await _apiService.postSignResult(
        signJwt: request.signJwt,
        status: SignResultStatus.unavailable.value,
      );
    } catch (error) {
      _rethrowOrWrap(error, 'mark sign request unavailable');
    }
  }

  /// Loads the default E2E private key for decryption.
  Future<EcPrivateJwk?> _loadE2ePrivateKey() async {
    final pubKeys = await _keyManagementService.listPublicKeys();
    final kid = pubKeys.defaultKid;
    final raw = await _storageService.readValue(
      key: '${SecureStorageKeys.e2ePrivateKeyPrefix}$kid',
    );
    if (raw == null) return null;
    return EcPrivateJwk.fromJson(jsonDecode(raw) as Map<String, dynamic>);
  }

  /// Decrypts a single request detail, returning null on failure.
  DecryptedSignRequest? _decryptDetail(
    SignRequestDetail detail,
    EcPrivateJwk privateKey,
  ) {
    try {
      final plainBytes = _jweService.decrypt(
        jweCompact: detail.encryptedPayload,
        privateKey: privateKey,
      );
      final payload =
          jsonDecode(utf8.decode(plainBytes)) as Map<String, dynamic>;
      return _parsePayload(detail, payload);
    } on Object {
      return null;
    }
  }

  DecryptedSignRequest? _parsePayload(
    SignRequestDetail detail,
    Map<String, dynamic> payload,
  ) {
    final hash = payload['hash'] as String?;
    final hashAlgorithm = payload['hash_algorithm'] as String?;
    final keyId = payload['key_id'] as String?;
    if (hash == null || hashAlgorithm == null || keyId == null) return null;
    return DecryptedSignRequest.fromDetail(
      detail: detail,
      hash: hash,
      hashAlgorithm: hashAlgorithm,
      keyId: keyId,
    );
  }

  Never _rethrowOrWrap(Object error, String operation) {
    if (error is SignRequestException) throw error;
    throw SignRequestException('failed to $operation', cause: error);
  }
}

@Riverpod(keepAlive: true)
SignRequestService signRequestService(Ref ref) {
  return DefaultSignRequestService(
    apiService: ref.read(signRequestApiProvider),
    storageService: ref.read(secureStorageProvider),
    keyManagementService: ref.read(keyManagementProvider),
  );
}
