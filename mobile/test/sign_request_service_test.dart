import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:gpg_bridge_mobile/http/gpg_key_api_service.dart';
import 'package:gpg_bridge_mobile/http/public_key_api_service.dart';
import 'package:gpg_bridge_mobile/http/sign_request_api_service.dart';
import 'package:gpg_bridge_mobile/security/gpg_key_models.dart';
import 'package:gpg_bridge_mobile/security/jwe_service.dart';
import 'package:gpg_bridge_mobile/security/secure_storage_service.dart';
import 'package:gpg_bridge_mobile/state/key_management_types.dart';
import 'package:gpg_bridge_mobile/state/sign_request_service.dart';

import 'helpers/in_memory_secure_storage_backend.dart';

// Shared test key pair from jwe_service_test.dart.
const _testPrivateJwk = {
  'kty': 'EC',
  'crv': 'P-256',
  'x': '0qHaLh3jKQAQ5tYB6NooOi2lFjJj9E5h80yoHSZoq0I',
  'y': 'F8CORGPfI9872Nxw2Fkr6XUn-5AczutLMi9uRygC7pE',
  'd': 'yeT1vLHEotPm9wgZKjtMXW5_gJGis8TV5vcIGavN7wE',
};

const _testPublicJwk = {
  'kty': 'EC',
  'crv': 'P-256',
  'x': '0qHaLh3jKQAQ5tYB6NooOi2lFjJj9E5h80yoHSZoq0I',
  'y': 'F8CORGPfI9872Nxw2Fkr6XUn-5AczutLMi9uRygC7pE',
};

void main() {
  group('DefaultSignRequestService', () {
    late _MockSignRequestApiService mockApi;
    late InMemorySecureStorageBackend backend;
    late SecureStorageService storageService;
    late _MockKeyManagementService mockKeyMgmt;
    late JweService jweService;

    setUp(() {
      mockApi = _MockSignRequestApiService();
      backend = InMemorySecureStorageBackend();
      storageService = SecureStorageService(backend);
      mockKeyMgmt = _MockKeyManagementService();
      jweService = JweService();
    });

    DefaultSignRequestService createService() {
      return DefaultSignRequestService(
        apiService: mockApi,
        storageService: storageService,
        keyManagementService: mockKeyMgmt,
        jweService: jweService,
      );
    }

    test('fetchAndDecrypt returns empty when no requests', () async {
      mockApi.requestsToReturn = [];
      mockKeyMgmt.defaultKid = 'kid-1';
      await backend.write(
        key: 'e2e_private_kid-1',
        value: jsonEncode(_testPrivateJwk),
      );

      final service = createService();
      final result = await service.fetchAndDecrypt();

      expect(result, isEmpty);
    });

    test('fetchAndDecrypt returns empty when no private key', () async {
      mockApi.requestsToReturn = [
        _buildDetail(requestId: 'req-1', payload: 'a.b.c.d.e'),
      ];
      mockKeyMgmt.defaultKid = 'kid-missing';

      final service = createService();
      final result = await service.fetchAndDecrypt();

      expect(result, isEmpty);
    });

    test('fetchAndDecrypt decrypts payload successfully', () async {
      mockKeyMgmt.defaultKid = 'kid-1';
      await backend.write(
        key: 'e2e_private_kid-1',
        value: jsonEncode(_testPrivateJwk),
      );

      final payload = jsonEncode({
        'hash': 'dGVzdA==',
        'hash_algorithm': 'sha256',
        'key_id': '0xABCD',
      });
      final pubKey = EcPublicJwk.fromJson(_testPublicJwk);
      final encrypted = jweService.encrypt(
        plaintext: utf8.encode(payload),
        recipientPublicKey: pubKey,
      );

      mockApi.requestsToReturn = [
        _buildDetail(requestId: 'req-1', payload: encrypted),
      ];

      final service = createService();
      final result = await service.fetchAndDecrypt();

      expect(result, hasLength(1));
      expect(result.first.requestId, 'req-1');
      expect(result.first.hash, 'dGVzdA==');
      expect(result.first.hashAlgorithm, 'sha256');
      expect(result.first.keyId, '0xABCD');
    });

    test('fetchAndDecrypt skips undecryptable payloads', () async {
      mockKeyMgmt.defaultKid = 'kid-1';
      await backend.write(
        key: 'e2e_private_kid-1',
        value: jsonEncode(_testPrivateJwk),
      );

      mockApi.requestsToReturn = [
        _buildDetail(requestId: 'req-bad', payload: 'bad.jwe.data.here.x'),
      ];

      final service = createService();
      final result = await service.fetchAndDecrypt();

      expect(result, isEmpty);
    });

    test('deny sends denied status', () async {
      final request = _buildDecryptedRequest(requestId: 'req-1');
      final service = createService();

      await service.deny(request: request);

      expect(mockApi.lastSignJwt, request.signJwt);
      expect(mockApi.lastStatus, 'denied');
      expect(mockApi.lastSignature, isNull);
    });

    test('markUnavailable sends unavailable status', () async {
      final request = _buildDecryptedRequest(requestId: 'req-2');
      final service = createService();

      await service.markUnavailable(request: request);

      expect(mockApi.lastStatus, 'unavailable');
    });

    test('approve encrypts signature and sends approved', () async {
      final request = _buildDecryptedRequest(requestId: 'req-3');
      final service = createService();

      await service.approve(
        request: request,
        signatureBytes: Uint8List.fromList([1, 2, 3, 4]),
      );

      expect(mockApi.lastStatus, 'approved');
      expect(mockApi.lastSignature, isNotNull);
      // Verify it's a JWE (5 base64url parts).
      expect(mockApi.lastSignature!.split('.'), hasLength(5));
    });
  });
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

SignRequestDetail _buildDetail({
  required String requestId,
  required String payload,
}) {
  return SignRequestDetail(
    requestId: requestId,
    signJwt: 'jwt-$requestId',
    encryptedPayload: payload,
    pairingId: 'pair-1',
    daemonEncPublicKey: EcPublicJwk.fromJson(_testPublicJwk),
  );
}

DecryptedSignRequest _buildDecryptedRequest({required String requestId}) {
  return DecryptedSignRequest(
    requestId: requestId,
    signJwt: 'jwt-$requestId',
    hash: 'dGVzdA==',
    hashAlgorithm: 'sha256',
    keyId: '0xABCD',
    pairingId: 'pair-1',
    daemonEncPublicKey: EcPublicJwk.fromJson(_testPublicJwk),
    receivedAt: DateTime.now(),
  );
}

class _MockSignRequestApiService implements SignRequestApiService {
  List<SignRequestDetail> requestsToReturn = [];
  String? lastSignJwt;
  String? lastStatus;
  String? lastSignature;

  @override
  Future<SignRequestListResponse> getSignRequests() async {
    return SignRequestListResponse(requests: requestsToReturn);
  }

  @override
  Future<void> postSignResult({
    required String signJwt,
    required String status,
    String? signature,
  }) async {
    lastSignJwt = signJwt;
    lastStatus = status;
    lastSignature = signature;
  }
}

class _MockKeyManagementService implements KeyManagementService {
  String defaultKid = '';

  @override
  Future<PublicKeyListResponse> listPublicKeys() async {
    return PublicKeyListResponse(keys: [], defaultKid: defaultKid);
  }

  @override
  Future<void> addE2eKeyPair() async {}

  @override
  Future<void> deletePublicKey(String kid) async {}

  @override
  List<GpgParsedKey> parseGpgArmoredKey(String armoredKey) => [];

  @override
  Future<void> registerGpgKeys(List<GpgParsedKey> keys) async {}

  @override
  Future<GpgKeyListResponse> listGpgKeys() async {
    return GpgKeyListResponse(gpgKeys: []);
  }

  @override
  Future<void> deleteGpgKey(String keygrip) async {}

  @override
  Future<void> storeGpgPrivateKey(String keygrip, Uint8List material) async {}

  @override
  Future<bool> hasGpgPrivateKey(String keygrip) async => false;

  @override
  Future<void> deleteGpgPrivateKeyMaterial(String keygrip) async {}
}
