import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:gpg_bridge_mobile/http/gpg_key_api_service.dart';
import 'package:gpg_bridge_mobile/http/public_key_api_service.dart';
import 'package:gpg_bridge_mobile/security/ec_jwk.dart';
import 'package:gpg_bridge_mobile/security/gpg_key_models.dart';
import 'package:gpg_bridge_mobile/security/gpg_signing_service.dart';
import 'package:gpg_bridge_mobile/state/key_management_service.dart';
import 'package:gpg_bridge_mobile/state/sign_execution_service.dart';
import 'package:gpg_bridge_mobile/state/sign_request_service.dart';

const _testPublicJwk = {
  'kty': 'EC',
  'crv': 'P-256',
  'x': '0qHaLh3jKQAQ5tYB6NooOi2lFjJj9E5h80yoHSZoq0I',
  'y': 'F8CORGPfI9872Nxw2Fkr6XUn-5AczutLMi9uRygC7pE',
};

void main() {
  late _MockKeyManagementService mockKeyMgmt;
  late _MockSignRequestService mockSignRequest;
  late _MockGpgSigningService mockGpgSigning;

  setUp(() {
    mockKeyMgmt = _MockKeyManagementService();
    mockSignRequest = _MockSignRequestService();
    mockGpgSigning = _MockGpgSigningService();
  });

  DefaultSignExecutionService createService() {
    return DefaultSignExecutionService(
      keyManagementService: mockKeyMgmt,
      signRequestService: mockSignRequest,
      gpgSigningService: mockGpgSigning,
    );
  }

  DecryptedSignRequest buildRequest({String keyId = '0xABCD1234EF567890'}) {
    return DecryptedSignRequest(
      requestId: 'req-1',
      signJwt: 'jwt-req-1',
      hash: base64Encode([1, 2, 3, 4]),
      hashAlgorithm: 'sha256',
      keyId: keyId,
      pairingId: 'pair-1',
      daemonEncPublicKey: EcPublicJwk.fromJson(_testPublicJwk),
      receivedAt: DateTime.now(),
    );
  }

  group('DefaultSignExecutionService', () {
    test('returns approved when signing succeeds', () async {
      mockKeyMgmt.gpgKeys = [
        GpgKeyEntry(
          keygrip: 'grip-1',
          keyId: 'ABCD1234EF567890',
          publicKey: {'kty': 'RSA', 'n': 'AA', 'e': 'AA'},
        ),
      ];
      mockKeyMgmt.privateKeyBytes = Uint8List.fromList([0, 1, 2]);
      mockGpgSigning.signResult = Uint8List.fromList([10, 20, 30]);

      final service = createService();
      final result = await service.executeApproval(buildRequest());

      expect(result, SignExecutionResult.approved);
      expect(mockSignRequest.lastApproveBytes, isNotNull);
      expect(mockSignRequest.lastApproveBytes, equals([10, 20, 30]));
    });

    test('key ID matching is case-insensitive and strips 0x', () async {
      mockKeyMgmt.gpgKeys = [
        GpgKeyEntry(
          keygrip: 'grip-1',
          keyId: 'abcd1234ef567890',
          publicKey: {'kty': 'RSA', 'n': 'AA', 'e': 'AA'},
        ),
      ];
      mockKeyMgmt.privateKeyBytes = Uint8List(3);
      mockGpgSigning.signResult = Uint8List(2);

      final service = createService();
      final result = await service.executeApproval(
        buildRequest(keyId: '0xABCD1234EF567890'),
      );

      expect(result, SignExecutionResult.approved);
    });

    test('returns unavailable when key not found on server', () async {
      mockKeyMgmt.gpgKeys = [];

      final service = createService();
      final result = await service.executeApproval(buildRequest());

      expect(result, SignExecutionResult.unavailable);
      expect(mockSignRequest.unavailableCalled, isTrue);
    });

    test('returns unavailable when private key not in storage', () async {
      mockKeyMgmt.gpgKeys = [
        GpgKeyEntry(
          keygrip: 'grip-1',
          keyId: 'ABCD1234EF567890',
          publicKey: {'kty': 'RSA', 'n': 'AA', 'e': 'AA'},
        ),
      ];
      mockKeyMgmt.privateKeyBytes = null;

      final service = createService();
      final result = await service.executeApproval(buildRequest());

      expect(result, SignExecutionResult.unavailable);
      expect(mockSignRequest.unavailableCalled, isTrue);
    });

    test('returns unavailable when signing returns null', () async {
      mockKeyMgmt.gpgKeys = [
        GpgKeyEntry(
          keygrip: 'grip-1',
          keyId: 'ABCD1234EF567890',
          publicKey: {'kty': 'OKP', 'crv': 'Ed25519', 'x': 'AA'},
        ),
      ];
      mockKeyMgmt.privateKeyBytes = Uint8List(3);
      mockGpgSigning.signResult = null;

      final service = createService();
      final result = await service.executeApproval(buildRequest());

      expect(result, SignExecutionResult.unavailable);
    });

    test('zeros secret material after use', () async {
      final material = Uint8List.fromList([1, 2, 3, 4, 5]);
      mockKeyMgmt.gpgKeys = [
        GpgKeyEntry(
          keygrip: 'grip-1',
          keyId: 'ABCD1234EF567890',
          publicKey: {'kty': 'RSA', 'n': 'AA', 'e': 'AA'},
        ),
      ];
      mockKeyMgmt.privateKeyBytes = material;
      mockGpgSigning.signResult = Uint8List(2);

      final service = createService();
      await service.executeApproval(buildRequest());

      // material should be zeroed.
      expect(material.every((b) => b == 0), isTrue);
    });
  });
}

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

class _MockKeyManagementService implements KeyManagementService {
  List<GpgKeyEntry> gpgKeys = [];
  Uint8List? privateKeyBytes;

  @override
  Future<GpgKeyListResponse> listGpgKeys() async {
    return GpgKeyListResponse(gpgKeys: gpgKeys);
  }

  @override
  Future<Uint8List?> readGpgPrivateKey(String keygrip) async {
    return privateKeyBytes;
  }

  @override
  Future<PublicKeyListResponse> listPublicKeys() async =>
      PublicKeyListResponse(keys: [], defaultKid: '');
  @override
  Future<void> addE2eKeyPair() async {}
  @override
  Future<void> deletePublicKey(String kid) async {}
  @override
  List<GpgParsedKey> parseGpgArmoredKey(String armoredKey) => [];
  @override
  Future<void> registerGpgKeys(List<GpgParsedKey> keys) async {}
  @override
  Future<void> deleteGpgKey(String keygrip) async {}
  @override
  Future<void> storeGpgPrivateKey(String keygrip, Uint8List material) async {}
  @override
  Future<bool> hasGpgPrivateKey(String keygrip) async => false;
  @override
  Future<void> deleteGpgPrivateKeyMaterial(String keygrip) async {}
}

class _MockSignRequestService implements SignRequestService {
  Uint8List? lastApproveBytes;
  bool unavailableCalled = false;

  @override
  Future<void> approve({
    required DecryptedSignRequest request,
    required Uint8List signatureBytes,
  }) async {
    lastApproveBytes = signatureBytes;
  }

  @override
  Future<void> deny({required DecryptedSignRequest request}) async {}

  @override
  Future<void> markUnavailable({required DecryptedSignRequest request}) async {
    unavailableCalled = true;
  }

  @override
  Future<List<DecryptedSignRequest>> fetchAndDecrypt() async => [];
}

class _MockGpgSigningService implements GpgSigningService {
  Uint8List? signResult;

  @override
  Uint8List? sign({
    required Uint8List hashBytes,
    required String hashAlgorithm,
    required Uint8List secretMaterial,
    required Map<String, dynamic> publicKeyJwk,
  }) {
    return signResult;
  }
}
