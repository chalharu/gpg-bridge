import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:gpg_bridge_mobile/http/gpg_key_api_service.dart';
import 'package:gpg_bridge_mobile/http/public_key_api_service.dart';
import 'package:gpg_bridge_mobile/security/gpg_key_models.dart';
import 'package:gpg_bridge_mobile/security/secure_storage_service.dart';
import 'package:gpg_bridge_mobile/state/key_management_service.dart';

import 'helpers/in_memory_secure_storage_backend.dart';

void main() {
  late _MockPublicKeyApiService mockPublicKeyApi;
  late _MockGpgKeyApiService mockGpgKeyApi;
  late SecureStorageService storageService;
  late InMemorySecureStorageBackend storageBackend;
  late DefaultKeyManagementService service;

  setUp(() {
    mockPublicKeyApi = _MockPublicKeyApiService();
    mockGpgKeyApi = _MockGpgKeyApiService();
    storageBackend = InMemorySecureStorageBackend();
    storageService = SecureStorageService(storageBackend);
    service = DefaultKeyManagementService(
      publicKeyApi: mockPublicKeyApi,
      gpgKeyApi: mockGpgKeyApi,
      storageService: storageService,
    );
  });

  group('KeyManagementException', () {
    test('toString without cause', () {
      final error = KeyManagementException('failed');

      expect(error.toString(), 'KeyManagementException: failed');
    });

    test('toString with cause', () {
      final error = KeyManagementException('failed', cause: Exception('inner'));

      expect(error.toString(), contains('failed'));
      expect(error.toString(), contains('inner'));
    });
  });

  group('listPublicKeys', () {
    test('delegates to PublicKeyApiService', () async {
      mockPublicKeyApi.listResult = PublicKeyListResponse(
        keys: [
          {'kty': 'EC', 'kid': 'k1'},
        ],
        defaultKid: 'k1',
      );

      final result = await service.listPublicKeys();

      expect(result.keys, hasLength(1));
      expect(result.defaultKid, 'k1');
    });

    test('wraps exception in KeyManagementException', () async {
      mockPublicKeyApi.throwOnList = Exception('network error');

      expect(
        () => service.listPublicKeys(),
        throwsA(isA<KeyManagementException>()),
      );
    });
  });

  group('addE2eKeyPair', () {
    test(
      'generates key pair, stores private key, and registers public key',
      () async {
        await service.addE2eKeyPair();

        // Public key was registered
        expect(mockPublicKeyApi.lastAddedKeys, isNotNull);
        expect(mockPublicKeyApi.lastAddedKeys!, hasLength(1));
        expect(mockPublicKeyApi.lastAddedKeys![0]['kty'], 'EC');
        expect(mockPublicKeyApi.lastAddedKeys![0]['crv'], 'P-256');
        expect(mockPublicKeyApi.lastDefaultKid, isNotNull);

        // Private key was stored with e2e_ prefix
        final kid = mockPublicKeyApi.lastDefaultKid!;
        final storedValue = await storageBackend.read(
          key: '${SecureStorageKeys.e2ePrivateKeyPrefix}$kid',
        );
        expect(storedValue, isNotNull);
        // Should be a JSON-encoded JWK with 'd' parameter
        final privateJwk = jsonDecode(storedValue!) as Map<String, dynamic>;
        expect(privateJwk['d'], isNotNull);
        expect(privateJwk['kty'], 'EC');
      },
    );

    test('wraps error in KeyManagementException', () async {
      mockPublicKeyApi.throwOnAdd = Exception('server error');

      expect(
        () => service.addE2eKeyPair(),
        throwsA(isA<KeyManagementException>()),
      );
    });
  });

  group('deletePublicKey', () {
    test('delegates to API and deletes from storage', () async {
      // Pre-store a private key
      await storageBackend.write(
        key: '${SecureStorageKeys.e2ePrivateKeyPrefix}kid-1',
        value: 'secret',
      );

      await service.deletePublicKey('kid-1');

      expect(mockPublicKeyApi.lastDeletedKid, 'kid-1');
      final remaining = await storageBackend.read(
        key: '${SecureStorageKeys.e2ePrivateKeyPrefix}kid-1',
      );
      expect(remaining, isNull);
    });

    test('wraps error in KeyManagementException', () async {
      mockPublicKeyApi.throwOnDelete = Exception('not found');

      expect(
        () => service.deletePublicKey('bad-kid'),
        throwsA(isA<KeyManagementException>()),
      );
    });
  });

  group('parseGpgArmoredKey', () {
    test('returns parsed keys for valid RSA armor', () {
      final body = Uint8List.fromList([
        0x04,
        0x60,
        0x00,
        0x00,
        0x00,
        0x01,
        0x00,
        0x09,
        0x01,
        0x00,
        0x00,
        0x11,
        0x01,
        0x00,
        0x01,
      ]);
      // Wrap in old-format packet (tag 6)
      final packet = Uint8List.fromList([0x98, body.length, ...body]);
      final armored =
          '-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n'
          '${base64.encode(packet)}\n'
          '-----END PGP PUBLIC KEY BLOCK-----';

      final keys = service.parseGpgArmoredKey(armored);

      expect(keys, hasLength(1));
      expect(keys[0].algorithm, GpgKeyAlgorithm.rsa);
    });

    test('wraps FormatException in KeyManagementException', () {
      expect(
        () => service.parseGpgArmoredKey('invalid armor'),
        throwsA(isA<KeyManagementException>()),
      );
    });
  });

  group('registerGpgKeys', () {
    test('converts and delegates to GpgKeyApiService', () async {
      final keys = [
        GpgParsedKey(
          keygrip: 'A' * 40,
          keyId: 'B' * 16,
          publicKeyJwk: {'kty': 'RSA'},
          algorithm: GpgKeyAlgorithm.rsa,
          isSubkey: false,
        ),
      ];

      await service.registerGpgKeys(keys);

      expect(mockGpgKeyApi.lastRegisteredKeys, hasLength(1));
      expect(mockGpgKeyApi.lastRegisteredKeys![0].keygrip, 'A' * 40);
    });

    test('wraps error in KeyManagementException', () async {
      mockGpgKeyApi.throwOnRegister = Exception('server error');

      expect(
        () => service.registerGpgKeys([]),
        throwsA(isA<KeyManagementException>()),
      );
    });
  });

  group('listGpgKeys', () {
    test('delegates to GpgKeyApiService', () async {
      mockGpgKeyApi.listResult = GpgKeyListResponse(
        gpgKeys: [
          GpgKeyEntry(
            keygrip: 'A' * 40,
            keyId: 'B' * 16,
            publicKey: {'kty': 'RSA'},
          ),
        ],
      );

      final result = await service.listGpgKeys();

      expect(result.gpgKeys, hasLength(1));
    });

    test('wraps error in KeyManagementException', () async {
      mockGpgKeyApi.throwOnList = Exception('server error');

      expect(
        () => service.listGpgKeys(),
        throwsA(isA<KeyManagementException>()),
      );
    });
  });

  group('deleteGpgKey', () {
    test('delegates to API and deletes from storage', () async {
      await storageBackend.write(
        key: '${SecureStorageKeys.gpgPrivateKeyPrefix}grip-1',
        value: 'secret',
      );

      await service.deleteGpgKey('grip-1');

      expect(mockGpgKeyApi.lastDeletedKeygrip, 'grip-1');
      final remaining = await storageBackend.read(
        key: '${SecureStorageKeys.gpgPrivateKeyPrefix}grip-1',
      );
      expect(remaining, isNull);
    });

    test('wraps error in KeyManagementException', () async {
      mockGpgKeyApi.throwOnDelete = Exception('not found');

      expect(
        () => service.deleteGpgKey('bad-grip'),
        throwsA(isA<KeyManagementException>()),
      );
    });
  });

  group('storeGpgPrivateKey', () {
    test('stores base64-encoded material in secure storage', () async {
      final material = Uint8List.fromList([1, 2, 3, 4]);

      await service.storeGpgPrivateKey('grip-x', material);

      final stored = await storageBackend.read(
        key: '${SecureStorageKeys.gpgPrivateKeyPrefix}grip-x',
      );
      expect(stored, isNotNull);
      expect(base64Decode(stored!), equals([1, 2, 3, 4]));
    });
  });

  group('hasGpgPrivateKey', () {
    test('returns true when key exists', () async {
      await storageBackend.write(
        key: '${SecureStorageKeys.gpgPrivateKeyPrefix}grip-y',
        value: 'data',
      );

      final result = await service.hasGpgPrivateKey('grip-y');

      expect(result, isTrue);
    });

    test('returns false when key does not exist', () async {
      final result = await service.hasGpgPrivateKey('grip-z');

      expect(result, isFalse);
    });
  });

  group('deleteGpgPrivateKeyMaterial', () {
    test('deletes from secure storage', () async {
      await storageBackend.write(
        key: '${SecureStorageKeys.gpgPrivateKeyPrefix}grip-w',
        value: 'data',
      );

      await service.deleteGpgPrivateKeyMaterial('grip-w');

      final remaining = await storageBackend.read(
        key: '${SecureStorageKeys.gpgPrivateKeyPrefix}grip-w',
      );
      expect(remaining, isNull);
    });
  });
}

// ---------------------------------------------------------------------------
// Mock implementations
// ---------------------------------------------------------------------------

class _MockPublicKeyApiService implements PublicKeyApiService {
  PublicKeyListResponse? listResult;
  List<Map<String, dynamic>>? lastAddedKeys;
  String? lastDefaultKid;
  String? lastDeletedKid;
  Exception? throwOnList;
  Exception? throwOnAdd;
  Exception? throwOnDelete;

  @override
  Future<void> addPublicKeys({
    required List<Map<String, dynamic>> keys,
    String? defaultKid,
  }) async {
    if (throwOnAdd != null) throw throwOnAdd!;
    lastAddedKeys = keys;
    lastDefaultKid = defaultKid;
  }

  @override
  Future<PublicKeyListResponse> listPublicKeys() async {
    if (throwOnList != null) throw throwOnList!;
    return listResult!;
  }

  @override
  Future<void> deletePublicKey({required String kid}) async {
    if (throwOnDelete != null) throw throwOnDelete!;
    lastDeletedKid = kid;
  }
}

class _MockGpgKeyApiService implements GpgKeyApiService {
  GpgKeyListResponse? listResult;
  List<GpgKeyEntry>? lastRegisteredKeys;
  String? lastDeletedKeygrip;
  Exception? throwOnRegister;
  Exception? throwOnList;
  Exception? throwOnDelete;

  @override
  Future<void> registerGpgKeys({required List<GpgKeyEntry> gpgKeys}) async {
    if (throwOnRegister != null) throw throwOnRegister!;
    lastRegisteredKeys = gpgKeys;
  }

  @override
  Future<GpgKeyListResponse> listGpgKeys() async {
    if (throwOnList != null) throw throwOnList!;
    return listResult!;
  }

  @override
  Future<void> deleteGpgKey({required String keygrip}) async {
    if (throwOnDelete != null) throw throwOnDelete!;
    lastDeletedKeygrip = keygrip;
  }
}
