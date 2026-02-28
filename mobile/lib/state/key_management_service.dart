import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/export.dart';
import 'package:riverpod_annotation/riverpod_annotation.dart';
import 'package:uuid/uuid.dart';

import '../http/gpg_key_api_service.dart';
import '../http/public_key_api_service.dart';
import '../security/crypto_utils.dart' show base64UrlEncode;
import '../security/gpg_key_models.dart';
import '../security/gpg_key_parser.dart';
import '../security/secure_storage_service.dart';
import 'key_management_types.dart';

export 'key_management_types.dart';

part 'key_management_service.g.dart';

class DefaultKeyManagementService implements KeyManagementService {
  DefaultKeyManagementService({
    required PublicKeyApiService publicKeyApi,
    required GpgKeyApiService gpgKeyApi,
    required SecureStorageService storageService,
  }) : _publicKeyApi = publicKeyApi,
       _gpgKeyApi = gpgKeyApi,
       _storageService = storageService;

  final PublicKeyApiService _publicKeyApi;
  final GpgKeyApiService _gpgKeyApi;
  final SecureStorageService _storageService;

  @override
  Future<PublicKeyListResponse> listPublicKeys() async {
    try {
      return await _publicKeyApi.listPublicKeys();
    } catch (error) {
      _rethrowOrWrap(error, 'list public keys');
    }
  }

  @override
  Future<void> addE2eKeyPair() async {
    try {
      final kid = const Uuid().v4();
      final keyPair = _generateEcKeyPair();

      final publicKey = keyPair.publicKey as ECPublicKey;
      final privateKey = keyPair.privateKey as ECPrivateKey;

      // Build public JWK.
      final encoded = publicKey.Q!.getEncoded(false);
      final publicJwk = <String, dynamic>{
        'kty': 'EC',
        'crv': 'P-256',
        'x': base64UrlEncode(encoded.sublist(1, 33)),
        'y': base64UrlEncode(encoded.sublist(33, 65)),
        'use': 'enc',
        'alg': 'ECDH-ES+A256KW',
        'kid': kid,
      };

      // Build private JWK for storage.
      final dBytes = _bigIntToFixedBytes(privateKey.d!, 32);
      final privateJwk = <String, dynamic>{
        ...publicJwk,
        'd': base64UrlEncode(dBytes),
      };

      // Store private key first, then register public key.
      // If registration fails, clean up the orphaned private key.
      final storageKey = '${SecureStorageKeys.e2ePrivateKeyPrefix}$kid';
      await _storageService.writeValue(
        key: storageKey,
        value: jsonEncode(privateJwk),
      );
      try {
        await _publicKeyApi.addPublicKeys(keys: [publicJwk], defaultKid: kid);
      } catch (_) {
        try {
          await _storageService.deleteValue(key: storageKey);
        } catch (_) {}
        rethrow;
      }
    } catch (error) {
      _rethrowOrWrap(error, 'add E2E key pair');
    }
  }

  @override
  Future<void> deletePublicKey(String kid) async {
    try {
      await _publicKeyApi.deletePublicKey(kid: kid);
      await _storageService.deleteValue(
        key: '${SecureStorageKeys.e2ePrivateKeyPrefix}$kid',
      );
    } catch (error) {
      _rethrowOrWrap(error, 'delete public key');
    }
  }

  @override
  List<GpgParsedKey> parseGpgArmoredKey(String armoredKey) {
    try {
      return parseGpgKeys(armoredKey);
    } catch (error) {
      _rethrowOrWrap(error, 'parse GPG armored key');
    }
  }

  @override
  Future<void> registerGpgKeys(List<GpgParsedKey> keys) async {
    try {
      final entries = keys
          .map(
            (k) => GpgKeyEntry(
              keygrip: k.keygrip,
              keyId: k.keyId,
              publicKey: k.publicKeyJwk,
            ),
          )
          .toList();
      await _gpgKeyApi.registerGpgKeys(gpgKeys: entries);
    } catch (error) {
      _rethrowOrWrap(error, 'register GPG keys');
    }
  }

  @override
  Future<GpgKeyListResponse> listGpgKeys() async {
    try {
      return await _gpgKeyApi.listGpgKeys();
    } catch (error) {
      _rethrowOrWrap(error, 'list GPG keys');
    }
  }

  @override
  Future<void> deleteGpgKey(String keygrip) async {
    try {
      await _gpgKeyApi.deleteGpgKey(keygrip: keygrip);
      await _storageService.deleteValue(
        key: '${SecureStorageKeys.gpgPrivateKeyPrefix}$keygrip',
      );
    } catch (error) {
      _rethrowOrWrap(error, 'delete GPG key');
    }
  }

  @override
  Future<void> storeGpgPrivateKey(String keygrip, Uint8List material) async {
    try {
      final encoded = base64Encode(material);
      await _storageService.writeValue(
        key: '${SecureStorageKeys.gpgPrivateKeyPrefix}$keygrip',
        value: encoded,
      );
    } catch (error) {
      _rethrowOrWrap(error, 'store GPG private key');
    }
  }

  @override
  Future<bool> hasGpgPrivateKey(String keygrip) async {
    try {
      final value = await _storageService.readValue(
        key: '${SecureStorageKeys.gpgPrivateKeyPrefix}$keygrip',
      );
      return value != null;
    } catch (error) {
      _rethrowOrWrap(error, 'check GPG private key');
    }
  }

  @override
  Future<void> deleteGpgPrivateKeyMaterial(String keygrip) async {
    try {
      await _storageService.deleteValue(
        key: '${SecureStorageKeys.gpgPrivateKeyPrefix}$keygrip',
      );
    } catch (error) {
      _rethrowOrWrap(error, 'delete GPG private key material');
    }
  }

  @override
  Future<Uint8List?> readGpgPrivateKey(String keygrip) async {
    try {
      final raw = await _storageService.readValue(
        key: '${SecureStorageKeys.gpgPrivateKeyPrefix}$keygrip',
      );
      if (raw == null) return null;
      return base64Decode(raw);
    } catch (error) {
      _rethrowOrWrap(error, 'read GPG private key');
    }
  }

  /// Generates an EC P-256 key pair using pointycastle.
  AsymmetricKeyPair<PublicKey, PrivateKey> _generateEcKeyPair() {
    final secureRandom = FortunaRandom();
    final seedSource = Random.secure();
    final seeds = List<int>.generate(32, (_) => seedSource.nextInt(256));
    secureRandom.seed(KeyParameter(Uint8List.fromList(seeds)));

    final keyGen = ECKeyGenerator()
      ..init(
        ParametersWithRandom(
          ECKeyGeneratorParameters(ECCurve_secp256r1()),
          secureRandom,
        ),
      );
    return keyGen.generateKeyPair();
  }

  /// Converts a [BigInt] to a fixed-length big-endian byte array.
  static Uint8List _bigIntToFixedBytes(BigInt value, int length) {
    final hex = value.toRadixString(16).padLeft(length * 2, '0');
    final bytes = Uint8List(length);
    for (var i = 0; i < length; i++) {
      bytes[i] = int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16);
    }
    return bytes;
  }

  Never _rethrowOrWrap(Object error, String operation) {
    if (error is KeyManagementException) throw error;
    throw KeyManagementException('failed to $operation', cause: error);
  }
}

@Riverpod(keepAlive: true)
KeyManagementService keyManagement(Ref ref) {
  return DefaultKeyManagementService(
    publicKeyApi: ref.read(publicKeyApiProvider),
    gpgKeyApi: ref.read(gpgKeyApiProvider),
    storageService: ref.read(secureStorageProvider),
  );
}
