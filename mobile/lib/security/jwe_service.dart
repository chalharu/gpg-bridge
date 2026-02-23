import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/export.dart';

import 'crypto_utils.dart';
import 'ec_jwk.dart';
import 'jwe_exception.dart';

export 'crypto_utils.dart';
export 'ec_jwk.dart';
export 'jwe_exception.dart';

/// JWE encryption / decryption service using **ECDH-ES+A256KW** key agreement
/// and **A256GCM** content encryption.
///
/// Implements the following RFCs:
/// - RFC 7516 (JWE compact serialization)
/// - RFC 7518 §4.6 (ECDH-ES key agreement with Concat KDF)
/// - RFC 3394 (AES Key Wrap)
/// - NIST SP 800-38D (AES-GCM)
///
/// The encryption flow:
/// 1. Generate an ephemeral EC P-256 key pair
/// 2. ECDH key agreement (ephemeral private + recipient public)
/// 3. Concat KDF → 256-bit KEK
/// 4. Generate random 256-bit CEK
/// 5. AES-256 Key Wrap the CEK with the KEK
/// 6. AES-256-GCM encrypt plaintext with the CEK
/// 7. JWE compact serialization
///
/// The decryption flow:
/// 1. Parse JWE compact serialization
/// 2. Extract `epk` from the protected header
/// 3. ECDH key agreement (own private + epk)
/// 4. Concat KDF → 256-bit KEK
/// 5. AES-256 Key Unwrap → CEK
/// 6. AES-256-GCM decrypt ciphertext with the CEK
class JweService {
  /// Creates a [JweService].
  ///
  /// An optional [random] can be provided for deterministic testing.
  JweService({Random? random}) : _random = random ?? Random.secure();

  final Random _random;

  static const String algorithm = 'ECDH-ES+A256KW';
  static const String encryption = 'A256GCM';
  static const int _kekBitLength = 256;
  static const int _cekByteLength = 32;
  static const int _ivByteLength = 12;

  /// P-256 (secp256r1) domain parameters.
  static final ECDomainParameters _ecParams = ECDomainParameters('secp256r1');

  // ---------------------------------------------------------------------------
  // Public API
  // ---------------------------------------------------------------------------

  /// Encrypts [plaintext] for the given [recipientPublicKey].
  ///
  /// Returns a JWE compact serialization string (five base64url-encoded parts
  /// separated by dots).
  String encrypt({
    required List<int> plaintext,
    required EcPublicJwk recipientPublicKey,
  }) {
    try {
      return _encryptInternal(
        plaintext: plaintext,
        recipientPublicKey: recipientPublicKey,
      );
    } catch (e) {
      if (e is JweException) rethrow;
      throw JweException('encryption failed', cause: e);
    }
  }

  /// Decrypts a JWE compact serialization string with the given [privateKey].
  ///
  /// Returns the original plaintext bytes.
  Uint8List decrypt({
    required String jweCompact,
    required EcPrivateJwk privateKey,
  }) {
    try {
      return _decryptInternal(jweCompact: jweCompact, privateKey: privateKey);
    } catch (e) {
      if (e is JweException) rethrow;
      throw JweException('decryption failed', cause: e);
    }
  }

  // ---------------------------------------------------------------------------
  // Internal: encrypt
  // ---------------------------------------------------------------------------

  String _encryptInternal({
    required List<int> plaintext,
    required EcPublicJwk recipientPublicKey,
  }) {
    // 1. Generate ephemeral key pair
    final ephemeralKeyPair = _generateEcKeyPair();
    final ephemeralPrivate = ephemeralKeyPair.privateKey as ECPrivateKey;
    final ephemeralPublic = ephemeralKeyPair.publicKey as ECPublicKey;

    // 2. ECDH shared secret
    final recipientPoint = jwkToEcPoint(recipientPublicKey);
    final sharedSecret = ecdh(ephemeralPrivate.d!, recipientPoint);

    Uint8List? kek;
    Uint8List? cek;
    try {
      // 3. Derive KEK via Concat KDF
      kek = concatKdf(
        sharedSecret: sharedSecret,
        algorithmId: algorithm,
        keyBitLength: _kekBitLength,
      );

      // 4. Random CEK
      cek = _generateRandomBytes(_cekByteLength);

      // 5. AES Key Wrap
      final wrappedCek = aesKeyWrap(kek: kek, keyToWrap: cek);

      // 6. Protected header
      final epkJson = ecPointToJwk(ephemeralPublic.Q!);
      final protectedHeader = {
        'alg': algorithm,
        'enc': encryption,
        'epk': epkJson,
      };
      final headerEncoded = base64UrlEncodeJson(protectedHeader);

      // 7. AES-256-GCM encrypt
      final iv = _generateRandomBytes(_ivByteLength);
      final aad = Uint8List.fromList(utf8.encode(headerEncoded));
      final encrypted = aesGcmEncrypt(
        key: cek,
        iv: iv,
        plaintext: Uint8List.fromList(plaintext),
        aad: aad,
      );

      // 8. Compact serialization
      return '$headerEncoded'
          '.${base64UrlEncode(wrappedCek)}'
          '.${base64UrlEncode(iv)}'
          '.${base64UrlEncode(encrypted.ciphertext)}'
          '.${base64UrlEncode(encrypted.tag)}';
    } finally {
      sharedSecret.fillRange(0, sharedSecret.length, 0);
      kek?.fillRange(0, kek.length, 0);
      cek?.fillRange(0, cek.length, 0);
    }
  }

  // ---------------------------------------------------------------------------
  // Internal: decrypt
  // ---------------------------------------------------------------------------

  Uint8List _decryptInternal({
    required String jweCompact,
    required EcPrivateJwk privateKey,
  }) {
    // 1. Split into 5 parts
    final parts = jweCompact.split('.');
    if (parts.length != 5) {
      throw JweException(
        'invalid JWE compact serialization: expected 5 parts, '
        'got ${parts.length}',
      );
    }

    final headerEncoded = parts[0];
    final encryptedKey = base64UrlDecode(parts[1]);
    final iv = base64UrlDecode(parts[2]);
    final ciphertext = base64UrlDecode(parts[3]);
    final tag = base64UrlDecode(parts[4]);

    // 2. Decode protected header
    final header = base64UrlDecodeJson(headerEncoded);
    _validateHeader(header);

    final epk = EcPublicJwk.fromJson(
      (header['epk'] as Map<String, dynamic>?) ??
          (throw JweException('missing epk in protected header')),
    );

    // 3. ECDH shared secret
    final privateScalar = base64UrlDecodeBigInt(privateKey.d);
    final ephemeralPoint = jwkToEcPoint(epk);
    final sharedSecret = ecdh(privateScalar, ephemeralPoint);

    Uint8List? kek;
    Uint8List? cek;
    try {
      // 4. Derive KEK (handle optional apu/apv from header)
      kek = concatKdf(
        sharedSecret: sharedSecret,
        algorithmId: algorithm,
        keyBitLength: _kekBitLength,
        apu: header['apu'] as String?,
        apv: header['apv'] as String?,
      );

      // 5. AES Key Unwrap
      cek = aesKeyUnwrap(kek: kek, wrappedKey: encryptedKey);

      // 6. AES-256-GCM decrypt
      final aad = Uint8List.fromList(utf8.encode(headerEncoded));
      return aesGcmDecrypt(
        key: cek,
        iv: iv,
        ciphertext: ciphertext,
        tag: tag,
        aad: aad,
      );
    } finally {
      sharedSecret.fillRange(0, sharedSecret.length, 0);
      kek?.fillRange(0, kek.length, 0);
      cek?.fillRange(0, cek.length, 0);
    }
  }

  void _validateHeader(Map<String, dynamic> header) {
    final alg = header['alg'] as String?;
    final enc = header['enc'] as String?;
    if (alg != algorithm) {
      throw JweException('unsupported algorithm: $alg');
    }
    if (enc != encryption) {
      throw JweException('unsupported encryption: $enc');
    }
  }

  // ---------------------------------------------------------------------------
  // EC key operations
  // ---------------------------------------------------------------------------

  AsymmetricKeyPair<PublicKey, PrivateKey> _generateEcKeyPair() {
    final keyGen = ECKeyGenerator()
      ..init(
        ParametersWithRandom(
          ECKeyGeneratorParameters(_ecParams),
          _secureRandom(),
        ),
      );
    return keyGen.generateKeyPair();
  }

  FortunaRandom _secureRandom() {
    final sr = FortunaRandom();
    final seed = Uint8List(32);
    for (var i = 0; i < 32; i++) {
      seed[i] = _random.nextInt(256);
    }
    sr.seed(KeyParameter(seed));
    return sr;
  }

  Uint8List _generateRandomBytes(int length) {
    return Uint8List.fromList(
      List.generate(length, (_) => _random.nextInt(256)),
    );
  }
}
