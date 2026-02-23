import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:flutter/foundation.dart' show visibleForTesting;
import 'package:pointycastle/export.dart';

/// Exception thrown by [JweService] operations.
class JweException implements Exception {
  JweException(this.message, {this.cause});

  final String message;
  final Object? cause;

  @override
  String toString() {
    if (cause == null) return 'JweException: $message';
    return 'JweException: $message ($cause)';
  }
}

/// EC P-256 public key in JWK format for JWE encryption.
///
/// Coordinates are unpadded base64url-encoded big-endian byte strings.
class EcPublicJwk {
  EcPublicJwk({required this.x, required this.y});

  /// Creates an [EcPublicJwk] from a JWK JSON map.
  ///
  /// Validates that `kty` is `"EC"` and `crv` is `"P-256"`.
  factory EcPublicJwk.fromJson(Map<String, dynamic> json) {
    final kty = json['kty'] as String?;
    final crv = json['crv'] as String?;
    if (kty != 'EC' || crv != 'P-256') {
      throw JweException('unsupported key type or curve: kty=$kty, crv=$crv');
    }
    final x = json['x'] as String?;
    final y = json['y'] as String?;
    if (x == null || y == null) {
      throw JweException('missing x or y coordinate');
    }
    return EcPublicJwk(x: x, y: y);
  }

  /// Unpadded base64url-encoded x coordinate (32 bytes for P-256).
  final String x;

  /// Unpadded base64url-encoded y coordinate (32 bytes for P-256).
  final String y;

  /// Returns the JWK JSON representation.
  Map<String, dynamic> toJson() => {
    'kty': 'EC',
    'crv': 'P-256',
    'x': x,
    'y': y,
  };
}

/// EC P-256 private key in JWK format for JWE decryption.
///
/// Coordinates and private scalar are unpadded base64url-encoded big-endian
/// byte strings.
class EcPrivateJwk {
  EcPrivateJwk({required this.x, required this.y, required this.d});

  /// Creates an [EcPrivateJwk] from a JWK JSON map.
  ///
  /// Validates that `kty` is `"EC"`, `crv` is `"P-256"`, and `d` is present.
  factory EcPrivateJwk.fromJson(Map<String, dynamic> json) {
    final kty = json['kty'] as String?;
    final crv = json['crv'] as String?;
    if (kty != 'EC' || crv != 'P-256') {
      throw JweException('unsupported key type or curve: kty=$kty, crv=$crv');
    }
    final x = json['x'] as String?;
    final y = json['y'] as String?;
    final d = json['d'] as String?;
    if (x == null || y == null || d == null) {
      throw JweException('missing x, y, or d parameter');
    }
    return EcPrivateJwk(x: x, y: y, d: d);
  }

  /// Unpadded base64url-encoded x coordinate.
  final String x;

  /// Unpadded base64url-encoded y coordinate.
  final String y;

  /// Unpadded base64url-encoded private key scalar.
  final String d;

  /// Extracts the corresponding public key.
  EcPublicJwk get publicKey => EcPublicJwk(x: x, y: y);

  /// Returns the JWK JSON representation (includes private material).
  Map<String, dynamic> toJson() => {
    'kty': 'EC',
    'crv': 'P-256',
    'x': x,
    'y': y,
    'd': d,
  };
}

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
  static const int _tagBitLength = 128;

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
    final recipientPoint = _jwkToEcPoint(recipientPublicKey);
    final sharedSecret = _ecdh(ephemeralPrivate.d!, recipientPoint);

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
      final epkJson = _ecPointToJwk(ephemeralPublic.Q!);
      final protectedHeader = {
        'alg': algorithm,
        'enc': encryption,
        'epk': epkJson,
      };
      final headerEncoded = _base64UrlEncodeJson(protectedHeader);

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
          '.${_base64UrlEncode(wrappedCek)}'
          '.${_base64UrlEncode(iv)}'
          '.${_base64UrlEncode(encrypted.ciphertext)}'
          '.${_base64UrlEncode(encrypted.tag)}';
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
    final encryptedKey = _base64UrlDecode(parts[1]);
    final iv = _base64UrlDecode(parts[2]);
    final ciphertext = _base64UrlDecode(parts[3]);
    final tag = _base64UrlDecode(parts[4]);

    // 2. Decode protected header
    final header = _base64UrlDecodeJson(headerEncoded);
    _validateHeader(header);

    final epk = EcPublicJwk.fromJson(
      (header['epk'] as Map<String, dynamic>?) ??
          (throw JweException('missing epk in protected header')),
    );

    // 3. ECDH shared secret
    final privateScalar = _base64UrlDecodeBigInt(privateKey.d);
    final ephemeralPoint = _jwkToEcPoint(epk);
    final sharedSecret = _ecdh(privateScalar, ephemeralPoint);

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

  /// Parses a JWK public key to an [ECPoint], validating it lies on P-256.
  static ECPoint _jwkToEcPoint(EcPublicJwk jwk) {
    final xBytes = _base64UrlDecode(jwk.x);
    final yBytes = _base64UrlDecode(jwk.y);
    if (xBytes.length != 32 || yBytes.length != 32) {
      throw JweException(
        'invalid P-256 coordinate length: '
        'x=${xBytes.length}, y=${yBytes.length}',
      );
    }
    // Encode as uncompressed point (0x04 || x || y) and decode via
    // the curve, which validates the point lies on the curve.
    final encoded = Uint8List(65);
    encoded[0] = 0x04;
    encoded.setRange(1, 33, xBytes);
    encoded.setRange(33, 65, yBytes);
    try {
      final point = _ecParams.curve.decodePoint(encoded);
      if (point == null) {
        throw JweException('invalid EC point: decodePoint returned null');
      }
      return point;
    } catch (e) {
      if (e is JweException) rethrow;
      throw JweException('invalid EC point', cause: e);
    }
  }

  /// Converts an [ECPoint] to a JWK JSON map.
  ///
  /// Uses `getEncoded(false)` to obtain affine coordinates.
  static Map<String, dynamic> _ecPointToJwk(ECPoint point) {
    // getEncoded(false) returns: 0x04 || x(32 bytes) || y(32 bytes)
    final encoded = point.getEncoded(false);
    return {
      'kty': 'EC',
      'crv': 'P-256',
      'x': _base64UrlEncode(encoded.sublist(1, 33)),
      'y': _base64UrlEncode(encoded.sublist(33, 65)),
    };
  }

  /// ECDH key agreement: returns the x-coordinate of
  /// `privateScalar * publicPoint` as a fixed-length 32-byte octet string.
  ///
  /// Uses `getEncoded(false)` to extract the affine x-coordinate.
  static Uint8List _ecdh(BigInt privateScalar, ECPoint publicPoint) {
    final sharedPoint = publicPoint * privateScalar;
    if (sharedPoint == null || sharedPoint.isInfinity) {
      throw JweException('ECDH resulted in point at infinity');
    }
    // getEncoded(false) returns: 0x04 || x(32 bytes) || y(32 bytes)
    final encoded = sharedPoint.getEncoded(false);
    return Uint8List.fromList(encoded.sublist(1, 33));
  }

  // ---------------------------------------------------------------------------
  // Concat KDF  (NIST SP 800-56A §5.8.1, RFC 7518 §4.6.2)
  // ---------------------------------------------------------------------------

  /// Derives a key using Concat KDF with SHA-256.
  ///
  /// [sharedSecret] is the ECDH shared secret (Z).
  /// [algorithmId] is the "alg" value for key-wrapping variants.
  /// [keyBitLength] is the desired output key length in bits.
  /// [apu] and [apv] are optional Agreement PartyU/V Info (base64url-encoded).
  @visibleForTesting
  static Uint8List concatKdf({
    required Uint8List sharedSecret,
    required String algorithmId,
    required int keyBitLength,
    String? apu,
    String? apv,
  }) {
    if (keyBitLength > 256) {
      throw JweException(
        'Concat KDF: multi-round derivation not implemented for '
        'keyBitLength > 256',
      );
    }
    final algIdBytes = utf8.encode(algorithmId);

    final otherInfo = BytesBuilder();
    // AlgorithmID (length-prefixed)
    otherInfo.add(_uint32BigEndian(algIdBytes.length));
    otherInfo.add(algIdBytes);
    // PartyUInfo (length-prefixed)
    final apuBytes = apu != null ? _base64UrlDecode(apu) : Uint8List(0);
    otherInfo.add(_uint32BigEndian(apuBytes.length));
    if (apuBytes.isNotEmpty) otherInfo.add(apuBytes);
    // PartyVInfo (length-prefixed)
    final apvBytes = apv != null ? _base64UrlDecode(apv) : Uint8List(0);
    otherInfo.add(_uint32BigEndian(apvBytes.length));
    if (apvBytes.isNotEmpty) otherInfo.add(apvBytes);
    // SuppPubInfo (keydatalen as 32-bit big-endian)
    otherInfo.add(_uint32BigEndian(keyBitLength));

    // Single SHA-256 round (keydatalen ≤ 256 for our use case)
    final digest = SHA256Digest();
    final hashInput = BytesBuilder();
    hashInput.add(_uint32BigEndian(1)); // counter = 1
    hashInput.add(sharedSecret);
    hashInput.add(otherInfo.toBytes());

    final inputBytes = hashInput.toBytes();
    final hash = Uint8List(digest.digestSize);
    digest.update(inputBytes, 0, inputBytes.length);
    digest.doFinal(hash, 0);

    return Uint8List.fromList(hash.sublist(0, keyBitLength ~/ 8));
  }

  // ---------------------------------------------------------------------------
  // AES Key Wrap  (RFC 3394)
  // ---------------------------------------------------------------------------

  /// Wraps [keyToWrap] with [kek] using AES Key Wrap (RFC 3394).
  @visibleForTesting
  static Uint8List aesKeyWrap({
    required Uint8List kek,
    required Uint8List keyToWrap,
  }) {
    if (keyToWrap.length % 8 != 0 || keyToWrap.length < 16) {
      throw JweException(
        'key to wrap must be a multiple of 8 bytes and at least 16 bytes',
      );
    }
    final n = keyToWrap.length ~/ 8;
    final aes = AESEngine()..init(true, KeyParameter(kek));

    var a = Uint8List.fromList(const [
      0xA6,
      0xA6,
      0xA6,
      0xA6,
      0xA6,
      0xA6,
      0xA6,
      0xA6,
    ]);
    final r = List<Uint8List>.generate(
      n,
      (i) => Uint8List.fromList(keyToWrap.sublist(i * 8, (i + 1) * 8)),
    );

    final block = Uint8List(16);
    final encrypted = Uint8List(16);

    for (var j = 0; j < 6; j++) {
      for (var i = 0; i < n; i++) {
        block.setRange(0, 8, a);
        block.setRange(8, 16, r[i]);
        aes.processBlock(block, 0, encrypted, 0);

        final t = n * j + i + 1;
        final tBytes = _uint64BigEndian(t);
        a = Uint8List(8);
        for (var k = 0; k < 8; k++) {
          a[k] = encrypted[k] ^ tBytes[k];
        }
        r[i] = Uint8List.fromList(encrypted.sublist(8, 16));
      }
    }

    final result = Uint8List(8 + n * 8);
    result.setRange(0, 8, a);
    for (var i = 0; i < n; i++) {
      result.setRange(8 + i * 8, 16 + i * 8, r[i]);
    }
    return result;
  }

  /// Unwraps [wrappedKey] with [kek] using AES Key Unwrap (RFC 3394).
  @visibleForTesting
  static Uint8List aesKeyUnwrap({
    required Uint8List kek,
    required Uint8List wrappedKey,
  }) {
    if (wrappedKey.length % 8 != 0 || wrappedKey.length < 24) {
      throw JweException(
        'wrapped key must be a multiple of 8 bytes and at least 24 bytes',
      );
    }
    final n = (wrappedKey.length ~/ 8) - 1;
    final aes = AESEngine()..init(false, KeyParameter(kek));

    var a = Uint8List.fromList(wrappedKey.sublist(0, 8));
    final r = List<Uint8List>.generate(
      n,
      (i) => Uint8List.fromList(wrappedKey.sublist((i + 1) * 8, (i + 2) * 8)),
    );

    final block = Uint8List(16);
    final decrypted = Uint8List(16);

    for (var j = 5; j >= 0; j--) {
      for (var i = n - 1; i >= 0; i--) {
        final t = n * j + i + 1;
        final tBytes = _uint64BigEndian(t);
        final axored = Uint8List(8);
        for (var k = 0; k < 8; k++) {
          axored[k] = a[k] ^ tBytes[k];
        }
        block.setRange(0, 8, axored);
        block.setRange(8, 16, r[i]);
        aes.processBlock(block, 0, decrypted, 0);
        a = Uint8List.fromList(decrypted.sublist(0, 8));
        r[i] = Uint8List.fromList(decrypted.sublist(8, 16));
      }
    }

    // Verify integrity check value (RFC 3394 §2.2.2) – constant-time compare
    const expectedIv = [0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6];
    var diff = 0;
    for (var i = 0; i < 8; i++) {
      diff |= a[i] ^ expectedIv[i];
    }
    if (diff != 0) {
      throw JweException('AES Key Unwrap integrity check failed');
    }

    final result = Uint8List(n * 8);
    for (var i = 0; i < n; i++) {
      result.setRange(i * 8, (i + 1) * 8, r[i]);
    }
    return result;
  }

  // ---------------------------------------------------------------------------
  // AES-256-GCM
  // ---------------------------------------------------------------------------

  /// Encrypts [plaintext] with AES-256-GCM, returning ciphertext and tag.
  @visibleForTesting
  static ({Uint8List ciphertext, Uint8List tag}) aesGcmEncrypt({
    required Uint8List key,
    required Uint8List iv,
    required Uint8List plaintext,
    required Uint8List aad,
  }) {
    final cipher = GCMBlockCipher(AESEngine())
      ..init(true, AEADParameters(KeyParameter(key), _tagBitLength, iv, aad));

    final out = Uint8List(cipher.getOutputSize(plaintext.length));
    var offset = cipher.processBytes(plaintext, 0, plaintext.length, out, 0);
    offset += cipher.doFinal(out, offset);

    final total = out.sublist(0, offset);
    final ctLen = total.length - (_tagBitLength ~/ 8);
    return (
      ciphertext: Uint8List.fromList(total.sublist(0, ctLen)),
      tag: Uint8List.fromList(total.sublist(ctLen)),
    );
  }

  /// Decrypts [ciphertext] + [tag] with AES-256-GCM.
  @visibleForTesting
  static Uint8List aesGcmDecrypt({
    required Uint8List key,
    required Uint8List iv,
    required Uint8List ciphertext,
    required Uint8List tag,
    required Uint8List aad,
  }) {
    final cipher = GCMBlockCipher(AESEngine())
      ..init(false, AEADParameters(KeyParameter(key), _tagBitLength, iv, aad));

    final input = Uint8List(ciphertext.length + tag.length);
    input.setRange(0, ciphertext.length, ciphertext);
    input.setRange(ciphertext.length, input.length, tag);

    final out = Uint8List(cipher.getOutputSize(input.length));
    var offset = cipher.processBytes(input, 0, input.length, out, 0);
    try {
      offset += cipher.doFinal(out, offset);
    } catch (e) {
      throw JweException(
        'AES-GCM decryption / authentication failed',
        cause: e,
      );
    }
    return Uint8List.fromList(out.sublist(0, offset));
  }

  // ---------------------------------------------------------------------------
  // Base64url helpers
  // ---------------------------------------------------------------------------

  static String _base64UrlEncode(List<int> bytes) {
    return base64Url.encode(bytes).replaceAll('=', '');
  }

  static Uint8List _base64UrlDecode(String encoded) {
    // Some libraries (e.g. josekit) emit base64url with non-zero trailing bits.
    // Dart's decoder is strict, so we mask the last character's padding bits.
    if (encoded.isEmpty) return Uint8List(0);
    final remainder = encoded.length % 4;
    var sanitized = encoded;
    if (remainder == 2 || remainder == 3) {
      const table =
          'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
      final lastVal = table.indexOf(encoded[encoded.length - 1]);
      if (lastVal >= 0) {
        // Zero out padding bits: 4 bits for remainder==2, 2 bits for remainder==3
        final mask = remainder == 2 ? 0x30 : 0x3C;
        sanitized =
            encoded.substring(0, encoded.length - 1) + table[lastVal & mask];
      }
    }
    final padded = sanitized + '=' * ((4 - sanitized.length % 4) % 4);
    return base64Url.decode(padded);
  }

  static String _base64UrlEncodeJson(Map<String, dynamic> json) {
    return _base64UrlEncode(utf8.encode(jsonEncode(json)));
  }

  static Map<String, dynamic> _base64UrlDecodeJson(String encoded) {
    return jsonDecode(utf8.decode(_base64UrlDecode(encoded)))
        as Map<String, dynamic>;
  }

  // ---------------------------------------------------------------------------
  // BigInt / byte helpers
  // ---------------------------------------------------------------------------

  static BigInt _base64UrlDecodeBigInt(String encoded) {
    return _bytesToBigInt(_base64UrlDecode(encoded));
  }

  static BigInt _bytesToBigInt(Uint8List bytes) {
    var result = BigInt.zero;
    for (final b in bytes) {
      result = (result << 8) | BigInt.from(b);
    }
    return result;
  }

  static Uint8List _uint32BigEndian(int value) {
    return Uint8List(4)
      ..[0] = (value >> 24) & 0xff
      ..[1] = (value >> 16) & 0xff
      ..[2] = (value >> 8) & 0xff
      ..[3] = value & 0xff;
  }

  static Uint8List _uint64BigEndian(int value) {
    return Uint8List(8)
      ..[0] = (value >> 56) & 0xff
      ..[1] = (value >> 48) & 0xff
      ..[2] = (value >> 40) & 0xff
      ..[3] = (value >> 32) & 0xff
      ..[4] = (value >> 24) & 0xff
      ..[5] = (value >> 16) & 0xff
      ..[6] = (value >> 8) & 0xff
      ..[7] = value & 0xff;
  }

  Uint8List _generateRandomBytes(int length) {
    return Uint8List.fromList(
      List.generate(length, (_) => _random.nextInt(256)),
    );
  }
}
