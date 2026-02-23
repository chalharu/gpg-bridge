import 'dart:convert';
import 'dart:typed_data';

import 'package:pointycastle/export.dart';

import 'ec_jwk.dart';
import 'jwe_exception.dart';

/// Default GCM authentication tag length in bits.
const int tagBitLength = 128;

/// P-256 (secp256r1) domain parameters (used by EC point operations).
final ECDomainParameters _ecParams = ECDomainParameters('secp256r1');

// ---------------------------------------------------------------------------
// Base64url helpers
// ---------------------------------------------------------------------------

/// Encodes [bytes] as an unpadded base64url string.
String base64UrlEncode(List<int> bytes) {
  return base64Url.encode(bytes).replaceAll('=', '');
}

/// Decodes an unpadded base64url [encoded] string to bytes.
///
/// Handles non-zero trailing bits that some libraries (e.g. josekit) emit.
Uint8List base64UrlDecode(String encoded) {
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

/// Encodes a JSON [json] map as an unpadded base64url string.
String base64UrlEncodeJson(Map<String, dynamic> json) {
  return base64UrlEncode(utf8.encode(jsonEncode(json)));
}

/// Decodes an unpadded base64url [encoded] string to a JSON map.
Map<String, dynamic> base64UrlDecodeJson(String encoded) {
  return jsonDecode(utf8.decode(base64UrlDecode(encoded)))
      as Map<String, dynamic>;
}

// ---------------------------------------------------------------------------
// BigInt / byte helpers
// ---------------------------------------------------------------------------

/// Decodes a base64url [encoded] string to a [BigInt].
BigInt base64UrlDecodeBigInt(String encoded) {
  return bytesToBigInt(base64UrlDecode(encoded));
}

/// Converts [bytes] to a [BigInt] (big-endian unsigned).
BigInt bytesToBigInt(Uint8List bytes) {
  var result = BigInt.zero;
  for (final b in bytes) {
    result = (result << 8) | BigInt.from(b);
  }
  return result;
}

/// Encodes [value] as a 4-byte big-endian [Uint8List].
Uint8List uint32BigEndian(int value) {
  return Uint8List(4)
    ..[0] = (value >> 24) & 0xff
    ..[1] = (value >> 16) & 0xff
    ..[2] = (value >> 8) & 0xff
    ..[3] = value & 0xff;
}

/// Encodes [value] as an 8-byte big-endian [Uint8List].
Uint8List uint64BigEndian(int value) {
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

// ---------------------------------------------------------------------------
// EC point helpers
// ---------------------------------------------------------------------------

/// Parses a JWK public key to an [ECPoint], validating it lies on P-256.
ECPoint jwkToEcPoint(EcPublicJwk jwk) {
  final xBytes = base64UrlDecode(jwk.x);
  final yBytes = base64UrlDecode(jwk.y);
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
Map<String, dynamic> ecPointToJwk(ECPoint point) {
  // getEncoded(false) returns: 0x04 || x(32 bytes) || y(32 bytes)
  final encoded = point.getEncoded(false);
  return {
    'kty': 'EC',
    'crv': 'P-256',
    'x': base64UrlEncode(encoded.sublist(1, 33)),
    'y': base64UrlEncode(encoded.sublist(33, 65)),
  };
}

/// ECDH key agreement: returns the x-coordinate of
/// `privateScalar * publicPoint` as a fixed-length 32-byte octet string.
///
/// Uses `getEncoded(false)` to extract the affine x-coordinate.
Uint8List ecdh(BigInt privateScalar, ECPoint publicPoint) {
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
Uint8List concatKdf({
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
  otherInfo.add(uint32BigEndian(algIdBytes.length));
  otherInfo.add(algIdBytes);
  // PartyUInfo (length-prefixed)
  final apuBytes = apu != null ? base64UrlDecode(apu) : Uint8List(0);
  otherInfo.add(uint32BigEndian(apuBytes.length));
  if (apuBytes.isNotEmpty) otherInfo.add(apuBytes);
  // PartyVInfo (length-prefixed)
  final apvBytes = apv != null ? base64UrlDecode(apv) : Uint8List(0);
  otherInfo.add(uint32BigEndian(apvBytes.length));
  if (apvBytes.isNotEmpty) otherInfo.add(apvBytes);
  // SuppPubInfo (keydatalen as 32-bit big-endian)
  otherInfo.add(uint32BigEndian(keyBitLength));

  // Single SHA-256 round (keydatalen ≤ 256 for our use case)
  final digest = SHA256Digest();
  final hashInput = BytesBuilder();
  hashInput.add(uint32BigEndian(1)); // counter = 1
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
Uint8List aesKeyWrap({required Uint8List kek, required Uint8List keyToWrap}) {
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
      final tBytes = uint64BigEndian(t);
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
Uint8List aesKeyUnwrap({
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
      final tBytes = uint64BigEndian(t);
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
({Uint8List ciphertext, Uint8List tag}) aesGcmEncrypt({
  required Uint8List key,
  required Uint8List iv,
  required Uint8List plaintext,
  required Uint8List aad,
}) {
  final cipher = GCMBlockCipher(AESEngine())
    ..init(true, AEADParameters(KeyParameter(key), tagBitLength, iv, aad));

  final out = Uint8List(cipher.getOutputSize(plaintext.length));
  var offset = cipher.processBytes(plaintext, 0, plaintext.length, out, 0);
  offset += cipher.doFinal(out, offset);

  final total = out.sublist(0, offset);
  final ctLen = total.length - (tagBitLength ~/ 8);
  return (
    ciphertext: Uint8List.fromList(total.sublist(0, ctLen)),
    tag: Uint8List.fromList(total.sublist(ctLen)),
  );
}

/// Decrypts [ciphertext] + [tag] with AES-256-GCM.
Uint8List aesGcmDecrypt({
  required Uint8List key,
  required Uint8List iv,
  required Uint8List ciphertext,
  required Uint8List tag,
  required Uint8List aad,
}) {
  final cipher = GCMBlockCipher(AESEngine())
    ..init(false, AEADParameters(KeyParameter(key), tagBitLength, iv, aad));

  final input = Uint8List(ciphertext.length + tag.length);
  input.setRange(0, ciphertext.length, ciphertext);
  input.setRange(ciphertext.length, input.length, tag);

  final out = Uint8List(cipher.getOutputSize(input.length));
  var offset = cipher.processBytes(input, 0, input.length, out, 0);
  try {
    offset += cipher.doFinal(out, offset);
  } catch (e) {
    throw JweException('AES-GCM decryption / authentication failed', cause: e);
  }
  return Uint8List.fromList(out.sublist(0, offset));
}
