import 'dart:typed_data';

import 'package:pointycastle/export.dart';

import 'crypto_utils.dart' show base64UrlDecode, bytesToBigInt;
import 'gpg_signing_service.dart';

/// Signs [hashBytes] using RSA PKCS#1 v1.5 (no re-hashing).
Uint8List signRsa(
  Uint8List hashBytes,
  String hashAlgorithm,
  Uint8List secretMaterial,
  Map<String, dynamic> jwk,
) {
  final n = _jwkParamToBigInt(jwk, 'n');
  final (d, p, q) = parseRsaSecret(secretMaterial);
  final privKey = RSAPrivateKey(n, d, p, q);

  try {
    final digestInfo = _buildDigestInfo(hashAlgorithm, hashBytes);
    final engine = PKCS1Encoding(RSAEngine());
    engine.init(true, PrivateKeyParameter<RSAPrivateKey>(privKey));
    return engine.process(digestInfo);
  } finally {
    zeroFill(secretMaterial);
  }
}

/// DigestInfo ASN.1 DER prefixes per RFC 3447 §9.2.
const _digestInfoPrefixes = <String, List<int>>{
  'sha256': [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, //
    0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
  ],
  'sha384': [
    0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, //
    0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30,
  ],
  'sha512': [
    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, //
    0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40,
  ],
  'sha224': [
    0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, //
    0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c,
  ],
  'sha1': [
    0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, //
    0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14,
  ],
};

Uint8List _buildDigestInfo(String hashAlgorithm, Uint8List hash) {
  final prefix = _digestInfoPrefixes[hashAlgorithm.toLowerCase()];
  if (prefix == null) {
    throw GpgSigningException('unsupported hash algorithm: $hashAlgorithm');
  }
  return Uint8List.fromList([...prefix, ...hash]);
}

BigInt _jwkParamToBigInt(Map<String, dynamic> jwk, String key) {
  final encoded = jwk[key] as String?;
  if (encoded == null) {
    throw GpgSigningException('missing JWK parameter: $key');
  }
  return bytesToBigInt(base64UrlDecode(encoded));
}
