import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/export.dart';

import 'gpg_signing_service.dart';

/// Signs [hashBytes] using ECDSA with the given P-256/P-384/P-521 key.
///
/// Returns raw R||S bytes (fixed-width, no DER wrapping).
Uint8List signEcdsa(
  Uint8List hashBytes,
  Uint8List secretMaterial,
  Map<String, dynamic> jwk,
) {
  final crv = jwk['crv'] as String?;
  final (domainName, orderLen) = _ecDomainParams(crv);
  final d = parseEcdsaSecret(secretMaterial);
  final domain = ECDomainParameters(domainName);
  final privKey = ECPrivateKey(d, domain);

  try {
    // null digest → pre-computed hash is used directly (no re-hashing).
    final signer = ECDSASigner(null, null);
    signer.init(
      true,
      ParametersWithRandom(
        PrivateKeyParameter<ECPrivateKey>(privKey),
        _newSecureRandom(),
      ),
    );
    final sig = signer.generateSignature(hashBytes) as ECSignature;
    return _encodeRawEcdsaSignature(sig.r, sig.s, orderLen);
  } finally {
    zeroFill(secretMaterial);
  }
}

/// Maps JWK curve name to pointycastle domain and order byte length.
(String domain, int orderLen) _ecDomainParams(String? crv) {
  return switch (crv) {
    'P-256' => ('secp256r1', 32),
    'P-384' => ('secp384r1', 48),
    'P-521' => ('secp521r1', 66),
    _ => throw GpgSigningException('unsupported EC curve: $crv'),
  };
}

/// Encodes R and S as fixed-width big-endian concatenation.
Uint8List _encodeRawEcdsaSignature(BigInt r, BigInt s, int orderLen) {
  final result = Uint8List(orderLen * 2);
  _bigIntToFixed(r, result, 0, orderLen);
  _bigIntToFixed(s, result, orderLen, orderLen);
  return result;
}

void _bigIntToFixed(BigInt value, Uint8List out, int offset, int length) {
  final hex = value.toRadixString(16).padLeft(length * 2, '0');
  for (var i = 0; i < length; i++) {
    out[offset + i] = int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16);
  }
}

FortunaRandom _newSecureRandom() {
  final random = FortunaRandom();
  final seed = List<int>.generate(32, (_) => Random.secure().nextInt(256));
  random.seed(KeyParameter(Uint8List.fromList(seed)));
  return random;
}
