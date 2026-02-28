import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:gpg_bridge_mobile/security/gpg_signing_service.dart';
import 'package:pointycastle/export.dart';

void main() {
  late DefaultGpgSigningService service;

  setUp(() {
    service = DefaultGpgSigningService();
  });

  group('GpgSigningException', () {
    test('toString without cause', () {
      final e = GpgSigningException('fail');
      expect(e.toString(), 'GpgSigningException: fail');
    });

    test('toString with cause', () {
      final e = GpgSigningException('fail', cause: Exception('inner'));
      expect(e.toString(), contains('fail'));
      expect(e.toString(), contains('inner'));
    });
  });

  group('RSA signing', () {
    late Map<String, dynamic> rsaJwk;
    late Uint8List secretMaterial;

    setUp(() {
      final pair = _generateRsaKeyPair(2048);
      final pub = pair.publicKey as RSAPublicKey;
      final priv = pair.privateKey as RSAPrivateKey;
      rsaJwk = _rsaPublicToJwk(pub);
      secretMaterial = _buildRsaSecretMaterial(priv);
    });

    test('signs sha256 hash and produces valid signature', () {
      final hash = _sha256Hash(Uint8List.fromList([1, 2, 3]));
      final sig = service.sign(
        hashBytes: hash,
        hashAlgorithm: 'sha256',
        secretMaterial: Uint8List.fromList(secretMaterial),
        publicKeyJwk: rsaJwk,
      );
      expect(sig, isNotNull);
      expect(sig!.length, 256); // 2048-bit → 256 bytes
    });

    test('signature is verifiable', () {
      final hash = _sha256Hash(Uint8List.fromList([4, 5, 6]));
      final sig = service.sign(
        hashBytes: hash,
        hashAlgorithm: 'sha256',
        secretMaterial: Uint8List.fromList(secretMaterial),
        publicKeyJwk: rsaJwk,
      )!;

      final n = _b64urlToBigInt(rsaJwk['n'] as String);
      final e = _b64urlToBigInt(rsaJwk['e'] as String);
      final pub = RSAPublicKey(n, e);
      final engine = PKCS1Encoding(RSAEngine());
      engine.init(false, PublicKeyParameter<RSAPublicKey>(pub));
      final decoded = engine.process(sig);

      final extractedHash = decoded.sublist(decoded.length - hash.length);
      expect(extractedHash, equals(hash));
    });

    test('sha384 signing works', () {
      final hash = Uint8List(48);
      final sig = service.sign(
        hashBytes: hash,
        hashAlgorithm: 'sha384',
        secretMaterial: Uint8List.fromList(secretMaterial),
        publicKeyJwk: rsaJwk,
      );
      expect(sig, isNotNull);
    });

    test('sha512 signing works', () {
      final hash = Uint8List(64);
      final sig = service.sign(
        hashBytes: hash,
        hashAlgorithm: 'sha512',
        secretMaterial: Uint8List.fromList(secretMaterial),
        publicKeyJwk: rsaJwk,
      );
      expect(sig, isNotNull);
    });

    test('sha1 signing works', () {
      final hash = Uint8List(20);
      final sig = service.sign(
        hashBytes: hash,
        hashAlgorithm: 'sha1',
        secretMaterial: Uint8List.fromList(secretMaterial),
        publicKeyJwk: rsaJwk,
      );
      expect(sig, isNotNull);
    });

    test('throws on unsupported hash algorithm', () {
      expect(
        () => service.sign(
          hashBytes: Uint8List(16),
          hashAlgorithm: 'md5',
          secretMaterial: Uint8List.fromList(secretMaterial),
          publicKeyJwk: rsaJwk,
        ),
        throwsA(isA<GpgSigningException>()),
      );
    });

    test('throws on encrypted key (S2K != 0)', () {
      final encrypted = Uint8List.fromList([0x03, ...secretMaterial.skip(1)]);
      expect(
        () => service.sign(
          hashBytes: Uint8List(32),
          hashAlgorithm: 'sha256',
          secretMaterial: encrypted,
          publicKeyJwk: rsaJwk,
        ),
        throwsA(isA<GpgSigningException>()),
      );
    });
  });

  group('ECDSA signing', () {
    late Map<String, dynamic> ecJwk;
    late Uint8List secretMaterial;
    late ECPublicKey ecPub;

    setUp(() {
      final pair = _generateEcKeyPair('secp256r1');
      ecPub = pair.publicKey as ECPublicKey;
      final ecPriv = pair.privateKey as ECPrivateKey;
      ecJwk = _ecPublicToJwk(ecPub, 'P-256', 32);
      secretMaterial = _buildEcdsaSecretMaterial(ecPriv);
    });

    test('signs sha256 and produces 64-byte raw signature', () {
      final hash = _sha256Hash(Uint8List.fromList([7, 8, 9]));
      final sig = service.sign(
        hashBytes: hash,
        hashAlgorithm: 'sha256',
        secretMaterial: Uint8List.fromList(secretMaterial),
        publicKeyJwk: ecJwk,
      );
      expect(sig, isNotNull);
      expect(sig!.length, 64);
    });

    test('P-256 signature is verifiable', () {
      final hash = _sha256Hash(Uint8List.fromList([10, 11, 12]));
      final sig = service.sign(
        hashBytes: hash,
        hashAlgorithm: 'sha256',
        secretMaterial: Uint8List.fromList(secretMaterial),
        publicKeyJwk: ecJwk,
      )!;

      final r = _bytesToBigInt(sig.sublist(0, 32));
      final s = _bytesToBigInt(sig.sublist(32, 64));
      final domain = ECDomainParameters('secp256r1');
      final verifier = ECDSASigner(null, null);
      verifier.init(
        false,
        PublicKeyParameter<ECPublicKey>(ECPublicKey(ecPub.Q, domain)),
      );
      expect(verifier.verifySignature(hash, ECSignature(r, s)), isTrue);
    });

    test('throws on encrypted key (S2K != 0)', () {
      final encrypted = Uint8List.fromList([0x03, ...secretMaterial.skip(1)]);
      expect(
        () => service.sign(
          hashBytes: Uint8List(32),
          hashAlgorithm: 'sha256',
          secretMaterial: encrypted,
          publicKeyJwk: ecJwk,
        ),
        throwsA(isA<GpgSigningException>()),
      );
    });

    test('throws on unsupported curve', () {
      final badJwk = {...ecJwk, 'crv': 'P-999'};
      expect(
        () => service.sign(
          hashBytes: Uint8List(32),
          hashAlgorithm: 'sha256',
          secretMaterial: Uint8List.fromList(secretMaterial),
          publicKeyJwk: badJwk,
        ),
        throwsA(isA<GpgSigningException>()),
      );
    });
  });

  group('unsupported algorithms', () {
    test('returns null for OKP (Ed25519)', () {
      final sig = service.sign(
        hashBytes: Uint8List(32),
        hashAlgorithm: 'sha256',
        secretMaterial: Uint8List.fromList([0x00, 0x00, 0x08, 0x42]),
        publicKeyJwk: {'kty': 'OKP', 'crv': 'Ed25519', 'x': 'AAAA'},
      );
      expect(sig, isNull);
    });

    test('returns null for unknown kty', () {
      final sig = service.sign(
        hashBytes: Uint8List(32),
        hashAlgorithm: 'sha256',
        secretMaterial: Uint8List(4),
        publicKeyJwk: {'kty': 'UNKNOWN'},
      );
      expect(sig, isNull);
    });
  });
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

AsymmetricKeyPair<PublicKey, PrivateKey> _generateRsaKeyPair(int bits) {
  final sr = _secureRandom();
  final keyGen = RSAKeyGenerator()
    ..init(
      ParametersWithRandom(
        RSAKeyGeneratorParameters(BigInt.from(65537), bits, 64),
        sr,
      ),
    );
  return keyGen.generateKeyPair();
}

AsymmetricKeyPair<PublicKey, PrivateKey> _generateEcKeyPair(String domain) {
  final sr = _secureRandom();
  final keyGen = ECKeyGenerator()
    ..init(
      ParametersWithRandom(
        ECKeyGeneratorParameters(ECDomainParameters(domain)),
        sr,
      ),
    );
  return keyGen.generateKeyPair();
}

FortunaRandom _secureRandom() {
  final sr = FortunaRandom();
  sr.seed(
    KeyParameter(
      Uint8List.fromList(
        List.generate(32, (_) => Random.secure().nextInt(256)),
      ),
    ),
  );
  return sr;
}

Uint8List _sha256Hash(Uint8List data) {
  final d = SHA256Digest();
  final out = Uint8List(d.digestSize);
  d.update(data, 0, data.length);
  d.doFinal(out, 0);
  return out;
}

Uint8List _buildRsaSecretMaterial(RSAPrivateKey priv) {
  final builder = BytesBuilder();
  builder.addByte(0x00);
  _writeMpi(builder, priv.privateExponent!);
  _writeMpi(builder, priv.p!);
  _writeMpi(builder, priv.q!);
  _writeMpi(builder, priv.p!.modInverse(priv.q!));
  builder.add([0x00, 0x00]);
  return builder.toBytes();
}

Uint8List _buildEcdsaSecretMaterial(ECPrivateKey priv) {
  final builder = BytesBuilder();
  builder.addByte(0x00);
  _writeMpi(builder, priv.d!);
  builder.add([0x00, 0x00]);
  return builder.toBytes();
}

void _writeMpi(BytesBuilder builder, BigInt value) {
  final bytes = _bigIntToMinBytes(value);
  final bitCount = value.bitLength;
  builder.addByte((bitCount >> 8) & 0xFF);
  builder.addByte(bitCount & 0xFF);
  builder.add(bytes);
}

Uint8List _bigIntToMinBytes(BigInt value) {
  if (value == BigInt.zero) return Uint8List.fromList([0]);
  final hex = value.toRadixString(16);
  final padded = hex.length.isOdd ? '0$hex' : hex;
  final bytes = Uint8List(padded.length ~/ 2);
  for (var i = 0; i < bytes.length; i++) {
    bytes[i] = int.parse(padded.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return bytes;
}

Map<String, dynamic> _rsaPublicToJwk(RSAPublicKey pub) {
  return {
    'kty': 'RSA',
    'n': _bigIntToB64url(pub.modulus!),
    'e': _bigIntToB64url(pub.publicExponent!),
  };
}

Map<String, dynamic> _ecPublicToJwk(ECPublicKey pub, String crv, int coordLen) {
  final encoded = pub.Q!.getEncoded(false);
  return {
    'kty': 'EC',
    'crv': crv,
    'x': _bytesToB64url(encoded.sublist(1, 1 + coordLen)),
    'y': _bytesToB64url(encoded.sublist(1 + coordLen, 1 + coordLen * 2)),
  };
}

String _bigIntToB64url(BigInt v) => _bytesToB64url(_bigIntToMinBytes(v));

String _bytesToB64url(List<int> bytes) {
  return base64Url.encode(bytes).replaceAll('=', '');
}

BigInt _bytesToBigInt(List<int> bytes) {
  var result = BigInt.zero;
  for (final b in bytes) {
    result = (result << 8) | BigInt.from(b);
  }
  return result;
}

BigInt _b64urlToBigInt(String encoded) {
  final padded = encoded + '=' * ((4 - encoded.length % 4) % 4);
  final bytes = base64Url.decode(padded);
  return _bytesToBigInt(bytes);
}
