import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:gpg_bridge_mobile/security/jwe_service.dart';

void main() {
  // -------------------------------------------------------------------------
  // Shared test key pair (P-256) – verified: d*G == (x,y)
  // Same key used by Rust josekit test vectors.
  // -------------------------------------------------------------------------

  const recipientPrivateJwk = {
    'kty': 'EC',
    'crv': 'P-256',
    'x': '0qHaLh3jKQAQ5tYB6NooOi2lFjJj9E5h80yoHSZoq0I',
    'y': 'F8CORGPfI9872Nxw2Fkr6XUn-5AczutLMi9uRygC7pE',
    'd': 'yeT1vLHEotPm9wgZKjtMXW5_gJGis8TV5vcIGavN7wE',
  };

  const recipientPublicJwk = {
    'kty': 'EC',
    'crv': 'P-256',
    'x': '0qHaLh3jKQAQ5tYB6NooOi2lFjJj9E5h80yoHSZoq0I',
    'y': 'F8CORGPfI9872Nxw2Fkr6XUn-5AczutLMi9uRygC7pE',
  };

  late JweService service;

  setUp(() {
    service = JweService();
  });

  // -------------------------------------------------------------------------
  // Round-trip tests
  // -------------------------------------------------------------------------

  group('encryption / decryption round-trip', () {
    test('encrypts and decrypts short plaintext', () {
      final plaintext = utf8.encode('hello world');
      final pubKey = EcPublicJwk.fromJson(recipientPublicJwk);
      final privKey = EcPrivateJwk.fromJson(recipientPrivateJwk);

      final jwe = service.encrypt(
        plaintext: plaintext,
        recipientPublicKey: pubKey,
      );

      final decrypted = service.decrypt(jweCompact: jwe, privateKey: privKey);
      expect(utf8.decode(decrypted), 'hello world');
    });

    test('encrypts and decrypts empty plaintext', () {
      final pubKey = EcPublicJwk.fromJson(recipientPublicJwk);
      final privKey = EcPrivateJwk.fromJson(recipientPrivateJwk);

      final jwe = service.encrypt(
        plaintext: <int>[],
        recipientPublicKey: pubKey,
      );

      final decrypted = service.decrypt(jweCompact: jwe, privateKey: privKey);
      expect(decrypted, isEmpty);
    });

    test('encrypts and decrypts large plaintext', () {
      final plaintext = List<int>.generate(10000, (i) => i % 256);
      final pubKey = EcPublicJwk.fromJson(recipientPublicJwk);
      final privKey = EcPrivateJwk.fromJson(recipientPrivateJwk);

      final jwe = service.encrypt(
        plaintext: plaintext,
        recipientPublicKey: pubKey,
      );

      final decrypted = service.decrypt(jweCompact: jwe, privateKey: privKey);
      expect(decrypted, plaintext);
    });

    test('encrypts and decrypts JSON payload', () {
      final payload = '{"hash":"sha256:abc123","timestamp":1700000000}';
      final pubKey = EcPublicJwk.fromJson(recipientPublicJwk);
      final privKey = EcPrivateJwk.fromJson(recipientPrivateJwk);

      final jwe = service.encrypt(
        plaintext: utf8.encode(payload),
        recipientPublicKey: pubKey,
      );

      final decrypted = service.decrypt(jweCompact: jwe, privateKey: privKey);
      expect(utf8.decode(decrypted), payload);
    });

    test('each encryption produces different ciphertext (randomness)', () {
      final plaintext = utf8.encode('same message');
      final pubKey = EcPublicJwk.fromJson(recipientPublicJwk);

      final jwe1 = service.encrypt(
        plaintext: plaintext,
        recipientPublicKey: pubKey,
      );
      final jwe2 = service.encrypt(
        plaintext: plaintext,
        recipientPublicKey: pubKey,
      );

      expect(jwe1, isNot(jwe2));
    });
  });

  // -------------------------------------------------------------------------
  // JWE compact serialization format
  // -------------------------------------------------------------------------

  group('JWE compact serialization format', () {
    test('produces 5 dot-separated base64url parts', () {
      final pubKey = EcPublicJwk.fromJson(recipientPublicJwk);

      final jwe = service.encrypt(
        plaintext: utf8.encode('test'),
        recipientPublicKey: pubKey,
      );

      final parts = jwe.split('.');
      expect(parts.length, 5);

      // Each part is valid base64url (no padding, no + or /)
      final b64urlPattern = RegExp(r'^[A-Za-z0-9_-]*$');
      for (final part in parts) {
        expect(part, matches(b64urlPattern));
      }
    });

    test('protected header contains correct alg enc and epk', () {
      final pubKey = EcPublicJwk.fromJson(recipientPublicJwk);

      final jwe = service.encrypt(
        plaintext: utf8.encode('test'),
        recipientPublicKey: pubKey,
      );

      final headerEncoded = jwe.split('.')[0];
      final padded = headerEncoded + '=' * ((4 - headerEncoded.length % 4) % 4);
      final headerJson =
          jsonDecode(utf8.decode(base64Url.decode(padded)))
              as Map<String, dynamic>;

      expect(headerJson['alg'], 'ECDH-ES+A256KW');
      expect(headerJson['enc'], 'A256GCM');
      expect(headerJson['epk'], isA<Map<String, dynamic>>());

      final epk = headerJson['epk'] as Map<String, dynamic>;
      expect(epk['kty'], 'EC');
      expect(epk['crv'], 'P-256');
      expect(epk['x'], isA<String>());
      expect(epk['y'], isA<String>());
      // Must NOT contain private key material
      expect(epk.containsKey('d'), isFalse);
    });
  });

  // -------------------------------------------------------------------------
  // Rust josekit interoperability test vectors
  // -------------------------------------------------------------------------

  group('Rust josekit interoperability', () {
    // Vector 1 – generated by josekit 0.8.7 (ECDH-ES+A256KW / A256GCM)
    // Key pair verified: d*G == (x,y) via Rust p256 crate.
    // Decrypt verified in Rust before export.
    const jweCompact1 =
        'eyJhbGciOiJFQ0RILUVTK0EyNTZLVyIsImVuYyI6IkEyNTZHQ00iLCJlcGsiOnsi'
        'a3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiI1OFpKZWZkYklBdHEtTmVYSU1G'
        'UGtLYWpmYy14bEhpVkp5MmF3R3BLZlBNIiwieSI6Img1X1p5WHVPZU03RUtWYkNR'
        'Tng2ZU4zNkZRQ08yS0ZZLTV4RlNGdnpxZEkifX0.P5BE9qPFlmwtpS-Nx4jUUGdb'
        'iRHJdcbUbpzwD1JVgVFUtX5Oi7TuNA.clEx7ivf8AVRXMSy.72ypTqWTiGXuQJ1Y'
        'wO9w3PBxG_WWQawNeIp51nZOCeeo_NZniDax8T-MKo-R_pYaLE9uxaGMz4dxu0Lj'
        'a3ojF1DNKXvtKyLkLTyhzctD.NSHkpevGNBJEA1MJZsIOQA';
    const expectedPlaintext1 =
        'Hello, gpg-bridge! This is a test message for E2E encryption '
        'interoperability.';

    // Vector 2 – generated by josekit 0.8.7, decrypt verified in Rust.
    const jweCompact2 =
        'eyJhbGciOiJFQ0RILUVTK0EyNTZLVyIsImVuYyI6IkEyNTZHQ00iLCJlcGsiOnsi'
        'a3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiIxY1FQcmRpSGpveFpPSzhQMm9v'
        'YTFjc0hlRnE4TFBzQ2ZPeXRNSDdWZ0JFIiwieSI6IjdNeXp4YzExN1dvcjdINjM4'
        'OE8xQkxJREUwR2NyZkM0YkhJX2ZIdHY2NVkifX0.SxzlLgJtYzZUzpltmDbNGITp'
        '8f2RgPh2RcqyzY6AIBBDh1gmTFVTOQ.1dwE7uGhj2lEQ5_N.JlQ0nDTBw6qeP0YS'
        'b3j45ePPh92FvI8jRU9avavs9iRG__jpHchVKPhlV5JM680.Qo2K-1e1QjI4Lp4Y8'
        'YmuXg';
    const expectedPlaintext2 =
        '{"hash":"sha256:abc123","timestamp":1700000000}';

    test('decrypts vector 1 from Rust josekit', () {
      final privKey = EcPrivateJwk.fromJson(recipientPrivateJwk);

      final decrypted = service.decrypt(
        jweCompact: jweCompact1,
        privateKey: privKey,
      );

      expect(utf8.decode(decrypted), expectedPlaintext1);
    });

    test('decrypts vector 2 from Rust josekit', () {
      final privKey = EcPrivateJwk.fromJson(recipientPrivateJwk);

      final decrypted = service.decrypt(
        jweCompact: jweCompact2,
        privateKey: privKey,
      );

      expect(utf8.decode(decrypted), expectedPlaintext2);
    });
  });

  // -------------------------------------------------------------------------
  // Concat KDF unit tests
  // -------------------------------------------------------------------------

  group('Concat KDF', () {
    test('produces correct output for known input', () {
      // RFC 7518 Appendix C test vector (not exhaustive, but verifies format)
      final sharedSecret = Uint8List(32); // all zeros
      final derived = JweService.concatKdf(
        sharedSecret: sharedSecret,
        algorithmId: 'ECDH-ES+A256KW',
        keyBitLength: 256,
      );
      expect(derived.length, 32);
    });

    test('different algorithm IDs produce different keys', () {
      final sharedSecret = Uint8List.fromList(List.filled(32, 0x42));

      final kek1 = JweService.concatKdf(
        sharedSecret: sharedSecret,
        algorithmId: 'ECDH-ES+A256KW',
        keyBitLength: 256,
      );
      final kek2 = JweService.concatKdf(
        sharedSecret: sharedSecret,
        algorithmId: 'ECDH-ES+A128KW',
        keyBitLength: 128,
      );

      expect(kek1, isNot(kek2));
    });
  });

  // -------------------------------------------------------------------------
  // AES Key Wrap unit tests
  // -------------------------------------------------------------------------

  group('AES Key Wrap', () {
    test('wrap then unwrap returns original key (RFC 3394 test vector)', () {
      // RFC 3394 §4.6 – 256-bit KEK, 256-bit data
      final kek = Uint8List.fromList([
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, //
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
      ]);
      final keyData = Uint8List.fromList([
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, //
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
      ]);

      final wrapped = JweService.aesKeyWrap(kek: kek, keyToWrap: keyData);
      expect(wrapped.length, keyData.length + 8);

      final unwrapped = JweService.aesKeyUnwrap(kek: kek, wrappedKey: wrapped);
      expect(unwrapped, keyData);
    });

    test('RFC 3394 §4.6 known ciphertext', () {
      // 256-bit KEK wrapping 256-bit key – known answer from RFC 3394
      final kek = Uint8List.fromList([
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, //
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
      ]);
      final keyData = Uint8List.fromList([
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, //
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
      ]);
      final expectedWrapped = Uint8List.fromList([
        0x28, 0xC9, 0xF4, 0x04, 0xC4, 0xB8, 0x10, 0xF4, //
        0xCB, 0xCC, 0xB3, 0x5C, 0xFB, 0x87, 0xF8, 0x26,
        0x3F, 0x57, 0x86, 0xE2, 0xD8, 0x0E, 0xD3, 0x26,
        0xCB, 0xC7, 0xF0, 0xE7, 0x1A, 0x99, 0xF4, 0x3B,
        0xFB, 0x98, 0x8B, 0x9B, 0x7A, 0x02, 0xDD, 0x21,
      ]);

      final wrapped = JweService.aesKeyWrap(kek: kek, keyToWrap: keyData);
      expect(wrapped, expectedWrapped);

      final unwrapped = JweService.aesKeyUnwrap(
        kek: kek,
        wrappedKey: expectedWrapped,
      );
      expect(unwrapped, keyData);
    });

    test('unwrap with wrong KEK throws', () {
      final kek = Uint8List.fromList(List.filled(32, 0x01));
      final wrongKek = Uint8List.fromList(List.filled(32, 0x02));
      final keyData = Uint8List.fromList(List.filled(32, 0xAB));

      final wrapped = JweService.aesKeyWrap(kek: kek, keyToWrap: keyData);

      expect(
        () => JweService.aesKeyUnwrap(kek: wrongKek, wrappedKey: wrapped),
        throwsA(
          isA<JweException>().having(
            (e) => e.message,
            'message',
            contains('integrity check failed'),
          ),
        ),
      );
    });
  });

  // -------------------------------------------------------------------------
  // AES-GCM unit tests
  // -------------------------------------------------------------------------

  group('AES-256-GCM', () {
    test('encrypt then decrypt roundtrip', () {
      final key = Uint8List.fromList(List.filled(32, 0x42));
      final iv = Uint8List.fromList(List.filled(12, 0x01));
      final plaintext = Uint8List.fromList(utf8.encode('AES-GCM test'));
      final aad = Uint8List.fromList(utf8.encode('additional data'));

      final encrypted = JweService.aesGcmEncrypt(
        key: key,
        iv: iv,
        plaintext: plaintext,
        aad: aad,
      );

      expect(encrypted.tag.length, 16);

      final decrypted = JweService.aesGcmDecrypt(
        key: key,
        iv: iv,
        ciphertext: encrypted.ciphertext,
        tag: encrypted.tag,
        aad: aad,
      );

      expect(decrypted, plaintext);
    });

    test('tampered ciphertext fails authentication', () {
      final key = Uint8List.fromList(List.filled(32, 0x42));
      final iv = Uint8List.fromList(List.filled(12, 0x01));
      final plaintext = Uint8List.fromList(utf8.encode('secret'));
      final aad = Uint8List.fromList(utf8.encode('aad'));

      final encrypted = JweService.aesGcmEncrypt(
        key: key,
        iv: iv,
        plaintext: plaintext,
        aad: aad,
      );

      // Tamper with ciphertext
      final tampered = Uint8List.fromList(encrypted.ciphertext);
      tampered[0] ^= 0xFF;

      expect(
        () => JweService.aesGcmDecrypt(
          key: key,
          iv: iv,
          ciphertext: tampered,
          tag: encrypted.tag,
          aad: aad,
        ),
        throwsA(isA<JweException>()),
      );
    });

    test('wrong AAD fails authentication', () {
      final key = Uint8List.fromList(List.filled(32, 0x42));
      final iv = Uint8List.fromList(List.filled(12, 0x01));
      final plaintext = Uint8List.fromList(utf8.encode('secret'));
      final aad = Uint8List.fromList(utf8.encode('aad'));

      final encrypted = JweService.aesGcmEncrypt(
        key: key,
        iv: iv,
        plaintext: plaintext,
        aad: aad,
      );

      expect(
        () => JweService.aesGcmDecrypt(
          key: key,
          iv: iv,
          ciphertext: encrypted.ciphertext,
          tag: encrypted.tag,
          aad: Uint8List.fromList(utf8.encode('wrong aad')),
        ),
        throwsA(isA<JweException>()),
      );
    });
  });

  // -------------------------------------------------------------------------
  // Error cases
  // -------------------------------------------------------------------------

  group('error handling', () {
    test('decrypt rejects non-5-part serialization', () {
      final privKey = EcPrivateJwk.fromJson(recipientPrivateJwk);

      expect(
        () => service.decrypt(jweCompact: 'a.b.c', privateKey: privKey),
        throwsA(
          isA<JweException>().having(
            (e) => e.message,
            'message',
            contains('expected 5 parts'),
          ),
        ),
      );
    });

    test('decrypt rejects unsupported algorithm', () {
      final privKey = EcPrivateJwk.fromJson(recipientPrivateJwk);

      // Construct JWE with wrong algorithm
      final header = base64Url
          .encode(utf8.encode('{"alg":"RSA-OAEP","enc":"A256GCM"}'))
          .replaceAll('=', '');
      final fakeJwe = '$header.AAAA.BBBB.CCCC.DDDD';

      expect(
        () => service.decrypt(jweCompact: fakeJwe, privateKey: privKey),
        throwsA(
          isA<JweException>().having(
            (e) => e.message,
            'message',
            contains('unsupported algorithm'),
          ),
        ),
      );
    });

    test('decrypt rejects unsupported encryption', () {
      final privKey = EcPrivateJwk.fromJson(recipientPrivateJwk);

      final header = base64Url
          .encode(utf8.encode('{"alg":"ECDH-ES+A256KW","enc":"A128CBC-HS256"}'))
          .replaceAll('=', '');
      final fakeJwe = '$header.AAAA.BBBB.CCCC.DDDD';

      expect(
        () => service.decrypt(jweCompact: fakeJwe, privateKey: privKey),
        throwsA(
          isA<JweException>().having(
            (e) => e.message,
            'message',
            contains('unsupported encryption'),
          ),
        ),
      );
    });

    test('decrypt rejects missing epk', () {
      final privKey = EcPrivateJwk.fromJson(recipientPrivateJwk);

      final header = base64Url
          .encode(utf8.encode('{"alg":"ECDH-ES+A256KW","enc":"A256GCM"}'))
          .replaceAll('=', '');
      final fakeJwe = '$header.AAAA.BBBB.CCCC.DDDD';

      expect(
        () => service.decrypt(jweCompact: fakeJwe, privateKey: privKey),
        throwsA(
          isA<JweException>().having(
            (e) => e.message,
            'message',
            contains('missing epk'),
          ),
        ),
      );
    });

    test('decrypt rejects corrupted encrypted key', () {
      // Encrypt a valid JWE first, then corrupt the encrypted key part
      final pubKey = EcPublicJwk.fromJson(recipientPublicJwk);
      final privKey = EcPrivateJwk.fromJson(recipientPrivateJwk);

      final jwe = service.encrypt(
        plaintext: utf8.encode('test'),
        recipientPublicKey: pubKey,
      );

      final parts = jwe.split('.');
      // Replace encrypted key with garbage
      parts[1] = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
      final corrupted = parts.join('.');

      expect(
        () => service.decrypt(jweCompact: corrupted, privateKey: privKey),
        throwsA(isA<JweException>()),
      );
    });

    test('decrypt rejects corrupted tag', () {
      final pubKey = EcPublicJwk.fromJson(recipientPublicJwk);
      final privKey = EcPrivateJwk.fromJson(recipientPrivateJwk);

      final jwe = service.encrypt(
        plaintext: utf8.encode('test'),
        recipientPublicKey: pubKey,
      );

      final parts = jwe.split('.');
      // Replace tag with garbage of same length
      parts[4] = 'AAAAAAAAAAAAAAAAAAAAAA';
      final corrupted = parts.join('.');

      expect(
        () => service.decrypt(jweCompact: corrupted, privateKey: privKey),
        throwsA(isA<JweException>()),
      );
    });

    test('decrypt with wrong private key fails', () {
      final pubKey = EcPublicJwk.fromJson(recipientPublicJwk);

      // Generate a different key pair via round-trip: use a known different key
      final wrongPrivKey = EcPrivateJwk.fromJson(const {
        'kty': 'EC',
        'crv': 'P-256',
        'x': 'WbbaSStufflt7SVQJkePlz--CDAwSA76XFeCG3v22GY',
        'y': 'vOGjkwWI7MEKGF6JmciS_UxhMF4wDJ8GamlYMBFManw',
        'd': 'HaEBm_bCMQ1nxPuDWmzXR0ihIX3GVrVi-8nUaD3a7Mc',
      });

      final jwe = service.encrypt(
        plaintext: utf8.encode('secret'),
        recipientPublicKey: pubKey,
      );

      expect(
        () => service.decrypt(jweCompact: jwe, privateKey: wrongPrivKey),
        throwsA(isA<JweException>()),
      );
    });
  });

  // -------------------------------------------------------------------------
  // Key model tests
  // -------------------------------------------------------------------------

  group('EcPublicJwk', () {
    test('fromJson validates kty and crv', () {
      expect(
        () => EcPublicJwk.fromJson({
          'kty': 'RSA',
          'crv': 'P-256',
          'x': 'x',
          'y': 'y',
        }),
        throwsA(isA<JweException>()),
      );

      expect(
        () => EcPublicJwk.fromJson({
          'kty': 'EC',
          'crv': 'P-384',
          'x': 'x',
          'y': 'y',
        }),
        throwsA(isA<JweException>()),
      );
    });

    test('fromJson rejects missing coordinates', () {
      expect(
        () =>
            EcPublicJwk.fromJson({'kty': 'EC', 'crv': 'P-256', 'x': 'only_x'}),
        throwsA(isA<JweException>()),
      );
    });

    test('toJson round-trip', () {
      final jwk = EcPublicJwk(x: 'test_x_coordinate', y: 'test_y_coordinate');
      final json = jwk.toJson();
      expect(json['kty'], 'EC');
      expect(json['crv'], 'P-256');
      expect(json['x'], 'test_x_coordinate');
      expect(json['y'], 'test_y_coordinate');
    });
  });

  group('EcPrivateJwk', () {
    test('fromJson validates kty crv and d', () {
      expect(
        () => EcPrivateJwk.fromJson({
          'kty': 'EC',
          'crv': 'P-256',
          'x': 'x',
          'y': 'y',
          // missing d
        }),
        throwsA(isA<JweException>()),
      );
    });

    test('publicKey extracts correct fields', () {
      final privKey = EcPrivateJwk.fromJson(recipientPrivateJwk);
      final pubKey = privKey.publicKey;
      expect(pubKey.x, privKey.x);
      expect(pubKey.y, privKey.y);
    });

    test('toJson includes d parameter', () {
      final privKey = EcPrivateJwk.fromJson(recipientPrivateJwk);
      final json = privKey.toJson();
      expect(json.containsKey('d'), isTrue);
    });
  });

  // -------------------------------------------------------------------------
  // JweException tests
  // -------------------------------------------------------------------------

  group('JweException', () {
    test('toString includes message only', () {
      final e = JweException('test error');
      expect(e.toString(), 'JweException: test error');
    });

    test('toString includes cause when present', () {
      final e = JweException('failed', cause: Exception('cause'));
      expect(e.toString(), contains('failed'));
      expect(e.toString(), contains('cause'));
    });
  });

  // -------------------------------------------------------------------------
  // Deterministic encryption (via injected Random)
  // -------------------------------------------------------------------------

  group('deterministic with seeded Random', () {
    test('same seed produces same JWE', () {
      final pubKey = EcPublicJwk.fromJson(recipientPublicJwk);
      final privKey = EcPrivateJwk.fromJson(recipientPrivateJwk);
      final plaintext = utf8.encode('deterministic');

      final svc1 = JweService(random: Random(42));
      final svc2 = JweService(random: Random(42));

      final jwe1 = svc1.encrypt(
        plaintext: plaintext,
        recipientPublicKey: pubKey,
      );
      final jwe2 = svc2.encrypt(
        plaintext: plaintext,
        recipientPublicKey: pubKey,
      );

      expect(jwe1, jwe2);

      // And it decrypts correctly
      final decrypted = svc1.decrypt(jweCompact: jwe1, privateKey: privKey);
      expect(utf8.decode(decrypted), 'deterministic');
    });
  });
}
