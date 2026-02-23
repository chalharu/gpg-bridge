import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:gpg_bridge_mobile/security/jwe_service.dart';

void main() {
  group('concatKdf edge cases', () {
    test('throws when keyBitLength > 256', () {
      expect(
        () => concatKdf(
          sharedSecret: Uint8List(32),
          algorithmId: 'ECDH-ES+A256KW',
          keyBitLength: 512,
        ),
        throwsA(
          isA<JweException>().having(
            (e) => e.message,
            'message',
            contains('multi-round derivation not implemented'),
          ),
        ),
      );
    });
  });

  group('aesKeyWrap edge cases', () {
    test('throws when key to wrap is not a multiple of 8 bytes', () {
      expect(
        () => aesKeyWrap(kek: Uint8List(32), keyToWrap: Uint8List(15)),
        throwsA(
          isA<JweException>().having(
            (e) => e.message,
            'message',
            contains('multiple of 8 bytes'),
          ),
        ),
      );
    });

    test('throws when key to wrap is less than 16 bytes', () {
      expect(
        () => aesKeyWrap(kek: Uint8List(32), keyToWrap: Uint8List(8)),
        throwsA(
          isA<JweException>().having(
            (e) => e.message,
            'message',
            contains('at least 16 bytes'),
          ),
        ),
      );
    });
  });

  group('aesKeyUnwrap edge cases', () {
    test('throws when wrapped key is less than 24 bytes', () {
      expect(
        () => aesKeyUnwrap(kek: Uint8List(32), wrappedKey: Uint8List(16)),
        throwsA(
          isA<JweException>().having(
            (e) => e.message,
            'message',
            contains('at least 24 bytes'),
          ),
        ),
      );
    });

    test('throws when wrapped key is not a multiple of 8 bytes', () {
      expect(
        () => aesKeyUnwrap(kek: Uint8List(32), wrappedKey: Uint8List(25)),
        throwsA(
          isA<JweException>().having(
            (e) => e.message,
            'message',
            contains('multiple of 8 bytes'),
          ),
        ),
      );
    });
  });

  group('EcPublicJwk.fromJson coordinate validation', () {
    test('throws when x coordinate has wrong length', () {
      expect(
        () => EcPublicJwk.fromJson({
          'kty': 'EC',
          'crv': 'P-256',
          'x': 'AAAA',
          'y': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        }),
        throwsA(
          isA<JweException>().having(
            (e) => e.message,
            'message',
            contains('invalid P-256 coordinate length'),
          ),
        ),
      );
    });

    test('throws when y coordinate has wrong length', () {
      expect(
        () => EcPublicJwk.fromJson({
          'kty': 'EC',
          'crv': 'P-256',
          'x': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
          'y': 'AAAA',
        }),
        throwsA(
          isA<JweException>().having(
            (e) => e.message,
            'message',
            contains('invalid P-256 coordinate length'),
          ),
        ),
      );
    });
  });
}
