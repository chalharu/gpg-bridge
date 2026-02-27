import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:gpg_bridge_mobile/security/gpg_armor.dart';

void main() {
  group('decodeAsciiArmor', () {
    test('decodes valid PGP PUBLIC KEY BLOCK without CRC', () {
      const armor =
          '-----BEGIN PGP PUBLIC KEY BLOCK-----\n'
          '\n'
          'AQID\n'
          '-----END PGP PUBLIC KEY BLOCK-----';

      final result = decodeAsciiArmor(armor);

      expect(result, equals(Uint8List.fromList([0x01, 0x02, 0x03])));
    });

    test('decodes valid PGP PRIVATE KEY BLOCK without CRC', () {
      const armor =
          '-----BEGIN PGP PRIVATE KEY BLOCK-----\n'
          '\n'
          'AQID\n'
          '-----END PGP PRIVATE KEY BLOCK-----';

      final result = decodeAsciiArmor(armor);

      expect(result, equals(Uint8List.fromList([0x01, 0x02, 0x03])));
    });

    test('throws FormatException on missing header', () {
      const armor =
          'AQID\n'
          '-----END PGP PUBLIC KEY BLOCK-----';

      expect(() => decodeAsciiArmor(armor), throwsA(isA<FormatException>()));
    });

    test('throws FormatException on missing footer', () {
      const armor =
          '-----BEGIN PGP PUBLIC KEY BLOCK-----\n'
          '\n'
          'AQID';

      expect(() => decodeAsciiArmor(armor), throwsA(isA<FormatException>()));
    });

    test('validates correct CRC24 checksum', () {
      // AQID = base64 of [1, 2, 3], CRC24 = 0x676193, base64 = Z2GT
      const armor =
          '-----BEGIN PGP PUBLIC KEY BLOCK-----\n'
          '\n'
          'AQID\n'
          '=Z2GT\n'
          '-----END PGP PUBLIC KEY BLOCK-----';

      final result = decodeAsciiArmor(armor);

      expect(result, equals(Uint8List.fromList([0x01, 0x02, 0x03])));
    });

    test('throws FormatException on invalid CRC24 checksum', () {
      const armor =
          '-----BEGIN PGP PUBLIC KEY BLOCK-----\n'
          '\n'
          'AQID\n'
          '=AAAA\n'
          '-----END PGP PUBLIC KEY BLOCK-----';

      expect(() => decodeAsciiArmor(armor), throwsA(isA<FormatException>()));
    });

    test('returns empty bytes for empty body', () {
      const armor =
          '-----BEGIN PGP PUBLIC KEY BLOCK-----\n'
          '\n'
          '\n'
          '-----END PGP PUBLIC KEY BLOCK-----';

      final result = decodeAsciiArmor(armor);

      expect(result, isEmpty);
    });

    test('strips metadata headers before decoding', () {
      const armor =
          '-----BEGIN PGP PUBLIC KEY BLOCK-----\n'
          'Version: GnuPG v2\n'
          'Comment: test key\n'
          '\n'
          'AQID\n'
          '-----END PGP PUBLIC KEY BLOCK-----';

      final result = decodeAsciiArmor(armor);

      expect(result, equals(Uint8List.fromList([0x01, 0x02, 0x03])));
    });

    test('handles multi-line base64 body', () {
      // 6 bytes [1,2,3,4,5,6] = base64 "AQIDBAUG" split across lines
      const armor =
          '-----BEGIN PGP PUBLIC KEY BLOCK-----\n'
          '\n'
          'AQID\n'
          'BAUG\n'
          '-----END PGP PUBLIC KEY BLOCK-----';

      final result = decodeAsciiArmor(armor);

      expect(
        result,
        equals(Uint8List.fromList([0x01, 0x02, 0x03, 0x04, 0x05, 0x06])),
      );
    });

    test('handles Windows line endings (CRLF)', () {
      const armor =
          '-----BEGIN PGP PUBLIC KEY BLOCK-----\r\n'
          '\r\n'
          'AQID\r\n'
          '-----END PGP PUBLIC KEY BLOCK-----';

      final result = decodeAsciiArmor(armor);

      expect(result, equals(Uint8List.fromList([0x01, 0x02, 0x03])));
    });
  });
}
