import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:gpg_bridge_mobile/security/gpg_key_models.dart';
import 'package:gpg_bridge_mobile/security/gpg_key_parser.dart';

void main() {
  /// Builds a minimal V4 RSA public key packet body.
  Uint8List buildRsaKeyBody() {
    return Uint8List.fromList([
      0x04, // version 4
      0x60, 0x00, 0x00, 0x00, // creation time
      0x01, // RSA algorithm
      0x00, 0x09, 0x01, 0x00, // MPI n = 256
      0x00, 0x11, 0x01, 0x00, 0x01, // MPI e = 65537
    ]);
  }

  /// Wraps a body in an old-format public key packet (tag 6).
  Uint8List wrapInOldFormatPacket(Uint8List body, {int tag = 6}) {
    final header = 0x80 | (tag << 2) | 0; // old format, 1-byte length
    return Uint8List.fromList([header, body.length, ...body]);
  }

  /// Wraps binary data in ASCII armor.
  String armorBinary(Uint8List binary, {String type = 'PUBLIC KEY BLOCK'}) {
    final b64 = base64.encode(binary);
    return '-----BEGIN PGP $type-----\n\n$b64\n-----END PGP $type-----';
  }

  group('parseGpgKeys', () {
    test('parses armored RSA public key', () {
      final body = buildRsaKeyBody();
      final packet = wrapInOldFormatPacket(body);
      final armored = armorBinary(packet);

      final keys = parseGpgKeys(armored);

      expect(keys, hasLength(1));
      expect(keys[0].algorithm, GpgKeyAlgorithm.rsa);
      expect(keys[0].keygrip.length, 40);
      expect(keys[0].keyId.length, 16);
      expect(keys[0].publicKeyJwk['kty'], 'RSA');
      expect(keys[0].isSubkey, isFalse);
    });

    test('throws FormatException for invalid armor', () {
      expect(
        () => parseGpgKeys('not valid armor'),
        throwsA(isA<FormatException>()),
      );
    });

    test('returns empty list for unsupported algorithm packet', () {
      // DSA (tag value 17): algorithm byte = 17
      final body = Uint8List.fromList([
        0x04, // version 4
        0x00, 0x00, 0x00, 0x00,
        17, // DSA — unsupported for JWK conversion
        // Minimal additional bytes so it can attempt parsing
        0x00, 0x01, 0x01, // a semi-valid MPI
      ]);
      final packet = wrapInOldFormatPacket(body);
      final armored = armorBinary(packet);

      // DSA extraction is not implemented, so the key is skipped
      final keys = parseGpgKeys(armored);

      expect(keys, isEmpty);
    });

    test('parses subkey packets', () {
      final body = buildRsaKeyBody();
      // Public subkey = tag 14: 0x80 | (14 << 2) | 0 = 0xB8
      final packet = wrapInOldFormatPacket(body, tag: 14);
      final armored = armorBinary(packet);

      final keys = parseGpgKeys(armored);

      expect(keys, hasLength(1));
      expect(keys[0].isSubkey, isTrue);
    });

    test('parses multiple key packets in one armored block', () {
      final body = buildRsaKeyBody();
      final primaryPacket = wrapInOldFormatPacket(body, tag: 6);
      final subkeyPacket = wrapInOldFormatPacket(body, tag: 14);
      final combined = Uint8List.fromList([...primaryPacket, ...subkeyPacket]);
      final armored = armorBinary(combined);

      final keys = parseGpgKeys(armored);

      expect(keys, hasLength(2));
      expect(keys[0].isSubkey, isFalse);
      expect(keys[1].isSubkey, isTrue);
    });
  });

  group('parseGpgKeysFromBinary', () {
    test('parses raw binary RSA public key', () {
      final body = buildRsaKeyBody();
      final packet = wrapInOldFormatPacket(body);

      final keys = parseGpgKeysFromBinary(packet);

      expect(keys, hasLength(1));
      expect(keys[0].algorithm, GpgKeyAlgorithm.rsa);
      expect(keys[0].publicKeyJwk['kty'], 'RSA');
    });

    test('returns empty list for empty binary', () {
      final keys = parseGpgKeysFromBinary(Uint8List(0));

      expect(keys, isEmpty);
    });

    test('skips non-key packets', () {
      // Signature packet (tag 2): 0x80 | (2 << 2) | 0 = 0x88
      final sigPacket = Uint8List.fromList([0x88, 0x02, 0x00, 0x00]);
      final body = buildRsaKeyBody();
      final keyPacket = wrapInOldFormatPacket(body);
      final combined = Uint8List.fromList([...sigPacket, ...keyPacket]);

      final keys = parseGpgKeysFromBinary(combined);

      // Only the key packet is returned, signature is skipped
      expect(keys, hasLength(1));
    });
  });

  group('GpgParsedKey', () {
    test('has expected fields', () {
      final body = buildRsaKeyBody();
      final packet = wrapInOldFormatPacket(body);
      final keys = parseGpgKeysFromBinary(packet);

      final key = keys[0];
      expect(key.keygrip, isNotEmpty);
      expect(key.keyId, isNotEmpty);
      expect(key.publicKeyJwk, isNotEmpty);
      expect(key.algorithm, isNotNull);
      expect(key.secretKeyMaterial, isNull);
    });
  });
}
