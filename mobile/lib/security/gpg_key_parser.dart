import 'dart:developer' as developer;
import 'dart:typed_data';

import 'gpg_armor.dart';
import 'gpg_jwk_converter.dart';
import 'gpg_key_material.dart';
import 'gpg_key_models.dart';
import 'gpg_keygrip.dart';
import 'gpg_packet.dart';

/// Set of packet tags that represent key packets.
const _keyTags = {
  PacketTag.publicKey,
  PacketTag.publicSubkey,
  PacketTag.secretKey,
  PacketTag.secretSubkey,
};

/// Set of packet tags for subkeys.
const _subkeyTags = {PacketTag.publicSubkey, PacketTag.secretSubkey};

/// Parses an ASCII-armored GPG key block into a list of [GpgParsedKey].
///
/// Handles both public and private key armor types. Each public key,
/// secret key, and subkey packet in the block is extracted, parsed, and
/// converted to JWK format.
///
/// Unsupported algorithms are silently skipped with a log warning.
List<GpgParsedKey> parseGpgKeys(String armoredKey) {
  final binary = decodeAsciiArmor(armoredKey);
  final packets = parsePackets(binary);
  return _extractKeys(packets);
}

/// Parses raw binary OpenPGP data into a list of [GpgParsedKey].
///
/// Use this when you already have decoded binary data.
List<GpgParsedKey> parseGpgKeysFromBinary(Uint8List binary) {
  final packets = parsePackets(binary);
  return _extractKeys(packets);
}

/// Extracts keys from parsed packets.
List<GpgParsedKey> _extractKeys(List<GpgPacket> packets) {
  final keys = <GpgParsedKey>[];

  for (final packet in packets) {
    if (!_keyTags.contains(packet.tag)) continue;

    try {
      final parsed = _parseKeyPacket(packet);
      if (parsed != null) keys.add(parsed);
    } on FormatException catch (e) {
      developer.log(
        'skipping key packet (${packet.tag}): $e',
        name: 'gpg_key_parser',
      );
    }
  }

  return keys;
}

/// Parses a single key packet into a [GpgParsedKey], or returns `null`
/// if the algorithm is unsupported.
GpgParsedKey? _parseKeyPacket(GpgPacket packet) {
  final material = extractKeyMaterial(packet.body, packet.tag);

  Map<String, dynamic> jwk;
  try {
    jwk = keyMaterialToJwk(material.algorithm, material.params);
  } on FormatException catch (e) {
    developer.log(
      'unsupported algorithm ${material.algorithm} for JWK: $e',
      name: 'gpg_key_parser',
    );
    return null;
  }

  final keygrip = computeKeygrip(material.algorithm, material.params);
  final keyId = computeKeyId(packet.body);
  final isSubkey = _subkeyTags.contains(packet.tag);

  final secretMaterial = material.params['secretMaterial'] as Uint8List?;

  return GpgParsedKey(
    keygrip: keygrip,
    keyId: keyId,
    publicKeyJwk: jwk,
    algorithm: material.algorithm,
    isSubkey: isSubkey,
    secretKeyMaterial: secretMaterial,
  );
}
