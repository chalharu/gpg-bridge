import 'dart:convert';

import 'package:flutter/services.dart';

class KeystorePlatformException implements Exception {
  KeystorePlatformException(this.message, {this.cause});

  final String message;
  final Object? cause;

  @override
  String toString() {
    if (cause == null) {
      return 'KeystorePlatformException: $message';
    }
    return 'KeystorePlatformException: $message ($cause)';
  }
}

abstract final class KeystoreAliases {
  static const String deviceKey = 'device_key';
  static const String e2eKey = 'e2e_key';

  static bool isSupported(String alias) {
    return alias == deviceKey || alias == e2eKey;
  }
}

abstract interface class KeystorePlatformService {
  Future<void> generateKeyPair({required String alias});
  Future<String> sign({required String alias, required List<int> data});
  Future<bool> verify({
    required String alias,
    required List<int> data,
    required String signatureBase64,
  });
  Future<Map<String, String>> getPublicKeyJwk({required String alias});
}

class MethodChannelKeystorePlatformService implements KeystorePlatformService {
  MethodChannelKeystorePlatformService([MethodChannel? channel])
    : _channel = channel ?? const MethodChannel(_channelName);

  static const String _channelName = 'gpg_bridge/keystore';

  final MethodChannel _channel;

  @override
  Future<void> generateKeyPair({required String alias}) async {
    _assertSupportedAlias(alias);

    final generated = await _guardPlatformCall<bool>(
      operation: 'generate key pair',
      call: () =>
          _channel.invokeMethod<bool>('generateKeyPair', {'alias': alias}),
    );

    if (generated != true) {
      throw KeystorePlatformException('invalid generate key pair response');
    }
  }

  @override
  Future<String> sign({required String alias, required List<int> data}) async {
    _assertSignAlias(alias);

    final signatureBase64 = await _guardPlatformCall<String>(
      operation: 'sign data',
      call: () => _channel.invokeMethod<String>('sign', {
        'alias': alias,
        'dataBase64': base64Encode(data),
      }),
    );

    if (signatureBase64 == null || signatureBase64.isEmpty) {
      throw KeystorePlatformException('signature is empty');
    }

    return signatureBase64;
  }

  @override
  Future<bool> verify({
    required String alias,
    required List<int> data,
    required String signatureBase64,
  }) async {
    _assertSignAlias(alias);
    _assertNonEmptySignature(signatureBase64);

    final verified = await _guardPlatformCall<bool>(
      operation: 'verify signature',
      call: () => _channel.invokeMethod<bool>('verify', {
        'alias': alias,
        'dataBase64': base64Encode(data),
        'signatureBase64': signatureBase64,
      }),
    );

    return verified ?? false;
  }

  @override
  Future<Map<String, String>> getPublicKeyJwk({required String alias}) async {
    _assertSupportedAlias(alias);

    final jwk = await _guardPlatformCall<Map<String, String>>(
      operation: 'get public key jwk',
      call: () => _channel.invokeMapMethod<String, String>('getPublicKeyJwk', {
        'alias': alias,
      }),
    );

    if (jwk == null || jwk.isEmpty) {
      throw KeystorePlatformException('public key jwk is empty');
    }

    try {
      _assertValidJwk(alias, jwk);
    } catch (error) {
      if (error is KeystorePlatformException) {
        rethrow;
      }
      throw KeystorePlatformException(
        'unexpected platform response while trying to get public key jwk',
        cause: error,
      );
    }

    return jwk;
  }

  Future<T?> _guardPlatformCall<T>({
    required String operation,
    required Future<T?> Function() call,
  }) async {
    try {
      return await call();
    } on PlatformException catch (error) {
      throw KeystorePlatformException('failed to $operation', cause: error);
    } on MissingPluginException catch (error) {
      throw KeystorePlatformException(
        'keystore platform channel is unavailable',
        cause: error,
      );
    } catch (error) {
      throw KeystorePlatformException(
        'unexpected platform response while trying to $operation',
        cause: error,
      );
    }
  }

  void _assertSupportedAlias(String alias) {
    if (!KeystoreAliases.isSupported(alias)) {
      throw KeystorePlatformException('unsupported alias: $alias');
    }
  }

  /// Restricts sign/verify to device_key only.
  /// Currently only device_assertion_jwt requires signing.
  /// If E2E key signing is needed in the future, extend this check.
  void _assertSignAlias(String alias) {
    if (alias != KeystoreAliases.deviceKey) {
      throw KeystorePlatformException(
        'alias does not support sign/verify: $alias',
      );
    }
  }

  void _assertValidJwk(String alias, Map<String, String> jwk) {
    if (jwk['kty'] != 'EC') {
      throw KeystorePlatformException('invalid jwk kty');
    }
    if (jwk['crv'] != 'P-256') {
      throw KeystorePlatformException('invalid jwk crv');
    }

    final expectedUse = alias == KeystoreAliases.deviceKey ? 'sig' : 'enc';
    final expectedAlg = alias == KeystoreAliases.deviceKey
        ? 'ES256'
        : 'ECDH-ES+A256KW';

    if (jwk['use'] != expectedUse) {
      throw KeystorePlatformException('invalid jwk use');
    }
    if (jwk['alg'] != expectedAlg) {
      throw KeystorePlatformException('invalid jwk alg');
    }

    _assertBase64UrlCoordinate(jwk['x'], 'x');
    _assertBase64UrlCoordinate(jwk['y'], 'y');
  }

  void _assertNonEmptySignature(String signatureBase64) {
    if (signatureBase64.isEmpty) {
      throw KeystorePlatformException('signature is empty');
    }
  }

  void _assertBase64UrlCoordinate(String? value, String name) {
    final pattern = RegExp(r'^[A-Za-z0-9_-]{43}$');
    if (value == null || !pattern.hasMatch(value)) {
      throw KeystorePlatformException('invalid jwk $name coordinate');
    }
  }
}
