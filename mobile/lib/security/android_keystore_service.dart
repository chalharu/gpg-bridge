import 'dart:convert';

import 'package:flutter/services.dart';

class AndroidKeystoreException implements Exception {
  AndroidKeystoreException(this.message, {this.cause});

  final String message;
  final Object? cause;

  @override
  String toString() {
    if (cause == null) {
      return 'AndroidKeystoreException: $message';
    }
    return 'AndroidKeystoreException: $message ($cause)';
  }
}

abstract final class AndroidKeystoreAliases {
  static const String deviceKey = 'device_key';
  static const String e2eKey = 'e2e_key';

  static bool isSupported(String alias) {
    return alias == deviceKey || alias == e2eKey;
  }
}

class AndroidKeystoreService {
  AndroidKeystoreService([MethodChannel? channel])
    : _channel = channel ?? const MethodChannel(_channelName);

  static const String _channelName = 'gpg_bridge/keystore';

  final MethodChannel _channel;

  Future<void> generateKeyPair({required String alias}) async {
    _assertSupportedAlias(alias);

    final generated = await _guardPlatformCall<bool>(
      operation: 'generate key pair',
      call: () =>
          _channel.invokeMethod<bool>('generateKeyPair', {'alias': alias}),
    );

    if (generated != true) {
      throw AndroidKeystoreException('invalid generate key pair response');
    }
  }

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
      throw AndroidKeystoreException('signature is empty');
    }

    return signatureBase64;
  }

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

  Future<Map<String, String>> getPublicKeyJwk({required String alias}) async {
    _assertSupportedAlias(alias);

    final jwk = await _guardPlatformCall<Map<String, String>>(
      operation: 'get public key jwk',
      call: () => _channel.invokeMapMethod<String, String>('getPublicKeyJwk', {
        'alias': alias,
      }),
    );

    if (jwk == null || jwk.isEmpty) {
      throw AndroidKeystoreException('public key jwk is empty');
    }

    try {
      _assertValidJwk(alias, jwk);
    } catch (error) {
      if (error is AndroidKeystoreException) {
        rethrow;
      }
      throw AndroidKeystoreException(
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
      throw AndroidKeystoreException('failed to $operation', cause: error);
    } on MissingPluginException catch (error) {
      throw AndroidKeystoreException(
        'android keystore is unavailable',
        cause: error,
      );
    } catch (error) {
      throw AndroidKeystoreException(
        'unexpected platform response while trying to $operation',
        cause: error,
      );
    }
  }

  void _assertSupportedAlias(String alias) {
    if (!AndroidKeystoreAliases.isSupported(alias)) {
      throw AndroidKeystoreException('unsupported alias: $alias');
    }
  }

  void _assertSignAlias(String alias) {
    if (alias != AndroidKeystoreAliases.deviceKey) {
      throw AndroidKeystoreException(
        'alias does not support sign/verify: $alias',
      );
    }
  }

  void _assertValidJwk(String alias, Map<String, String> jwk) {
    if (jwk['kty'] != 'EC') {
      throw AndroidKeystoreException('invalid jwk kty');
    }
    if (jwk['crv'] != 'P-256') {
      throw AndroidKeystoreException('invalid jwk crv');
    }

    final expectedUse = alias == AndroidKeystoreAliases.deviceKey
        ? 'sig'
        : 'enc';
    final expectedAlg = alias == AndroidKeystoreAliases.deviceKey
        ? 'ES256'
        : 'ECDH-ES+A256KW';

    if (jwk['use'] != expectedUse) {
      throw AndroidKeystoreException('invalid jwk use');
    }
    if (jwk['alg'] != expectedAlg) {
      throw AndroidKeystoreException('invalid jwk alg');
    }

    _assertBase64UrlCoordinate(jwk['x'], 'x');
    _assertBase64UrlCoordinate(jwk['y'], 'y');
  }

  void _assertNonEmptySignature(String signatureBase64) {
    if (signatureBase64.isEmpty) {
      throw AndroidKeystoreException('signature is empty');
    }
  }

  void _assertBase64UrlCoordinate(String? value, String name) {
    final pattern = RegExp(r'^[A-Za-z0-9_-]{43}$');
    if (value == null || !pattern.hasMatch(value)) {
      throw AndroidKeystoreException('invalid jwk $name coordinate');
    }
  }
}
