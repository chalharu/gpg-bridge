import 'package:flutter/services.dart';

import 'keystore_platform_service.dart';

class IosSecureEnclaveException implements Exception {
  IosSecureEnclaveException(this.message, {this.cause});

  IosSecureEnclaveException.fromPlatform(KeystorePlatformException error)
    : message = error.message,
      cause = error.cause;

  final String message;
  final Object? cause;

  @override
  String toString() {
    if (cause == null) {
      return 'IosSecureEnclaveException: $message';
    }
    return 'IosSecureEnclaveException: $message ($cause)';
  }
}

abstract final class IosSecureEnclaveAliases {
  static const String deviceKey = KeystoreAliases.deviceKey;
  static const String e2eKey = KeystoreAliases.e2eKey;

  static bool isSupported(String alias) {
    return KeystoreAliases.isSupported(alias);
  }
}

class IosSecureEnclaveService {
  IosSecureEnclaveService([MethodChannel? channel])
    : _delegate = MethodChannelKeystorePlatformService(channel);

  final MethodChannelKeystorePlatformService _delegate;

  Future<void> generateKeyPair({required String alias}) async {
    await _guard(() => _delegate.generateKeyPair(alias: alias));
  }

  Future<String> sign({required String alias, required List<int> data}) async {
    return _guard(() => _delegate.sign(alias: alias, data: data));
  }

  Future<bool> verify({
    required String alias,
    required List<int> data,
    required String signatureBase64,
  }) async {
    return _guard(
      () => _delegate.verify(
        alias: alias,
        data: data,
        signatureBase64: signatureBase64,
      ),
    );
  }

  Future<Map<String, String>> getPublicKeyJwk({required String alias}) async {
    return _guard(() => _delegate.getPublicKeyJwk(alias: alias));
  }

  Future<T> _guard<T>(Future<T> Function() call) async {
    try {
      return await call();
    } on KeystorePlatformException catch (error) {
      throw IosSecureEnclaveException.fromPlatform(error);
    }
  }
}
