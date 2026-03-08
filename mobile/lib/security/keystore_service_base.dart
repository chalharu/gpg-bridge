import 'package:flutter/services.dart';

import 'keystore_platform_service.dart';

abstract class MethodChannelKeystoreServiceBase<T extends Exception> {
  MethodChannelKeystoreServiceBase(
    this._exceptionFromPlatform, [
    MethodChannel? channel,
  ]) : _delegate = MethodChannelKeystorePlatformService(channel);

  final T Function(KeystorePlatformException error) _exceptionFromPlatform;
  final MethodChannelKeystorePlatformService _delegate;

  Future<void> generateKeyPair({required String alias}) async {
    await _guard(() => _delegate.generateKeyPair(alias: alias));
  }

  Future<String> sign({required String alias, required List<int> data}) {
    return _guard(() => _delegate.sign(alias: alias, data: data));
  }

  Future<bool> verify({
    required String alias,
    required List<int> data,
    required String signatureBase64,
  }) {
    return _guard(
      () => _delegate.verify(
        alias: alias,
        data: data,
        signatureBase64: signatureBase64,
      ),
    );
  }

  Future<Map<String, String>> getPublicKeyJwk({required String alias}) {
    return _guard(() => _delegate.getPublicKeyJwk(alias: alias));
  }

  Future<R> _guard<R>(Future<R> Function() call) async {
    try {
      return await call();
    } on KeystorePlatformException catch (error) {
      throw _exceptionFromPlatform(error);
    }
  }
}
