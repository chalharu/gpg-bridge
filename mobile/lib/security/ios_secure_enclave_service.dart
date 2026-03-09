import 'package:flutter/services.dart';

import 'keystore_service_base.dart';
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

class IosSecureEnclaveService
    extends MethodChannelKeystoreServiceBase<IosSecureEnclaveException> {
  IosSecureEnclaveService([MethodChannel? channel])
    : super(IosSecureEnclaveException.fromPlatform, channel);
}
