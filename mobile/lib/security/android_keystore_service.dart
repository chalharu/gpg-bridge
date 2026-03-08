import 'package:flutter/services.dart';

import 'keystore_service_base.dart';
import 'keystore_platform_service.dart';

class AndroidKeystoreException implements Exception {
  AndroidKeystoreException(this.message, {this.cause});

  AndroidKeystoreException.fromPlatform(KeystorePlatformException error)
    : message = error.message,
      cause = error.cause;

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
  static const String deviceKey = KeystoreAliases.deviceKey;
  static const String e2eKey = KeystoreAliases.e2eKey;

  static bool isSupported(String alias) {
    return KeystoreAliases.isSupported(alias);
  }
}

class AndroidKeystoreService
    extends MethodChannelKeystoreServiceBase<AndroidKeystoreException> {
  AndroidKeystoreService([MethodChannel? channel])
    : super(AndroidKeystoreException.fromPlatform, channel);
}
