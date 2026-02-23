import 'dart:convert';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:gpg_bridge_mobile/security/keystore_platform_service.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  const channelName = 'gpg_bridge/keystore';
  const channel = MethodChannel(channelName);
  final messenger =
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;

  final methodCalls = <MethodCall>[];

  setUp(() async {
    methodCalls.clear();
    messenger.setMockMethodCallHandler(channel, (call) async {
      methodCalls.add(call);

      switch (call.method) {
        case 'generateKeyPair':
          return true;
        case 'sign':
          return 'c2ln';
        case 'verify':
          return true;
        case 'getPublicKeyJwk':
          return {
            'kty': 'EC',
            'use': 'sig',
            'crv': 'P-256',
            'x': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
            'y': 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB',
            'alg': 'ES256',
          };
        default:
          return null;
      }
    });
  });

  tearDown(() async {
    messenger.setMockMethodCallHandler(channel, null);
  });

  test(
    'method channel service invokes expected methods and arguments',
    () async {
      final service = MethodChannelKeystorePlatformService(channel);

      await service.generateKeyPair(alias: KeystoreAliases.deviceKey);

      final signature = await service.sign(
        alias: KeystoreAliases.deviceKey,
        data: utf8.encode('hello'),
      );

      final verified = await service.verify(
        alias: KeystoreAliases.deviceKey,
        data: utf8.encode('hello'),
        signatureBase64: signature,
      );

      final jwk = await service.getPublicKeyJwk(
        alias: KeystoreAliases.deviceKey,
      );

      expect(signature, 'c2ln');
      expect(verified, isTrue);
      expect(jwk['kty'], 'EC');
      expect(methodCalls.map((call) => call.method).toList(), [
        'generateKeyPair',
        'sign',
        'verify',
        'getPublicKeyJwk',
      ]);
      expect(methodCalls[1].arguments, {
        'alias': 'device_key',
        'dataBase64': base64Encode(utf8.encode('hello')),
      });
    },
  );

  test('service rejects unsupported sign alias before platform call', () async {
    final service = MethodChannelKeystorePlatformService(channel);

    await expectLater(
      () => service.sign(alias: KeystoreAliases.e2eKey, data: utf8.encode('x')),
      throwsA(isA<KeystorePlatformException>()),
    );

    expect(methodCalls, isEmpty);
  });

  test('service wraps PlatformException', () async {
    messenger.setMockMethodCallHandler(channel, (call) async {
      throw PlatformException(code: 'ERR', message: 'boom');
    });

    final service = MethodChannelKeystorePlatformService(channel);

    await expectLater(
      () => service.generateKeyPair(alias: KeystoreAliases.deviceKey),
      throwsA(isA<KeystorePlatformException>()),
    );
  });

  test('service validates JWK coordinate format', () async {
    messenger.setMockMethodCallHandler(channel, (call) async {
      if (call.method == 'getPublicKeyJwk') {
        return {
          'kty': 'EC',
          'use': 'sig',
          'crv': 'P-256',
          'x': 'invalid',
          'y': 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB',
          'alg': 'ES256',
        };
      }
      return true;
    });

    final service = MethodChannelKeystorePlatformService(channel);

    await expectLater(
      () => service.getPublicKeyJwk(alias: KeystoreAliases.deviceKey),
      throwsA(isA<KeystorePlatformException>()),
    );
  });
}
