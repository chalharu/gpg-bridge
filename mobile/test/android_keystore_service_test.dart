import 'dart:convert';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:gpg_bridge_mobile/security/android_keystore_service.dart';

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
    'generate sign verify getPublicKeyJwk invoke channel with expected args',
    () async {
      final service = AndroidKeystoreService(channel);

      await service.generateKeyPair(alias: AndroidKeystoreAliases.deviceKey);

      final signature = await service.sign(
        alias: AndroidKeystoreAliases.deviceKey,
        data: utf8.encode('hello'),
      );

      final verified = await service.verify(
        alias: AndroidKeystoreAliases.deviceKey,
        data: utf8.encode('hello'),
        signatureBase64: signature,
      );

      final jwk = await service.getPublicKeyJwk(
        alias: AndroidKeystoreAliases.deviceKey,
      );

      expect(signature, 'c2ln');
      expect(verified, isTrue);
      expect(jwk['kty'], 'EC');
      expect(jwk['use'], 'sig');
      expect(jwk['alg'], 'ES256');
      expect(methodCalls.map((call) => call.method).toList(), [
        'generateKeyPair',
        'sign',
        'verify',
        'getPublicKeyJwk',
      ]);

      expect(methodCalls[0].arguments, {'alias': 'device_key'});
      expect(methodCalls[1].arguments, {
        'alias': 'device_key',
        'dataBase64': base64Encode(utf8.encode('hello')),
      });
      expect(methodCalls[2].arguments, {
        'alias': 'device_key',
        'dataBase64': base64Encode(utf8.encode('hello')),
        'signatureBase64': 'c2ln',
      });
      expect(methodCalls[3].arguments, {'alias': 'device_key'});
    },
  );

  test('service wraps PlatformException from each method', () async {
    messenger.setMockMethodCallHandler(channel, (call) async {
      throw PlatformException(code: 'ERR', message: 'boom');
    });

    final service = AndroidKeystoreService(channel);

    await expectLater(
      () => service.generateKeyPair(alias: AndroidKeystoreAliases.deviceKey),
      throwsA(isA<AndroidKeystoreException>()),
    );

    await expectLater(
      () => service.sign(
        alias: AndroidKeystoreAliases.deviceKey,
        data: utf8.encode('hello'),
      ),
      throwsA(isA<AndroidKeystoreException>()),
    );

    await expectLater(
      () => service.verify(
        alias: AndroidKeystoreAliases.deviceKey,
        data: utf8.encode('hello'),
        signatureBase64: 'c2ln',
      ),
      throwsA(isA<AndroidKeystoreException>()),
    );

    await expectLater(
      () => service.getPublicKeyJwk(alias: AndroidKeystoreAliases.deviceKey),
      throwsA(isA<AndroidKeystoreException>()),
    );
  });

  test('service throws when platform returns invalid payload', () async {
    messenger.setMockMethodCallHandler(channel, (call) async {
      switch (call.method) {
        case 'sign':
          return '';
        case 'verify':
          return null;
        case 'getPublicKeyJwk':
          return <String, String>{};
        default:
          return true;
      }
    });

    final service = AndroidKeystoreService(channel);

    await expectLater(
      () => service.sign(
        alias: AndroidKeystoreAliases.deviceKey,
        data: utf8.encode('hello'),
      ),
      throwsA(isA<AndroidKeystoreException>()),
    );

    final verified = await service.verify(
      alias: AndroidKeystoreAliases.deviceKey,
      data: utf8.encode('hello'),
      signatureBase64: 'c2ln',
    );
    expect(verified, isFalse);

    await expectLater(
      () => service.getPublicKeyJwk(alias: AndroidKeystoreAliases.deviceKey),
      throwsA(isA<AndroidKeystoreException>()),
    );
  });

  test('generateKeyPair rejects unexpected platform response', () async {
    messenger.setMockMethodCallHandler(channel, (call) async {
      if (call.method == 'generateKeyPair') {
        return false;
      }
      return true;
    });

    final service = AndroidKeystoreService(channel);

    await expectLater(
      () => service.generateKeyPair(alias: AndroidKeystoreAliases.deviceKey),
      throwsA(isA<AndroidKeystoreException>()),
    );
  });

  test('service wraps MissingPluginException from channel calls', () async {
    messenger.setMockMethodCallHandler(channel, (call) async {
      throw MissingPluginException('missing');
    });

    final service = AndroidKeystoreService(channel);

    await expectLater(
      () => service.sign(
        alias: AndroidKeystoreAliases.deviceKey,
        data: utf8.encode('hello'),
      ),
      throwsA(isA<AndroidKeystoreException>()),
    );
  });

  test(
    'service wraps non platform errors from malformed channel payload',
    () async {
      messenger.setMockMethodCallHandler(channel, (call) async {
        if (call.method == 'getPublicKeyJwk') {
          return {
            'kty': 'EC',
            'use': 'sig',
            'crv': 'P-256',
            'x': 123,
            'y': 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB',
            'alg': 'ES256',
          };
        }
        return true;
      });

      final service = AndroidKeystoreService(channel);

      await expectLater(
        () => service.getPublicKeyJwk(alias: AndroidKeystoreAliases.deviceKey),
        throwsA(isA<AndroidKeystoreException>()),
      );
    },
  );

  test('exception toString includes cause when present', () {
    final error = AndroidKeystoreException('failed', cause: Exception('boom'));

    expect(error.toString(), contains('failed'));
    expect(error.toString(), contains('boom'));
  });

  test('exception toString omits cause when absent', () {
    final error = AndroidKeystoreException('failed');

    expect(error.toString(), 'AndroidKeystoreException: failed');
  });

  test('service rejects unsupported alias before channel invocation', () async {
    final service = AndroidKeystoreService(channel);

    await expectLater(
      () => service.generateKeyPair(alias: 'unknown_alias'),
      throwsA(isA<AndroidKeystoreException>()),
    );

    expect(methodCalls, isEmpty);
  });

  test('service rejects e2e alias for sign and verify', () async {
    final service = AndroidKeystoreService(channel);

    await expectLater(
      () => service.sign(
        alias: AndroidKeystoreAliases.e2eKey,
        data: utf8.encode('hello'),
      ),
      throwsA(isA<AndroidKeystoreException>()),
    );

    await expectLater(
      () => service.verify(
        alias: AndroidKeystoreAliases.e2eKey,
        data: utf8.encode('hello'),
        signatureBase64: 'c2ln',
      ),
      throwsA(isA<AndroidKeystoreException>()),
    );

    expect(methodCalls, isEmpty);
  });

  test('service validates JWK payload shape and values', () async {
    messenger.setMockMethodCallHandler(channel, (call) async {
      if (call.method == 'getPublicKeyJwk') {
        return {
          'kty': 'EC',
          'use': 'sig',
          'crv': 'P-256',
          'x': 'invalid',
          'y': 'def',
          'alg': 'ES256',
        };
      }
      return true;
    });

    final service = AndroidKeystoreService(channel);

    await expectLater(
      () => service.getPublicKeyJwk(alias: AndroidKeystoreAliases.deviceKey),
      throwsA(isA<AndroidKeystoreException>()),
    );
  });

  test('service validates e2e JWK use and algorithm', () async {
    messenger.setMockMethodCallHandler(channel, (call) async {
      if (call.method == 'getPublicKeyJwk') {
        return {
          'kty': 'EC',
          'use': 'enc',
          'crv': 'P-256',
          'x': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
          'y': 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB',
          'alg': 'ECDH-ES+A256KW',
        };
      }
      return true;
    });

    final service = AndroidKeystoreService(channel);

    final jwk = await service.getPublicKeyJwk(
      alias: AndroidKeystoreAliases.e2eKey,
    );

    expect(jwk['use'], 'enc');
    expect(jwk['alg'], 'ECDH-ES+A256KW');
  });

  test('verify rejects empty signature before channel invocation', () async {
    final service = AndroidKeystoreService(channel);

    await expectLater(
      () => service.verify(
        alias: AndroidKeystoreAliases.deviceKey,
        data: utf8.encode('hello'),
        signatureBase64: '',
      ),
      throwsA(isA<AndroidKeystoreException>()),
    );

    expect(methodCalls, isEmpty);
  });
}
