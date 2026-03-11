import 'package:flutter_test/flutter_test.dart';
import 'package:gpg_bridge_mobile/http/api_config.dart';
import 'package:gpg_bridge_mobile/http/server_url_service.dart';
import 'package:gpg_bridge_mobile/security/secure_storage_service.dart';

import 'helpers/in_memory_secure_storage_backend.dart';

void main() {
  late SecureStorageService storageService;
  late DefaultServerUrlService service;

  setUp(() {
    storageService = SecureStorageService(InMemorySecureStorageBackend());
    service = DefaultServerUrlService(storageService);
  });

  test('getSavedOrDefault falls back to API_BASE_URL', () async {
    expect(await service.getSavedOrDefault(), ApiConfig.baseUrl);
  });

  test('normalize trims whitespace and removes trailing slash', () {
    expect(
      service.normalize('  https://runtime.example.com/api/  '),
      'https://runtime.example.com/api',
    );
  });

  test('normalize rejects insecure URLs', () {
    expect(
      () => service.normalize('http://runtime.example.com'),
      throwsA(isA<ServerUrlException>()),
    );
  });

  test('normalize rejects URLs with query strings', () {
    expect(
      () => service.normalize('https://runtime.example.com/api?env=dev'),
      throwsA(isA<ServerUrlException>()),
    );
  });

  test('normalize rejects URLs with fragments or user info', () {
    expect(
      () => service.normalize('https://user@runtime.example.com/api'),
      throwsA(isA<ServerUrlException>()),
    );
    expect(
      () => service.normalize('https://runtime.example.com/api#fragment'),
      throwsA(isA<ServerUrlException>()),
    );
  });

  test('buildEndpointUrl preserves nested base paths', () {
    expect(
      service.buildEndpointUrl(
        baseUrl: 'https://runtime.example.com/api',
        path: '/device/refresh',
      ),
      'https://runtime.example.com/api/device/refresh',
    );
  });

  test('save persists normalized URL for later reads', () async {
    await service.save('https://runtime.example.com/api/');

    expect(
      await service.getSavedOrDefault(),
      'https://runtime.example.com/api',
    );
  });

  test('getSavedOrDefault reflects external storage changes', () async {
    await storageService.writeValue(
      key: SecureStorageKeys.serverUrl,
      value: 'https://first.example.com',
    );
    expect(await service.getSavedOrDefault(), 'https://first.example.com');

    await storageService.writeValue(
      key: SecureStorageKeys.serverUrl,
      value: 'https://second.example.com/api',
    );
    expect(await service.getSavedOrDefault(), 'https://second.example.com/api');
  });

  test('getSavedOrDefault throws for corrupt stored URL', () async {
    await storageService.writeValue(
      key: SecureStorageKeys.serverUrl,
      value: 'not-a-url',
    );

    expect(
      () => service.getSavedOrDefault(),
      throwsA(isA<ServerUrlException>()),
    );
  });
}
