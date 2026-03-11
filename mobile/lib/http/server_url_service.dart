import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../security/secure_storage_service.dart';
import 'api_config.dart';

final serverUrlServiceProvider = Provider<ServerUrlService>((ref) {
  return DefaultServerUrlService(ref.read(secureStorageProvider));
});

class ServerUrlException implements Exception {
  ServerUrlException(this.message, {this.cause});

  final String message;
  final Object? cause;

  @override
  String toString() {
    if (cause == null) {
      return 'ServerUrlException: $message';
    }
    return 'ServerUrlException: $message ($cause)';
  }
}

abstract interface class ServerUrlService {
  Future<String> getSavedOrDefault();
  Future<void> save(String serverUrl);
  Future<void> clear();
  String normalize(String input);
  String buildEndpointUrl({required String baseUrl, required String path});
}

class DefaultServerUrlService implements ServerUrlService {
  DefaultServerUrlService(this._storageService);

  final SecureStorageService _storageService;

  @override
  Future<String> getSavedOrDefault() async {
    final stored = await _storageService.readValue(
      key: SecureStorageKeys.serverUrl,
    );
    if (stored == null || stored.isEmpty) {
      return ApiConfig.baseUrl;
    }

    return normalize(stored);
  }

  @override
  Future<void> save(String serverUrl) async {
    final normalized = normalize(serverUrl);
    await _storageService.writeValue(
      key: SecureStorageKeys.serverUrl,
      value: normalized,
    );
  }

  @override
  Future<void> clear() async {
    await _storageService.deleteValue(key: SecureStorageKeys.serverUrl);
  }

  @override
  String normalize(String input) {
    final trimmed = input.trim();
    final uri = Uri.tryParse(trimmed);
    if (uri == null || !uri.isAbsolute || uri.host.isEmpty) {
      throw ServerUrlException('enter a valid HTTPS server URL');
    }
    if (uri.scheme != 'https') {
      throw ServerUrlException('server URL must start with https://');
    }
    if (uri.hasQuery || uri.hasFragment || uri.userInfo.isNotEmpty) {
      throw ServerUrlException('server URL must not include query or fragment');
    }

    final segments = uri.pathSegments.where((segment) => segment.isNotEmpty);
    final normalizedPath = segments.join('/');
    return uri
        .replace(path: normalizedPath.isEmpty ? '' : '/$normalizedPath')
        .toString();
  }

  @override
  String buildEndpointUrl({required String baseUrl, required String path}) {
    final normalizedBaseUrl = normalize(baseUrl);
    final trimmedPath = path.startsWith('/') ? path.substring(1) : path;
    final baseUri = Uri.parse('$normalizedBaseUrl/');
    return baseUri.resolve(trimmedPath).toString();
  }
}
