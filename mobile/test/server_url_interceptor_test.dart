import 'package:dio/dio.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:gpg_bridge_mobile/http/server_url_interceptor.dart';
import 'package:gpg_bridge_mobile/http/server_url_service.dart';

void main() {
  group('ServerUrlInterceptor', () {
    test('leaves absolute URLs unchanged', () async {
      final service = _FakeServerUrlService(
        savedUrl: 'https://saved.example.com',
      );
      final interceptor = ServerUrlInterceptor(serverUrlService: service);
      final options = RequestOptions(
        path: 'https://absolute.example.com/device',
      );
      late RequestOptions captured;

      await interceptor.onRequest(
        options,
        _CaptureRequestHandler(onNext: (request) => captured = request),
      );

      expect(captured.path, 'https://absolute.example.com/device');
      expect(service.getSavedOrDefaultCallCount, 0);
      expect(service.buildEndpointUrlCallCount, 0);
    });

    test('rewrites relative URLs using the saved server URL', () async {
      final service = _FakeServerUrlService(
        savedUrl: 'https://saved.example.com/api',
      );
      final interceptor = ServerUrlInterceptor(serverUrlService: service);
      final options = RequestOptions(
        path: '/device',
        baseUrl: 'https://ignored.example.com',
      );
      late RequestOptions captured;

      await interceptor.onRequest(
        options,
        _CaptureRequestHandler(onNext: (request) => captured = request),
      );

      expect(captured.path, 'https://saved.example.com/api/device');
      expect(captured.baseUrl, '');
      expect(service.getSavedOrDefaultCallCount, 1);
      expect(service.lastBuildBaseUrl, 'https://saved.example.com/api');
      expect(service.lastBuildPath, '/device');
    });

    test('prefers the per-request server URL override', () async {
      final service = _FakeServerUrlService(
        savedUrl: 'https://saved.example.com/api',
      );
      final interceptor = ServerUrlInterceptor(serverUrlService: service);
      final options = RequestOptions(
        path: '/health',
        extra: {
          serverUrlOverrideExtraKey: 'https://override.example.com/runtime',
        },
      );
      late RequestOptions captured;

      await interceptor.onRequest(
        options,
        _CaptureRequestHandler(onNext: (request) => captured = request),
      );

      expect(captured.path, 'https://override.example.com/runtime/health');
      expect(service.getSavedOrDefaultCallCount, 0);
      expect(service.lastBuildBaseUrl, 'https://override.example.com/runtime');
      expect(service.lastBuildPath, '/health');
    });
  });
}

class _FakeServerUrlService implements ServerUrlService {
  _FakeServerUrlService({required this.savedUrl});

  final String savedUrl;
  int getSavedOrDefaultCallCount = 0;
  int buildEndpointUrlCallCount = 0;
  String? lastBuildBaseUrl;
  String? lastBuildPath;

  @override
  Future<String> getSavedOrDefault() async {
    getSavedOrDefaultCallCount += 1;
    return savedUrl;
  }

  @override
  String buildEndpointUrl({required String baseUrl, required String path}) {
    buildEndpointUrlCallCount += 1;
    lastBuildBaseUrl = baseUrl;
    lastBuildPath = path;
    final trimmedPath = path.startsWith('/') ? path.substring(1) : path;
    return '$baseUrl/$trimmedPath';
  }

  @override
  Future<void> clear() async {}

  @override
  String normalize(String input) => input;

  @override
  Future<void> save(String serverUrl) async {}
}

class _CaptureRequestHandler extends RequestInterceptorHandler {
  _CaptureRequestHandler({required this.onNext});

  final void Function(RequestOptions options) onNext;

  @override
  void next(RequestOptions requestOptions) {
    onNext(requestOptions);
  }

  @override
  void reject(
    DioException error, [
    bool callFollowingErrorInterceptor = false,
  ]) {}

  @override
  void resolve(
    Response<dynamic> response, [
    bool callFollowingResponseInterceptor = false,
  ]) {}
}
