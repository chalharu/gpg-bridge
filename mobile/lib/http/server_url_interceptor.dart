import 'package:dio/dio.dart';

import 'server_url_service.dart';

const String serverUrlOverrideExtraKey = 'serverUrlOverride';

class ServerUrlInterceptor extends Interceptor {
  ServerUrlInterceptor({required ServerUrlService serverUrlService})
    : _serverUrlService = serverUrlService;

  final ServerUrlService _serverUrlService;

  @override
  Future<void> onRequest(
    RequestOptions options,
    RequestInterceptorHandler handler,
  ) async {
    if (_isAbsoluteUrl(options.path)) {
      handler.next(options);
      return;
    }

    final overrideUrl = options.extra[serverUrlOverrideExtraKey] as String?;
    final baseUrl = overrideUrl ?? await _serverUrlService.getSavedOrDefault();
    options.path = _serverUrlService.buildEndpointUrl(
      baseUrl: baseUrl,
      path: options.path,
    );
    options.baseUrl = '';
    handler.next(options);
  }

  bool _isAbsoluteUrl(String path) {
    return path.startsWith('http://') || path.startsWith('https://');
  }
}
