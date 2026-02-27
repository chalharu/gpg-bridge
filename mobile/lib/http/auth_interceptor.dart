import 'package:dio/dio.dart';

/// Callback that generates a device_assertion_jwt for each request.
typedef TokenProvider = Future<String?> Function(RequestOptions options);

/// Key for [RequestOptions.extra] to skip auth header injection.
const String skipAuthExtraKey = 'skipAuth';

/// Interceptor that attaches `Authorization: Bearer <token>` to every request.
///
/// The [tokenProvider] is called per-request because the mobile app generates
/// a fresh device_assertion_jwt (ES256 signed) for each API call.
///
/// Set `options.extra['skipAuth'] = true` to skip token injection (e.g. for
/// unauthenticated endpoints like POST /device).
class AuthInterceptor extends Interceptor {
  AuthInterceptor({required TokenProvider tokenProvider})
    : _tokenProvider = tokenProvider;

  final TokenProvider _tokenProvider;

  @override
  Future<void> onRequest(
    RequestOptions options,
    RequestInterceptorHandler handler,
  ) async {
    if (options.extra[skipAuthExtraKey] == true) {
      return handler.next(options);
    }

    try {
      final token = await _tokenProvider(options);
      if (token != null && token.isNotEmpty) {
        options.headers['Authorization'] = 'Bearer $token';
      }
    } catch (error) {
      return handler.reject(
        DioException(
          requestOptions: options,
          error: error,
          message: 'failed to generate auth token',
        ),
      );
    }
    return handler.next(options);
  }
}
