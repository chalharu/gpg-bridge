import 'dart:async';

import 'package:dio/dio.dart';

import 'api_exception.dart';

/// Callback that refreshes the device_jwt by calling POST /device/refresh.
///
/// Should return `true` if the refresh succeeded and the request can be
/// retried, or `false` if the refresh failed (e.g. device_jwt expired).
typedef TokenRefresher = Future<bool> Function();

/// Interceptor that attempts to refresh the device_jwt on 401 responses.
///
/// When a 401 is received:
/// 1. Calls [tokenRefresher] to obtain a new device_jwt.
/// 2. If successful, retries the original request (which will get a fresh
///    device_assertion_jwt via [AuthInterceptor]).
/// 3. If refresh fails, propagates the original error.
///
/// Concurrent 401s are coalesced: the first triggers a refresh and subsequent
/// ones wait on the same [Completer].
///
/// This interceptor should be added **after** [AuthInterceptor] and
/// [ErrorInterceptor] in the interceptor chain so that 401s from the
/// original request are already parsed.
class TokenRefreshInterceptor extends Interceptor {
  TokenRefreshInterceptor({
    required Dio dio,
    required TokenRefresher tokenRefresher,
  }) : _dio = dio,
       _tokenRefresher = tokenRefresher;

  final Dio _dio;
  final TokenRefresher _tokenRefresher;

  Completer<bool>? _refreshCompleter;

  @override
  Future<void> onError(
    DioException err,
    ErrorInterceptorHandler handler,
  ) async {
    final response = err.response;
    if (response == null || response.statusCode != 401) {
      return handler.next(err);
    }

    // Avoid infinite loops: don't retry the refresh endpoint itself.
    if (response.requestOptions.path.endsWith('/device/refresh')) {
      return handler.next(err);
    }

    try {
      final refreshed = await _waitForRefresh();

      if (!refreshed) {
        return handler.next(err);
      }

      // Retry the original request. AuthInterceptor will generate a new
      // device_assertion_jwt automatically.
      final requestOptions = response.requestOptions;
      final retryResponse = await _dio.fetch<dynamic>(requestOptions);
      return handler.resolve(retryResponse);
    } on DioException catch (retryError) {
      return handler.next(retryError);
    } catch (error) {
      return handler.next(
        ApiException(
          requestOptions: response.requestOptions,
          response: response,
          overrideMessage: 'token refresh failed',
          error: error,
        ),
      );
    }
  }

  Future<bool> _waitForRefresh() async {
    if (_refreshCompleter != null) {
      return _refreshCompleter!.future;
    }

    _refreshCompleter = Completer<bool>();
    try {
      final result = await _tokenRefresher();
      _refreshCompleter!.complete(result);
      return result;
    } catch (error) {
      _refreshCompleter!.completeError(error);
      rethrow;
    } finally {
      _refreshCompleter = null;
    }
  }
}
