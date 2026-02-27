import 'dart:async';

import 'package:dio/dio.dart';

import 'auth_interceptor.dart';
import 'device_jwt_checker.dart';

/// Callback that reads the current device_jwt from secure storage.
typedef JwtReader = Future<String?> Function();

/// Callback that refreshes the device_jwt and writes it to storage.
typedef RefreshCallback = Future<void> Function();

/// Proactively refreshes device_jwt **before** each API request.
///
/// If the current JWT needs refreshing ([DeviceJwtChecker.needsRefresh]),
/// the [refreshCallback] is invoked before the request proceeds.
///
/// Concurrent refresh requests are coalesced via a shared [Completer].
/// If refresh fails the original request proceeds anyway (best-effort).
class DeviceJwtRefreshInterceptor extends Interceptor {
  DeviceJwtRefreshInterceptor({
    required JwtReader jwtReader,
    required RefreshCallback refreshCallback,
  }) : _jwtReader = jwtReader,
       _refreshCallback = refreshCallback;

  final JwtReader _jwtReader;
  final RefreshCallback _refreshCallback;

  Completer<void>? _refreshCompleter;

  @override
  Future<void> onRequest(
    RequestOptions options,
    RequestInterceptorHandler handler,
  ) async {
    if (_shouldSkip(options)) {
      return handler.next(options);
    }

    try {
      final jwt = await _jwtReader();
      if (jwt != null && jwt.isNotEmpty && DeviceJwtChecker.needsRefresh(jwt)) {
        await _coalesceRefresh();
      }
    } catch (_) {
      // Best-effort: proceed with the original request on any failure.
    }

    return handler.next(options);
  }

  bool _shouldSkip(RequestOptions options) {
    if (options.extra[skipAuthExtraKey] == true) return true;
    if (options.path.endsWith('/device/refresh')) return true;
    return false;
  }

  Future<void> _coalesceRefresh() async {
    if (_refreshCompleter != null) {
      return _refreshCompleter!.future;
    }

    _refreshCompleter = Completer<void>();
    try {
      await _refreshCallback();
    } catch (_) {
      // Best-effort: swallow errors so concurrent waiters also proceed.
    } finally {
      _refreshCompleter!.complete();
      _refreshCompleter = null;
    }
  }
}
