import 'dart:developer' as developer;

import 'package:dio/dio.dart';
import 'package:flutter/foundation.dart';

/// Thin wrapper around Dio's [LogInterceptor] that is only active in debug
/// mode.
///
/// In release / profile builds the interceptor passes everything through
/// without logging.
class DebugLogInterceptor extends Interceptor {
  DebugLogInterceptor()
    : _inner = kDebugMode
          ? LogInterceptor(
              logPrint: (object) =>
                  developer.log(object.toString(), name: 'HTTP'),
              requestBody: true,
              responseBody: true,
            )
          : null;

  final LogInterceptor? _inner;

  @override
  void onRequest(RequestOptions options, RequestInterceptorHandler handler) {
    if (_inner != null) {
      _inner.onRequest(options, handler);
    } else {
      handler.next(options);
    }
  }

  @override
  void onResponse(
    Response<dynamic> response,
    ResponseInterceptorHandler handler,
  ) {
    if (_inner != null) {
      _inner.onResponse(response, handler);
    } else {
      handler.next(response);
    }
  }

  @override
  void onError(DioException err, ErrorInterceptorHandler handler) {
    if (_inner != null) {
      _inner.onError(err, handler);
    } else {
      handler.next(err);
    }
  }
}
