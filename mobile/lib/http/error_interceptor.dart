import 'package:dio/dio.dart';

import 'api_exception.dart';

/// Interceptor that parses error responses into [ApiException].
///
/// Supports two formats:
/// - RFC 7807 Problem Details (`application/problem+json`)
/// - Server ErrorResponse (`{ error, message }`)
class ErrorInterceptor extends Interceptor {
  @override
  void onResponse(
    Response<dynamic> response,
    ResponseInterceptorHandler handler,
  ) {
    final statusCode = response.statusCode ?? 0;
    if (statusCode >= 400) {
      handler.reject(_buildApiException(response), true);
      return;
    }
    handler.next(response);
  }

  @override
  void onError(DioException err, ErrorInterceptorHandler handler) {
    if (err is ApiException) {
      return handler.next(err);
    }

    final response = err.response;
    if (response != null) {
      return handler.next(_buildApiException(response, original: err));
    }

    handler.next(err);
  }

  ApiException _buildApiException(
    Response<dynamic> response, {
    DioException? original,
  }) {
    final contentType = response.headers.value('content-type') ?? '';
    final data = response.data;

    ProblemDetails? problemDetails;
    ErrorResponse? errorResponse;

    if (data is Map<String, dynamic>) {
      if (contentType.contains('application/problem+json')) {
        problemDetails = ProblemDetails.fromJson(data);
      }

      // Fall back to ErrorResponse parsing if ProblemDetails parsing failed
      // or if the content-type is not problem+json.
      if (problemDetails == null) {
        errorResponse = ErrorResponse.fromJson(data);
      }
    }

    return ApiException(
      requestOptions: response.requestOptions,
      response: response,
      problemDetails: problemDetails,
      errorResponse: errorResponse,
      error: original?.error,
    );
  }
}
