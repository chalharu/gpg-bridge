import 'package:dio/dio.dart';

/// RFC 7807 / RFC 9457 Problem Details representation.
class ProblemDetails {
  ProblemDetails({
    required this.type,
    required this.title,
    required this.status,
    required this.detail,
    this.instance,
  });

  /// Parses a [ProblemDetails] from a JSON map.
  ///
  /// Returns `null` if the required fields are missing.
  static ProblemDetails? fromJson(Map<String, dynamic> json) {
    final type = json['type'];
    final title = json['title'];
    final status = json['status'];
    final detail = json['detail'];

    if (type is! String ||
        title is! String ||
        status is! int ||
        detail is! String) {
      return null;
    }

    return ProblemDetails(
      type: type,
      title: title,
      status: status,
      detail: detail,
      instance: json['instance'] as String?,
    );
  }

  final String type;
  final String title;
  final int status;
  final String detail;
  final String? instance;

  @override
  String toString() {
    return 'ProblemDetails(type: $type, title: $title, status: $status, '
        'detail: $detail, instance: $instance)';
  }
}

/// Server `ErrorResponse` representation (`{ error, message }`).
class ErrorResponse {
  ErrorResponse({required this.error, this.message});

  /// Parses an [ErrorResponse] from a JSON map.
  ///
  /// Returns `null` if the required `error` field is missing.
  static ErrorResponse? fromJson(Map<String, dynamic> json) {
    final error = json['error'];
    if (error is! String) return null;

    return ErrorResponse(error: error, message: json['message'] as String?);
  }

  final String error;
  final String? message;

  @override
  String toString() {
    return 'ErrorResponse(error: $error, message: $message)';
  }
}

/// Unified API exception wrapping either a [ProblemDetails] or [ErrorResponse].
class ApiException extends DioException {
  ApiException({
    required super.requestOptions,
    super.response,
    this.problemDetails,
    this.errorResponse,
    super.error,
    String? overrideMessage,
  }) : _overrideMessage = overrideMessage;

  /// Present when the server returned `application/problem+json`.
  final ProblemDetails? problemDetails;

  /// Present when the server returned a standard `{ error, message }` body.
  final ErrorResponse? errorResponse;

  final String? _overrideMessage;

  @override
  String get message {
    if (_overrideMessage != null) return _overrideMessage;
    if (problemDetails != null) return problemDetails!.detail;
    if (errorResponse != null) {
      return errorResponse!.message ?? errorResponse!.error;
    }
    return super.message ?? 'unknown error';
  }

  @override
  DioExceptionType get type => DioExceptionType.badResponse;

  @override
  String toString() {
    return 'ApiException(message: $message, '
        'statusCode: ${response?.statusCode}, '
        'problemDetails: $problemDetails, '
        'errorResponse: $errorResponse)';
  }
}
