/// API configuration constants.
abstract final class ApiConfig {
  /// Base URL for the API server.
  ///
  /// Override with a different value per environment as needed.
  static const String baseUrl = 'https://api.example.com';

  /// Connection timeout duration.
  static const Duration connectTimeout = Duration(seconds: 10);

  /// Response receive timeout duration.
  static const Duration receiveTimeout = Duration(seconds: 30);

  /// Request send timeout duration.
  static const Duration sendTimeout = Duration(seconds: 30);
}
