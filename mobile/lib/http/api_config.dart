/// API configuration constants.
abstract final class ApiConfig {
  /// Base URL for the API server.
  ///
  /// Override at build time via `--dart-define=API_BASE_URL=https://...`.
  static const String baseUrl = String.fromEnvironment(
    'API_BASE_URL',
    defaultValue: 'https://api.example.com',
  );

  /// Connection timeout duration.
  static const Duration connectTimeout = Duration(seconds: 10);

  /// Response receive timeout duration.
  static const Duration receiveTimeout = Duration(seconds: 30);

  /// Request send timeout duration.
  static const Duration sendTimeout = Duration(seconds: 30);
}
