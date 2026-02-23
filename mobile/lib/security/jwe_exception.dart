/// Exception thrown by JWE operations.
class JweException implements Exception {
  JweException(this.message, {this.cause});

  final String message;
  final Object? cause;

  @override
  String toString() {
    if (cause == null) return 'JweException: $message';
    return 'JweException: $message ($cause)';
  }
}
