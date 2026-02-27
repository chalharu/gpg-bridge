// Types used by the device registration service.

/// Exception thrown by [DeviceRegistrationService] operations.
class DeviceRegistrationException implements Exception {
  DeviceRegistrationException(this.message, {this.cause});

  final String message;
  final Object? cause;

  @override
  String toString() {
    if (cause == null) return 'DeviceRegistrationException: $message';
    return 'DeviceRegistrationException: $message ($cause)';
  }
}

/// Orchestrates device registration, token refresh listening, and
/// unregistration.
abstract interface class DeviceRegistrationService {
  Future<void> register();
  void startTokenRefreshListener();
  Future<void> unregister();
  Future<void> checkAndRefreshDeviceJwt();
  Future<void> checkAndRefreshFcmToken();
}
