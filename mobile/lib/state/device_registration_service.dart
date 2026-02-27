import 'dart:async';
import 'dart:convert';

import 'package:riverpod_annotation/riverpod_annotation.dart';
import 'package:uuid/uuid.dart';

import '../fcm/fcm_token_service.dart';
import '../http/device_api_service.dart';
import '../security/device_assertion_jwt_service.dart';
import '../security/keystore_platform_service.dart';
import '../security/secure_storage_service.dart';
import '../state/auth_state.dart';
import 'device_registration_types.dart';
import 'fid_service.dart';

export 'device_registration_types.dart';

part 'device_registration_service.g.dart';

class DefaultDeviceRegistrationService implements DeviceRegistrationService {
  DefaultDeviceRegistrationService({
    required KeystorePlatformService keystoreService,
    required FcmTokenService fcmTokenService,
    required FidService fidService,
    required DeviceApiService deviceApiService,
    required SecureStorageService storageService,
    required void Function(bool) onRegistrationChanged,
  }) : _keystoreService = keystoreService,
       _fcmTokenService = fcmTokenService,
       _fidService = fidService,
       _deviceApiService = deviceApiService,
       _storageService = storageService,
       _onRegistrationChanged = onRegistrationChanged;

  final KeystorePlatformService _keystoreService;
  final FcmTokenService _fcmTokenService;
  final FidService _fidService;
  final DeviceApiService _deviceApiService;
  final SecureStorageService _storageService;
  final void Function(bool) _onRegistrationChanged;

  StreamSubscription<String>? _tokenRefreshSubscription;
  bool _isRefreshing = false;

  @override
  Future<void> register() async {
    try {
      await _registerInternal();
    } catch (error) {
      if (error is DeviceRegistrationException) rethrow;
      throw DeviceRegistrationException(
        'device registration failed',
        cause: error,
      );
    }
  }

  @override
  void startTokenRefreshListener() {
    _tokenRefreshSubscription?.cancel();
    _tokenRefreshSubscription = _fcmTokenService.onTokenRefresh.listen(
      _handleTokenRefresh,
    );
  }

  @override
  Future<void> unregister() async {
    try {
      await _deviceApiService.deleteDevice();
      _tokenRefreshSubscription?.cancel();
      _tokenRefreshSubscription = null;

      await _clearStorage();
      _onRegistrationChanged(false);
    } catch (error) {
      if (error is DeviceRegistrationException) rethrow;
      throw DeviceRegistrationException(
        'device unregistration failed',
        cause: error,
      );
    }
  }

  // TODO: If a prior registration succeeded at the server but storage
  // writes failed, the next call generates new keys and may receive 409.
  // A future resilience ticket should add recovery for this scenario.
  Future<void> _registerInternal() async {
    // 1. Generate key pairs
    await _keystoreService.generateKeyPair(alias: KeystoreAliases.deviceKey);
    await _keystoreService.generateKeyPair(alias: KeystoreAliases.e2eKey);

    // 2. Get FCM token and FID
    final fcmToken = await _fcmTokenService.getToken();
    final fid = await _fidService.getId();

    // 3. Get public keys and add kid
    final sigKid = const Uuid().v4();
    final encKid = const Uuid().v4();

    final sigJwk = await _keystoreService.getPublicKeyJwk(
      alias: KeystoreAliases.deviceKey,
    );
    final encJwk = await _keystoreService.getPublicKeyJwk(
      alias: KeystoreAliases.e2eKey,
    );

    final sigJwkWithKid = {...sigJwk, 'kid': sigKid};
    final encJwkWithKid = {...encJwk, 'kid': encKid};

    // 4. POST /device
    final response = await _deviceApiService.registerDevice(
      deviceToken: fcmToken,
      firebaseInstallationId: fid,
      sigKeys: [sigJwkWithKid],
      encKeys: [encJwkWithKid],
      defaultKid: encKid,
    );

    // 5. Store credentials and sigKid
    final credentials = {
      SecureStorageKeys.deviceJwt: response.deviceJwt,
      SecureStorageKeys.deviceId: fid,
      SecureStorageKeys.fcmToken: fcmToken,
      SecureStorageKeys.sigKid: sigKid,
    };
    for (final entry in credentials.entries) {
      await _storageService.writeValue(key: entry.key, value: entry.value);
    }

    _onRegistrationChanged(true);
  }

  Future<void> _handleTokenRefresh(String newToken) async {
    if (_isRefreshing) return;
    _isRefreshing = true;
    try {
      final cachedToken = await _storageService.readValue(
        key: SecureStorageKeys.fcmToken,
      );
      if (cachedToken == newToken) return;

      await _deviceApiService.updateDevice(deviceToken: newToken);
      await _storageService.writeValue(
        key: SecureStorageKeys.fcmToken,
        value: newToken,
      );
    } catch (_) {
      // Token refresh is best-effort; will retry on next refresh event.
    } finally {
      _isRefreshing = false;
    }
  }

  @override
  Future<void> checkAndRefreshDeviceJwt() async {
    try {
      final jwt = await _storageService.readValue(
        key: SecureStorageKeys.deviceJwt,
      );
      if (jwt == null) return;

      final parts = jwt.split('.');
      if (parts.length != 3) return;

      final normalized = base64Url.normalize(parts[1]);
      final payload =
          jsonDecode(utf8.decode(base64Url.decode(normalized)))
              as Map<String, dynamic>;
      final exp = payload['exp'] as int?;
      final iat = payload['iat'] as int?;
      if (exp == null || iat == null) return;

      final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
      final totalValidity = exp - iat;
      final remaining = exp - now;

      if (remaining > 0 && remaining < totalValidity ~/ 3) {
        final response = await _deviceApiService.refreshDeviceJwt(
          currentDeviceJwt: jwt,
        );
        await _storageService.writeValue(
          key: SecureStorageKeys.deviceJwt,
          value: response.deviceJwt,
        );
      }
    } catch (_) {
      // Best-effort; will retry on next check.
    }
  }

  @override
  Future<void> checkAndRefreshFcmToken() async {
    try {
      final storedToken = await _storageService.readValue(
        key: SecureStorageKeys.fcmToken,
      );
      if (storedToken == null) return;

      final currentToken = await _fcmTokenService.getToken();
      if (currentToken == storedToken) return;

      await _deviceApiService.updateDevice(deviceToken: currentToken);
      await _storageService.writeValue(
        key: SecureStorageKeys.fcmToken,
        value: currentToken,
      );
    } catch (_) {
      // Best-effort; will retry on next startup.
    }
  }

  static const _storageKeys = [
    SecureStorageKeys.deviceJwt,
    SecureStorageKeys.deviceId,
    SecureStorageKeys.fcmToken,
    SecureStorageKeys.sigKid,
    SecureStorageKeys.deviceToken, // legacy key
  ];

  Future<void> _clearStorage() async {
    for (final key in _storageKeys) {
      await _storageService.deleteValue(key: key);
    }
  }
}

@Riverpod(keepAlive: true)
DeviceRegistrationService deviceRegistration(Ref ref) {
  return DefaultDeviceRegistrationService(
    keystoreService: ref.read(keystorePlatformProvider),
    fcmTokenService: ref.read(fcmTokenProvider),
    fidService: ref.read(fidServiceProvider),
    deviceApiService: ref.read(deviceApiProvider),
    storageService: ref.read(secureStorageProvider),
    onRegistrationChanged: (registered) {
      ref.read(authStateProvider.notifier).setRegistered(registered);
    },
  );
}
