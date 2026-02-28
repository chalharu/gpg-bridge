import 'dart:convert';
import 'dart:typed_data';

import 'package:riverpod_annotation/riverpod_annotation.dart';

import '../http/gpg_key_api_service.dart';
import '../security/gpg_signing_service.dart';
import 'key_management_service.dart';
import 'sign_request_service.dart';

export 'sign_request_types.dart';

part 'sign_execution_service.g.dart';

/// Result of a sign execution attempt.
enum SignExecutionResult { approved, unavailable, error }

/// Orchestrates GPG signing: key lookup → sign → submit result.
abstract interface class SignExecutionService {
  /// Executes an approval flow for the given [request].
  Future<SignExecutionResult> executeApproval(DecryptedSignRequest request);
}

class DefaultSignExecutionService implements SignExecutionService {
  DefaultSignExecutionService({
    required KeyManagementService keyManagementService,
    required SignRequestService signRequestService,
    GpgSigningService? gpgSigningService,
  }) : _keyMgmt = keyManagementService,
       _signRequest = signRequestService,
       _gpgSigning = gpgSigningService ?? DefaultGpgSigningService();

  final KeyManagementService _keyMgmt;
  final SignRequestService _signRequest;
  final GpgSigningService _gpgSigning;

  @override
  Future<SignExecutionResult> executeApproval(
    DecryptedSignRequest request,
  ) async {
    try {
      return await _doApproval(request);
    } on Object catch (e) {
      if (e is SignRequestException) rethrow;
      throw SignRequestException('sign execution failed', cause: e);
    }
  }

  Future<SignExecutionResult> _doApproval(DecryptedSignRequest request) async {
    // 1. Find the matching key entry on the server.
    final entry = await _findKeyEntry(request.keyId);
    if (entry == null) {
      await _signRequest.markUnavailable(request: request);
      return SignExecutionResult.unavailable;
    }

    // 2. Read private key material from secure storage.
    final secretMaterial = await _keyMgmt.readGpgPrivateKey(entry.keygrip);
    if (secretMaterial == null) {
      await _signRequest.markUnavailable(request: request);
      return SignExecutionResult.unavailable;
    }

    try {
      return await _signAndSubmit(request, entry, secretMaterial);
    } finally {
      secretMaterial.fillRange(0, secretMaterial.length, 0);
    }
  }

  Future<SignExecutionResult> _signAndSubmit(
    DecryptedSignRequest request,
    GpgKeyEntry entry,
    Uint8List secretMaterial,
  ) async {
    // 3. Perform the GPG signature.
    final hashBytes = base64Decode(request.hash);
    final sigBytes = _gpgSigning.sign(
      hashBytes: hashBytes,
      hashAlgorithm: request.hashAlgorithm,
      secretMaterial: secretMaterial,
      publicKeyJwk: entry.publicKey,
    );

    if (sigBytes == null) {
      await _signRequest.markUnavailable(request: request);
      return SignExecutionResult.unavailable;
    }

    // 4. Submit approval with the raw signature bytes.
    await _signRequest.approve(request: request, signatureBytes: sigBytes);
    return SignExecutionResult.approved;
  }

  /// Finds a GPG key entry matching [keyId] (hex, possibly "0x"-prefixed).
  Future<GpgKeyEntry?> _findKeyEntry(String keyId) async {
    final normalized = _normalizeKeyId(keyId);
    final response = await _keyMgmt.listGpgKeys();
    for (final entry in response.gpgKeys) {
      if (_normalizeKeyId(entry.keyId) == normalized) return entry;
    }
    return null;
  }

  static String _normalizeKeyId(String keyId) {
    final stripped = keyId.startsWith('0x') || keyId.startsWith('0X')
        ? keyId.substring(2)
        : keyId;
    return stripped.toUpperCase();
  }
}

@Riverpod(keepAlive: true)
SignExecutionService signExecutionService(Ref ref) {
  return DefaultSignExecutionService(
    keyManagementService: ref.read(keyManagementProvider),
    signRequestService: ref.read(signRequestServiceProvider),
  );
}
