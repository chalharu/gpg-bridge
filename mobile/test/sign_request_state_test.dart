import 'dart:typed_data';

import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:gpg_bridge_mobile/security/ec_jwk.dart';
import 'package:gpg_bridge_mobile/state/sign_execution_service.dart';
import 'package:gpg_bridge_mobile/state/sign_request_service.dart';
import 'package:gpg_bridge_mobile/state/sign_request_state.dart';

const _testPublicJwk = {
  'kty': 'EC',
  'crv': 'P-256',
  'x': '0qHaLh3jKQAQ5tYB6NooOi2lFjJj9E5h80yoHSZoq0I',
  'y': 'F8CORGPfI9872Nxw2Fkr6XUn-5AczutLMi9uRygC7pE',
};

DecryptedSignRequest _buildRequest({
  String requestId = 'req-1',
  DateTime? receivedAt,
}) {
  return DecryptedSignRequest(
    requestId: requestId,
    signJwt: 'jwt-$requestId',
    hash: 'dGVzdCBoYXNoIHZhbHVl',
    hashAlgorithm: 'sha256',
    keyId: '0xABCD1234',
    pairingId: 'pair-1',
    daemonEncPublicKey: EcPublicJwk.fromJson(_testPublicJwk),
    receivedAt: receivedAt ?? DateTime.now(),
  );
}

void main() {
  group('SignRequestState', () {
    late _MockSignRequestService mockService;
    late _MockSignExecutionService mockExecution;

    setUp(() {
      mockService = _MockSignRequestService();
      mockExecution = _MockSignExecutionService();
    });

    ProviderContainer createContainer() {
      return ProviderContainer(
        overrides: [
          signRequestServiceProvider.overrideWithValue(mockService),
          signExecutionServiceProvider.overrideWithValue(mockExecution),
        ],
      );
    }

    test('build() fetches and filters expired requests', () async {
      final fresh = _buildRequest(requestId: 'fresh');
      final expired = _buildRequest(
        requestId: 'expired',
        receivedAt: DateTime.now().subtract(const Duration(minutes: 10)),
      );
      mockService.requestsToReturn = [fresh, expired];

      final container = createContainer();
      addTearDown(container.dispose);

      final result = await container.read(signRequestStateProvider.future);

      expect(result, hasLength(1));
      expect(result.first.requestId, 'fresh');
    });

    test('refresh() re-fetches requests', () async {
      mockService.requestsToReturn = [_buildRequest(requestId: 'req-1')];

      final container = createContainer();
      addTearDown(container.dispose);

      // Initial load.
      await container.read(signRequestStateProvider.future);
      expect(mockService.fetchCount, 1);

      // Add a new request and refresh.
      mockService.requestsToReturn = [
        _buildRequest(requestId: 'req-1'),
        _buildRequest(requestId: 'req-2'),
      ];
      final notifier = container.read(signRequestStateProvider.notifier);
      await notifier.refresh();

      final updated = container.read(signRequestStateProvider).value!;
      expect(updated, hasLength(2));
      expect(mockService.fetchCount, 2);
    });

    test('dismiss() removes a request by ID', () async {
      mockService.requestsToReturn = [
        _buildRequest(requestId: 'req-1'),
        _buildRequest(requestId: 'req-2'),
      ];

      final container = createContainer();
      addTearDown(container.dispose);

      await container.read(signRequestStateProvider.future);
      final notifier = container.read(signRequestStateProvider.notifier);
      notifier.dismiss('req-1');

      final state = container.read(signRequestStateProvider).value!;
      expect(state, hasLength(1));
      expect(state.first.requestId, 'req-2');
    });

    test('approve() calls executeApproval and dismisses on success', () async {
      final request = _buildRequest(requestId: 'req-approve');
      mockService.requestsToReturn = [request];
      mockExecution.resultToReturn = SignExecutionResult.approved;

      final container = createContainer();
      addTearDown(container.dispose);

      await container.read(signRequestStateProvider.future);
      final notifier = container.read(signRequestStateProvider.notifier);
      await notifier.approve(request);

      expect(mockExecution.approvedRequests, ['req-approve']);
      final state = container.read(signRequestStateProvider).value!;
      expect(state, isEmpty);
    });

    test('approve() dismisses on unavailable result', () async {
      final request = _buildRequest(requestId: 'req-unavail');
      mockService.requestsToReturn = [request];
      mockExecution.resultToReturn = SignExecutionResult.unavailable;

      final container = createContainer();
      addTearDown(container.dispose);

      await container.read(signRequestStateProvider.future);
      final notifier = container.read(signRequestStateProvider.notifier);
      await notifier.approve(request);

      final state = container.read(signRequestStateProvider).value!;
      expect(state, isEmpty);
    });

    test('approve() keeps request on error result', () async {
      final request = _buildRequest(requestId: 'req-err');
      mockService.requestsToReturn = [request];
      mockExecution.resultToReturn = SignExecutionResult.error;

      final container = createContainer();
      addTearDown(container.dispose);

      await container.read(signRequestStateProvider.future);
      final notifier = container.read(signRequestStateProvider.notifier);
      await notifier.approve(request);

      final state = container.read(signRequestStateProvider).value!;
      expect(state, hasLength(1));
    });

    test('deny() delegates to service and dismisses', () async {
      final request = _buildRequest(requestId: 'req-deny');
      mockService.requestsToReturn = [request];

      final container = createContainer();
      addTearDown(container.dispose);

      await container.read(signRequestStateProvider.future);
      final notifier = container.read(signRequestStateProvider.notifier);
      await notifier.deny(request);

      expect(mockService.deniedRequests, ['req-deny']);
      final state = container.read(signRequestStateProvider).value!;
      expect(state, isEmpty);
    });

    test('markUnavailable() delegates to service and dismisses', () async {
      final request = _buildRequest(requestId: 'req-mark');
      mockService.requestsToReturn = [request];

      final container = createContainer();
      addTearDown(container.dispose);

      await container.read(signRequestStateProvider.future);
      final notifier = container.read(signRequestStateProvider.notifier);
      await notifier.markUnavailable(request);

      expect(mockService.unavailableRequests, ['req-mark']);
      final state = container.read(signRequestStateProvider).value!;
      expect(state, isEmpty);
    });
  });
}

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

class _MockSignRequestService implements SignRequestService {
  List<DecryptedSignRequest> requestsToReturn = [];
  int fetchCount = 0;
  final List<String> deniedRequests = [];
  final List<String> unavailableRequests = [];

  @override
  Future<List<DecryptedSignRequest>> fetchAndDecrypt() async {
    fetchCount++;
    return requestsToReturn;
  }

  @override
  Future<void> approve({
    required DecryptedSignRequest request,
    required Uint8List signatureBytes,
  }) async {}

  @override
  Future<void> deny({required DecryptedSignRequest request}) async {
    deniedRequests.add(request.requestId);
  }

  @override
  Future<void> markUnavailable({required DecryptedSignRequest request}) async {
    unavailableRequests.add(request.requestId);
  }
}

class _MockSignExecutionService implements SignExecutionService {
  SignExecutionResult resultToReturn = SignExecutionResult.approved;
  final List<String> approvedRequests = [];

  @override
  Future<SignExecutionResult> executeApproval(
    DecryptedSignRequest request,
  ) async {
    approvedRequests.add(request.requestId);
    return resultToReturn;
  }
}
