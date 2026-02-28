// Types for FCM message handling.

/// Parsed FCM data message types.
enum FcmMessageType {
  /// A new sign request is pending.
  signRequest,

  /// A previously pending sign request was cancelled.
  signRequestCancelled,
}

/// A parsed FCM data message.
class FcmDataMessage {
  FcmDataMessage({required this.type, this.requestId});

  final FcmMessageType type;
  final String? requestId;
}

/// Parses a raw FCM data payload into a typed [FcmDataMessage].
///
/// Returns `null` if the data does not contain a recognized message type.
FcmDataMessage? parseFcmData(Map<String, dynamic> data) {
  final rawType = data['type'];
  if (rawType is! String) return null;

  switch (rawType) {
    case 'sign_request':
      final requestId = data['request_id'] as String?;
      if (requestId == null || requestId.isEmpty) return null;
      return FcmDataMessage(
        type: FcmMessageType.signRequest,
        requestId: requestId,
      );
    case 'sign_request_cancelled':
      final requestId = data['request_id'] as String?;
      return FcmDataMessage(
        type: FcmMessageType.signRequestCancelled,
        requestId: requestId,
      );
    default:
      return null;
  }
}
