import 'package:riverpod_annotation/riverpod_annotation.dart';

part 'fid_service.g.dart';

/// Firebase Installation ID provider abstraction.
abstract interface class FidService {
  Future<String> getId();
}

/// Provider for Firebase Installation ID.
///
/// Override this provider in tests or if a different FID source is needed.
@Riverpod(keepAlive: true)
FidService fidService(Ref ref) {
  return _DefaultFidService();
}

/// Default implementation that throws until overridden.
///
/// In a production setup this would use `FirebaseInstallations.instance.getId()`.
/// Since firebase_installations requires separate dependency, we delegate
/// to a provider that can be overridden.
// Replace with firebase_installations once that dependency is introduced.
class _DefaultFidService implements FidService {
  @override
  Future<String> getId() async {
    throw UnimplementedError(
      'FidService not configured. Override fidServiceProvider.',
    );
  }
}
