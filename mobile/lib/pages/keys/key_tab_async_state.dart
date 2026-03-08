import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

mixin AsyncKeyTabState<T, W extends ConsumerStatefulWidget>
    on ConsumerState<W> {
  T? data;
  String? errorMessage;
  bool isLoading = true;

  @protected
  Future<void> loadData(Future<T> Function() loader) async {
    if (mounted) {
      setState(() {
        isLoading = true;
        errorMessage = null;
      });
    } else {
      isLoading = true;
      errorMessage = null;
    }

    try {
      final result = await loader();
      if (!mounted) {
        data = result;
        isLoading = false;
        return;
      }
      setState(() {
        data = result;
        isLoading = false;
      });
    } catch (error) {
      if (!mounted) {
        errorMessage = error.toString();
        isLoading = false;
        return;
      }
      setState(() {
        errorMessage = error.toString();
        isLoading = false;
      });
    }
  }

  @protected
  Future<void> runActionAndReload({
    required Future<void> Function() action,
    required Future<void> Function() reload,
    String? successMessage,
    required String Function(Object error) errorMessageBuilder,
    bool showLoading = false,
  }) async {
    if (showLoading && mounted) {
      setState(() {
        isLoading = true;
        errorMessage = null;
      });
    }

    try {
      await action();
      if (!mounted) {
        return;
      }
      if (successMessage != null) {
        _showSnackBar(successMessage);
      }
      await reload();
    } catch (error) {
      if (showLoading && mounted) {
        setState(() => isLoading = false);
      }
      if (mounted) {
        _showSnackBar(errorMessageBuilder(error));
      }
    }
  }

  void _showSnackBar(String message) {
    ScaffoldMessenger.of(
      context,
    ).showSnackBar(SnackBar(content: Text(message)));
  }
}

Widget buildAsyncKeyTabBody({
  required BuildContext context,
  required bool isLoading,
  required String? errorMessage,
  required VoidCallback onRetry,
  required Widget child,
}) {
  if (isLoading) {
    return const Center(child: CircularProgressIndicator());
  }

  if (errorMessage != null) {
    final textTheme = Theme.of(context).textTheme;
    return Center(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Text('読み込みに失敗しました', style: textTheme.bodyLarge),
          const SizedBox(height: 8),
          Text(errorMessage, style: textTheme.bodySmall),
          const SizedBox(height: 16),
          ElevatedButton(onPressed: onRetry, child: const Text('再試行')),
        ],
      ),
    );
  }

  return child;
}
