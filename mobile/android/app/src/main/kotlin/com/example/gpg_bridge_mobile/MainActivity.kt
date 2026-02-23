package com.example.gpg_bridge_mobile

import io.flutter.embedding.engine.FlutterEngine
import io.flutter.embedding.android.FlutterActivity
import io.flutter.plugin.common.MethodChannel
import java.util.concurrent.Executors

class MainActivity : FlutterActivity() {
	companion object {
		private const val CHANNEL_NAME = "gpg_bridge/keystore"
	}

	private val methodExecutor = Executors.newSingleThreadExecutor()
	private val methodCallHandler = KeystoreMethodCallHandler(
		operations = AndroidKeystoreOperations(),
		backgroundExecutor = methodExecutor,
		postToMainThread = { task -> runOnUiThread(task) },
	)

	override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
		super.configureFlutterEngine(flutterEngine)

		MethodChannel(flutterEngine.dartExecutor.binaryMessenger, CHANNEL_NAME)
			.setMethodCallHandler(methodCallHandler::onMethodCall)
	}

	override fun onDestroy() {
		methodExecutor.shutdown()
		super.onDestroy()
	}
}
