package com.example.gpg_bridge_mobile

import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.GeneralSecurityException
import java.util.concurrent.Executor
import java.util.concurrent.RejectedExecutionException

class KeystoreMethodCallHandlerTest {
	private val immediateExecutor = Executor { task -> task.run() }
	private val immediateDispatcher: (Runnable) -> Unit = { task -> task.run() }

	@Test
	fun missingArgumentReturnsInvalidArgumentError() {
		val handler = KeystoreMethodCallHandler(
			operations = FakeKeystoreOperations(),
			backgroundExecutor = immediateExecutor,
			postToMainThread = immediateDispatcher,
		)
		val result = CapturingResult()

		handler.onMethodCall(
			MethodCall("generateKeyPair", mapOf<String, Any>()),
			result,
		)

		assertEquals("INVALID_ARGUMENT", result.errorCode)
		assertTrue(result.errorMessage?.contains("missing argument: alias") == true)
		assertNull(result.successValue)
	}

	@Test
	fun invalidAliasReturnsInvalidArgumentError() {
		val handler = KeystoreMethodCallHandler(
			operations = FakeKeystoreOperations(
				onGenerateKeyPair = { throw IllegalArgumentException("unsupported alias: bad_alias") },
			),
			backgroundExecutor = immediateExecutor,
			postToMainThread = immediateDispatcher,
		)
		val result = CapturingResult()

		handler.onMethodCall(
			MethodCall("generateKeyPair", mapOf("alias" to "bad_alias")),
			result,
		)

		assertEquals("INVALID_ARGUMENT", result.errorCode)
		assertTrue(result.errorMessage?.contains("unsupported alias") == true)
		assertNull(result.successValue)
	}

	@Test
	fun invalidBase64ReturnsInvalidArgumentError() {
		val handler = KeystoreMethodCallHandler(
			operations = FakeKeystoreOperations(
				onSign = { _, _ -> throw IllegalArgumentException("invalid base64 payload") },
			),
			backgroundExecutor = immediateExecutor,
			postToMainThread = immediateDispatcher,
		)
		val result = CapturingResult()

		handler.onMethodCall(
			MethodCall(
				"sign",
				mapOf(
					"alias" to "device_key",
					"dataBase64" to "!!!!",
				),
			),
			result,
		)

		assertEquals("INVALID_ARGUMENT", result.errorCode)
		assertTrue(result.errorMessage?.contains("base64") == true)
		assertNull(result.successValue)
	}

	@Test
	fun generalSecurityExceptionReturnsKeystoreError() {
		val handler = KeystoreMethodCallHandler(
			operations = FakeKeystoreOperations(
				onGetPublicKeyJwk = { throw GeneralSecurityException("keystore unavailable") },
			),
			backgroundExecutor = immediateExecutor,
			postToMainThread = immediateDispatcher,
		)
		val result = CapturingResult()

		handler.onMethodCall(
			MethodCall("getPublicKeyJwk", mapOf("alias" to "device_key")),
			result,
		)

		assertEquals("KEYSTORE_ERROR", result.errorCode)
		assertTrue(result.errorMessage?.contains("keystore unavailable") == true)
		assertNull(result.successValue)
	}

	@Test
	fun rejectedExecutionReturnsKeystoreError() {
		val rejectingExecutor = Executor { throw RejectedExecutionException("executor is shut down") }
		val handler = KeystoreMethodCallHandler(
			operations = FakeKeystoreOperations(),
			backgroundExecutor = rejectingExecutor,
			postToMainThread = immediateDispatcher,
		)
		val result = CapturingResult()

		handler.onMethodCall(
			MethodCall("generateKeyPair", mapOf("alias" to "device_key")),
			result,
		)

		assertEquals("KEYSTORE_ERROR", result.errorCode)
		assertTrue(result.errorMessage?.contains("executor rejected task") == true)
		assertNull(result.successValue)
	}

	private class FakeKeystoreOperations(
		private val onGenerateKeyPair: (String) -> Unit = {},
		private val onSign: (String, String) -> String = { _, _ -> "signed" },
		private val onVerify: (String, String, String) -> Boolean = { _, _, _ -> true },
		private val onGetPublicKeyJwk: (String) -> Map<String, String> = { mapOf("kty" to "EC") },
	) : KeystoreOperations {
		override fun generateKeyPair(alias: String) {
			onGenerateKeyPair(alias)
		}

		override fun sign(alias: String, dataBase64: String): String {
			return onSign(alias, dataBase64)
		}

		override fun verify(alias: String, dataBase64: String, signatureBase64: String): Boolean {
			return onVerify(alias, dataBase64, signatureBase64)
		}

		override fun getPublicKeyJwk(alias: String): Map<String, String> {
			return onGetPublicKeyJwk(alias)
		}
	}

	private class CapturingResult : MethodChannel.Result {
		var successValue: Any? = null
		var errorCode: String? = null
		var errorMessage: String? = null
		var notImplemented = false

		override fun success(result: Any?) {
			successValue = result
		}

		override fun error(errorCode: String, errorMessage: String?, errorDetails: Any?) {
			this.errorCode = errorCode
			this.errorMessage = errorMessage
		}

		override fun notImplemented() {
			notImplemented = true
		}
	}
}
