package com.example.gpg_bridge_mobile

import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException
import java.security.GeneralSecurityException
import java.security.ProviderException
import java.util.concurrent.Executor
import java.util.concurrent.RejectedExecutionException

class KeystoreMethodCallHandlerTest {
	private val immediateExecutor = Executor { task -> task.run() }
	private val immediateDispatcher: (Runnable) -> Unit = { task -> task.run() }

	@Test
	fun unsupportedMethodReturnsNotImplemented() {
		val handler = KeystoreMethodCallHandler(
			operations = FakeKeystoreOperations(),
			backgroundExecutor = immediateExecutor,
			postToMainThread = immediateDispatcher,
		)
		val result = CapturingResult()

		handler.onMethodCall(MethodCall("unknown", null), result)

		assertTrue(result.notImplemented)
		assertNull(result.successValue)
		assertNull(result.errorCode)
	}

	@Test
	fun parseSupportedMethodReturnsEnumForSupportedMethods() {
		assertEquals(SupportedMethod.GENERATE_KEY_PAIR, parseSupportedMethod("generateKeyPair"))
		assertEquals(SupportedMethod.SIGN, parseSupportedMethod("sign"))
		assertEquals(SupportedMethod.VERIFY, parseSupportedMethod("verify"))
		assertEquals(SupportedMethod.GET_PUBLIC_KEY_JWK, parseSupportedMethod("getPublicKeyJwk"))
	}

	@Test
	fun parseSupportedMethodReturnsNullForUnsupportedMethod() {
		assertNull(parseSupportedMethod("unknown"))
	}

	@Test
	fun generateKeyPairReturnsTrueOnSuccess() {
		val handler = KeystoreMethodCallHandler(
			operations = FakeKeystoreOperations(),
			backgroundExecutor = immediateExecutor,
			postToMainThread = immediateDispatcher,
		)
		val result = CapturingResult()

		handler.onMethodCall(
			MethodCall("generateKeyPair", mapOf("alias" to "device_key")),
			result,
		)

		assertEquals(true, result.successValue)
		assertNull(result.errorCode)
	}

	@Test
	fun signReturnsSignatureOnSuccess() {
		val handler = KeystoreMethodCallHandler(
			operations = FakeKeystoreOperations(
				onSign = { alias, dataBase64 -> "$alias:$dataBase64" },
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
					"dataBase64" to "payload",
				),
			),
			result,
		)

		assertEquals("device_key:payload", result.successValue)
		assertNull(result.errorCode)
	}

	@Test
	fun verifyReturnsBooleanOnSuccess() {
		val handler = KeystoreMethodCallHandler(
			operations = FakeKeystoreOperations(
				onVerify = { _, _, _ -> false },
			),
			backgroundExecutor = immediateExecutor,
			postToMainThread = immediateDispatcher,
		)
		val result = CapturingResult()

		handler.onMethodCall(
			MethodCall(
				"verify",
				mapOf(
					"alias" to "device_key",
					"dataBase64" to "payload",
					"signatureBase64" to "sig",
				),
			),
			result,
		)

		assertEquals(false, result.successValue)
		assertNull(result.errorCode)
	}

	@Test
	fun getPublicKeyJwkReturnsMapOnSuccess() {
		val handler = KeystoreMethodCallHandler(
			operations = FakeKeystoreOperations(
				onGetPublicKeyJwk = { mapOf("kty" to "EC", "use" to "sig") },
			),
			backgroundExecutor = immediateExecutor,
			postToMainThread = immediateDispatcher,
		)
		val result = CapturingResult()

		handler.onMethodCall(
			MethodCall("getPublicKeyJwk", mapOf("alias" to "device_key")),
			result,
		)

		assertEquals(mapOf("kty" to "EC", "use" to "sig"), result.successValue)
		assertNull(result.errorCode)
	}

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
	fun providerExceptionReturnsKeystoreError() {
		val handler = KeystoreMethodCallHandler(
			operations = FakeKeystoreOperations(
				onGetPublicKeyJwk = { throw ProviderException("provider failure") },
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
		assertTrue(result.errorMessage?.contains("provider failure") == true)
		assertNull(result.successValue)
	}

	@Test
	fun ioExceptionReturnsKeystoreError() {
		val handler = KeystoreMethodCallHandler(
			operations = FakeKeystoreOperations(
				onGetPublicKeyJwk = { throw IOException("io failure") },
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
		assertTrue(result.errorMessage?.contains("io failure") == true)
		assertNull(result.successValue)
	}

	@Test
	fun illegalStateReturnsKeystoreError() {
		val handler = KeystoreMethodCallHandler(
			operations = FakeKeystoreOperations(
				onGetPublicKeyJwk = { throw IllegalStateException("bad state") },
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
		assertTrue(result.errorMessage?.contains("bad state") == true)
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

	@Test
	fun generateKeyPairRejectsUnknownAliasBeforeKeystoreAccess() {
		val operations = AndroidKeystoreOperations()

		val error = assertThrows(IllegalArgumentException::class.java) {
			operations.generateKeyPair("bad_alias")
		}

		assertEquals("unsupported alias: bad_alias", error.message)
	}

	@Test
	fun generateKeyPairReturnsWhenAliasAlreadyExists() {
		val operations = FakeKeystoreOperations()
		val handler = KeystoreMethodCallHandler(
			operations = operations,
			backgroundExecutor = immediateExecutor,
			postToMainThread = immediateDispatcher,
		)
		val result = CapturingResult()

		handler.onMethodCall(
			MethodCall("generateKeyPair", mapOf("alias" to "device_key")),
			result,
		)

		assertEquals(true, result.successValue)
	}

	@Test
	fun getPublicKeyJwkRejectsUnknownAliasBeforeKeystoreAccess() {
		val operations = AndroidKeystoreOperations()

		val error = assertThrows(IllegalArgumentException::class.java) {
			operations.getPublicKeyJwk("bad_alias")
		}

		assertEquals("unsupported alias: bad_alias", error.message)
	}

	@Test
	fun parseKeystoreAliasAcceptsBothSupportedAliases() {
		assertEquals(KeystoreAlias.DEVICE, parseKeystoreAlias("device_key"))
		assertEquals(KeystoreAlias.E2E, parseKeystoreAlias("e2e_key"))
	}

	@Test
	fun requireSignAliasAcceptsDeviceAlias() {
		requireSignAlias("device_key")
	}

	@Test
	fun requireKnownAliasRejectsUnknownAlias() {
		val error = assertThrows(IllegalArgumentException::class.java) {
			requireKnownAlias("bad_alias")
		}

		assertEquals("unsupported alias: bad_alias", error.message)
	}

	@Test
	fun signRejectsEncryptionOnlyAlias() {
		val operations = AndroidKeystoreOperations()

		val error = assertThrows(IllegalArgumentException::class.java) {
			operations.sign("e2e_key", "ignored")
		}

		assertEquals("alias does not support sign/verify: e2e_key", error.message)
	}

	@Test
	fun verifyRejectsUnknownAlias() {
		val operations = AndroidKeystoreOperations()

		val error = assertThrows(IllegalArgumentException::class.java) {
			operations.verify("bad_alias", "ignored", "ignored")
		}

		assertEquals("alias does not support sign/verify: bad_alias", error.message)
	}

	@Test
	fun requireSignAliasRejectsEncryptionOnlyAlias() {
		val error = assertThrows(IllegalArgumentException::class.java) {
			requireSignAlias("e2e_key")
		}

		assertEquals("alias does not support sign/verify: e2e_key", error.message)
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
