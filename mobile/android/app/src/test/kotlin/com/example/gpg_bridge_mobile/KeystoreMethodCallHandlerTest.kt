package com.example.gpg_bridge_mobile

import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException
import java.math.BigInteger
import java.security.GeneralSecurityException
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.ProviderException
import java.security.interfaces.ECPublicKey
import java.security.spec.ECPoint
import java.security.spec.ECGenParameterSpec
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
		val operations = TestAndroidKeystoreOperations(
			existingAliases = setOf("device_key"),
		)

		operations.generateKeyPair("device_key")

		assertTrue(operations.createdKeyPairs.isEmpty())
	}

	@Test
	fun generateKeyPairCreatesDeviceKeyPairWithResolvedAlias() {
		val operations = TestAndroidKeystoreOperations()

		operations.generateKeyPair("device_key")

		assertEquals(listOf("device_key" to true), operations.createdKeyPairs)
	}

	@Test
	fun generateKeyPairCreatesE2eKeyPairWithResolvedAlias() {
		val operations = TestAndroidKeystoreOperations()

		operations.generateKeyPair("e2e_key")

		assertEquals(listOf("e2e_key" to false), operations.createdKeyPairs)
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
	fun requireKnownAliasAcceptsBothSupportedAliases() {
		assertEquals(KeystoreAlias.DEVICE, requireKnownAlias("device_key"))
		assertEquals(KeystoreAlias.E2E, requireKnownAlias("e2e_key"))
	}

	@Test
	fun requireSignAliasAcceptsDeviceAlias() {
		requireSignAlias("device_key")
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
	fun signEncodesProducedSignature() {
		val operations = TestAndroidKeystoreOperations(
			signatureBytes = byteArrayOf(1, 2, 3),
		)

		val result = operations.sign("device_key", "payload")

		assertEquals("1:2:3", result)
		assertSame(operations.privateKeys.getValue("device_key"), operations.lastSignedPrivateKey)
		assertArrayEquals("payload".toByteArray(), operations.lastSignedData)
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
	fun verifyDecodesInputsAndReturnsBackendResult() {
		val operations = TestAndroidKeystoreOperations(
			verifyResult = false,
		)

		val result = operations.verify("device_key", "payload", "signature")

		assertFalse(result)
		assertSame(operations.publicKeys.getValue("device_key"), operations.lastVerifiedPublicKey)
		assertArrayEquals("payload".toByteArray(), operations.lastVerifiedData)
		assertArrayEquals("signature".toByteArray(), operations.lastVerifiedSignature)
	}

	@Test
	fun getPublicKeyJwkBuildsDeviceKeyMetadata() {
		val operations = TestAndroidKeystoreOperations()

		val jwk = operations.getPublicKeyJwk("device_key")

		assertEquals("EC", jwk["kty"])
		assertEquals("sig", jwk["use"])
		assertEquals("P-256", jwk["crv"])
		assertEquals("32:1", jwk["x"])
		assertEquals("32:2", jwk["y"])
		assertEquals("ES256", jwk["alg"])
	}

	@Test
	fun getPublicKeyJwkBuildsE2eKeyMetadata() {
		val operations = TestAndroidKeystoreOperations()

		val jwk = operations.getPublicKeyJwk("e2e_key")

		assertEquals("enc", jwk["use"])
		assertEquals("32:3", jwk["x"])
		assertEquals("32:4", jwk["y"])
		assertEquals("ECDH-ES+A256KW", jwk["alg"])
	}

	@Test
	fun baseContainsAliasAttemptsAndroidKeystoreLookup() {
		val operations = ExposedBaseAndroidKeystoreOperations()

		assertThrows(Exception::class.java) {
			operations.callBaseContainsAlias("device_key")
		}
	}

	@Test
	fun baseCreateKeyPairAttemptsDeviceKeyGeneration() {
		val operations = ExposedBaseAndroidKeystoreOperations()

		assertThrows(Exception::class.java) {
			operations.callBaseCreateKeyPair("device_key", true)
		}
	}

	@Test
	fun baseCreateKeyPairAttemptsE2eKeyGeneration() {
		val operations = ExposedBaseAndroidKeystoreOperations()

		assertThrows(Exception::class.java) {
			operations.callBaseCreateKeyPair("e2e_key", false)
		}
	}

	@Test
	fun baseGetKeyStoreAttemptsAndroidProviderLookup() {
		val operations = ExposedBaseAndroidKeystoreOperations()

		assertThrows(Exception::class.java) {
			operations.callBaseGetKeyStore()
		}
	}

	@Test
	fun baseGetPrivateKeyAttemptsAndroidProviderLookup() {
		val operations = ExposedBaseAndroidKeystoreOperations()

		assertThrows(Exception::class.java) {
			operations.callBaseGetPrivateKey("device_key")
		}
	}

	@Test
	fun baseGetEcPublicKeyAttemptsAndroidProviderLookup() {
		val operations = ExposedBaseAndroidKeystoreOperations()

		assertThrows(Exception::class.java) {
			operations.callBaseGetEcPublicKey("device_key")
		}
	}

	@Test
	fun baseBase64HelpersAttemptAndroidBase64Calls() {
		val operations = ExposedBaseAndroidKeystoreOperations()

		assertThrows(RuntimeException::class.java) {
			operations.callBaseDecodeBase64("AQID")
		}
		assertThrows(RuntimeException::class.java) {
			operations.callBaseEncodeBase64(byteArrayOf(1, 2, 3))
		}
		assertThrows(RuntimeException::class.java) {
			operations.callBaseEncodeBase64Url(byteArrayOf(-5, -1))
		}
	}

	@Test
	fun baseSignAndVerifyUseJcaImplementation() {
		val operations = ExposedBaseAndroidKeystoreOperations()
		val keyPair = KeyPairGenerator.getInstance("EC")
			.apply { initialize(ECGenParameterSpec("secp256r1")) }
			.generateKeyPair()
		val data = "payload".toByteArray()

		val signature = operations.callBaseSignBytes(keyPair.private, data)

		assertTrue(operations.callBaseVerifyBytes(keyPair.public as ECPublicKey, data, signature))
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

	private class TestAndroidKeystoreOperations(
		private val existingAliases: Set<String> = emptySet(),
		val privateKeys: Map<String, PrivateKey> = mapOf(
			"device_key" to FakePrivateKey(),
		),
		val publicKeys: Map<String, ECPublicKey> = mapOf(
			"device_key" to fakeEcPublicKey(BigInteger.ONE, BigInteger.TWO),
			"e2e_key" to fakeEcPublicKey(BigInteger.valueOf(3), BigInteger.valueOf(4)),
		),
		private val signatureBytes: ByteArray = byteArrayOf(9, 8, 7),
		private val verifyResult: Boolean = true,
	) : AndroidKeystoreOperations() {
		val createdKeyPairs = mutableListOf<Pair<String, Boolean>>()
		var lastSignedPrivateKey: PrivateKey? = null
		var lastSignedData: ByteArray? = null
		var lastVerifiedPublicKey: ECPublicKey? = null
		var lastVerifiedData: ByteArray? = null
		var lastVerifiedSignature: ByteArray? = null

		override fun containsAlias(alias: String): Boolean {
			return existingAliases.contains(alias)
		}

		override fun createKeyPair(alias: String, supportsSignAndVerify: Boolean) {
			createdKeyPairs += alias to supportsSignAndVerify
		}

		override fun getPrivateKey(alias: String): PrivateKey {
			return privateKeys.getValue(alias)
		}

		override fun getEcPublicKey(alias: String): ECPublicKey {
			return publicKeys.getValue(alias)
		}

		override fun decodeBase64(value: String): ByteArray {
			return value.toByteArray()
		}

		override fun encodeBase64(value: ByteArray): String {
			return value.joinToString(":") { byte -> (byte.toInt() and 0xff).toString() }
		}

		override fun encodeBase64Url(value: ByteArray): String {
			return "${value.size}:${value.last().toInt() and 0xff}"
		}

		override fun signBytes(privateKey: PrivateKey, data: ByteArray): ByteArray {
			lastSignedPrivateKey = privateKey
			lastSignedData = data
			return signatureBytes
		}

		override fun verifyBytes(publicKey: ECPublicKey, data: ByteArray, signature: ByteArray): Boolean {
			lastVerifiedPublicKey = publicKey
			lastVerifiedData = data
			lastVerifiedSignature = signature
			return verifyResult
		}
	}

	private class FakePrivateKey : PrivateKey {
		override fun getAlgorithm(): String = "EC"

		override fun getFormat(): String = "PKCS#8"

		override fun getEncoded(): ByteArray = byteArrayOf()
	}

	private class ExposedBaseAndroidKeystoreOperations : AndroidKeystoreOperations() {
		fun callBaseContainsAlias(alias: String): Boolean = super.containsAlias(alias)

		fun callBaseCreateKeyPair(alias: String, supportsSignAndVerify: Boolean) =
			super.createKeyPair(alias, supportsSignAndVerify)

		fun callBaseGetKeyStore(): KeyStore = super.getKeyStore()

		fun callBaseGetPrivateKey(alias: String): PrivateKey = super.getPrivateKey(alias)

		fun callBaseGetEcPublicKey(alias: String): ECPublicKey = super.getEcPublicKey(alias)

		fun callBaseDecodeBase64(value: String): ByteArray = super.decodeBase64(value)

		fun callBaseEncodeBase64(value: ByteArray): String = super.encodeBase64(value)

		fun callBaseEncodeBase64Url(value: ByteArray): String = super.encodeBase64Url(value)

		fun callBaseSignBytes(privateKey: PrivateKey, data: ByteArray): ByteArray =
			super.signBytes(privateKey, data)

		fun callBaseVerifyBytes(publicKey: ECPublicKey, data: ByteArray, signature: ByteArray): Boolean =
			super.verifyBytes(publicKey, data, signature)
	}

	private companion object {
		fun fakeEcPublicKey(x: BigInteger, y: BigInteger): ECPublicKey {
			return object : ECPublicKey {
				override fun getW(): ECPoint = ECPoint(x, y)

				override fun getParams() = null

				override fun getAlgorithm(): String = "EC"

				override fun getFormat(): String = "X.509"

				override fun getEncoded(): ByteArray = byteArrayOf()
			}
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
