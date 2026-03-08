package com.example.gpg_bridge_mobile

import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException
import java.security.GeneralSecurityException
import java.security.Key
import java.security.KeyStore
import java.security.KeyStoreSpi
import java.security.PrivateKey
import java.security.Provider
import java.security.ProviderException
import java.security.PublicKey
import java.security.cert.Certificate
import java.security.spec.ECFieldFp
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.EllipticCurve
import java.math.BigInteger
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
	fun requireKnownAliasAcceptsKnownAliases() {
		assertEquals(Unit, requireKnownAlias("device_key"))
		assertEquals(Unit, requireKnownAlias("e2e_key"))
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
	fun generateKeyPairSkipsGenerationWhenAliasAlreadyExists() {
		val keyStore = RecordingKeyStoreAccess(existingAliases = setOf("device_key"))
		val generator = RecordingKeyPairGeneratorAccess()
		val operations = AndroidKeystoreOperations(
			AndroidKeystoreDependencies(
				keyStoreAccess = { keyStore },
				keyPairGeneratorAccess = { generator },
			),
		)

		operations.generateKeyPair("device_key")

		assertNull(generator.initializedWith)
		assertEquals(0, generator.generateCalls)
	}

	@Test
	fun generateKeyPairBuildsSigningRequestForDeviceAlias() {
		val generator = RecordingKeyPairGeneratorAccess()
		val operations = AndroidKeystoreOperations(
			AndroidKeystoreDependencies(
				keyStoreAccess = { RecordingKeyStoreAccess() },
				keyPairGeneratorAccess = { generator },
			),
		)

		operations.generateKeyPair("device_key")

		assertEquals(
			KeystoreKeyGenRequest(
				alias = "device_key",
				purposes = android.security.keystore.KeyProperties.PURPOSE_SIGN or android.security.keystore.KeyProperties.PURPOSE_VERIFY,
				includeSha256Digest = true,
			),
			generator.initializedWith,
		)
		assertEquals(1, generator.generateCalls)
	}

	@Test
	fun generateKeyPairBuildsAgreementRequestForEncryptionAlias() {
		val generator = RecordingKeyPairGeneratorAccess()
		val operations = AndroidKeystoreOperations(
			AndroidKeystoreDependencies(
				keyStoreAccess = { RecordingKeyStoreAccess() },
				keyPairGeneratorAccess = { generator },
			),
		)

		operations.generateKeyPair("e2e_key")

		assertEquals(
			KeystoreKeyGenRequest(
				alias = "e2e_key",
				purposes = android.security.keystore.KeyProperties.PURPOSE_AGREE_KEY,
				includeSha256Digest = false,
			),
			generator.initializedWith,
		)
		assertEquals(1, generator.generateCalls)
	}

	@Test
	fun signUsesInjectedCryptoAndBase64Codec() {
		val privateKey = FakePrivateKey()
		val keyStore = RecordingKeyStoreAccess(privateKeys = mapOf("device_key" to privateKey))
		val signatureAccess = RecordingSignatureAccess(signResult = byteArrayOf(9, 8, 7))
		val base64Codec = RecordingBase64Codec(decodedValues = mapOf("payload" to byteArrayOf(1, 2, 3)))
		val operations = AndroidKeystoreOperations(
			AndroidKeystoreDependencies(
				keyStoreAccess = { keyStore },
				signatureAccess = signatureAccess,
				base64Codec = base64Codec,
			),
		)

		val signature = operations.sign("device_key", "payload")

		assertEquals("encoded:9,8,7", signature)
		assertEquals(privateKey, signatureAccess.lastPrivateKey)
		assertEquals(byteArrayOf(1, 2, 3).toList(), signatureAccess.lastSignedData?.toList())
	}

	@Test
	fun signRejectsMissingPrivateKey() {
		val operations = AndroidKeystoreOperations(
			AndroidKeystoreDependencies(keyStoreAccess = { RecordingKeyStoreAccess() }),
		)

		val error = assertThrows(IllegalArgumentException::class.java) {
			operations.sign("device_key", "payload")
		}

		assertEquals("key alias not found: device_key", error.message)
	}

	@Test
	fun verifyUsesInjectedCryptoAndDecodedInputs() {
		val publicKey = FakeECPublicKey(x = BigInteger.valueOf(10), y = BigInteger.valueOf(20))
		val keyStore = RecordingKeyStoreAccess(publicKeys = mapOf("device_key" to publicKey))
		val signatureAccess = RecordingSignatureAccess(verifyResult = false)
		val base64Codec = RecordingBase64Codec(
			decodedValues = mapOf(
				"payload" to byteArrayOf(4, 5),
				"signature" to byteArrayOf(6, 7),
			),
		)
		val operations = AndroidKeystoreOperations(
			AndroidKeystoreDependencies(
				keyStoreAccess = { keyStore },
				signatureAccess = signatureAccess,
				base64Codec = base64Codec,
			),
		)

		val verified = operations.verify("device_key", "payload", "signature")

		assertFalse(verified)
		assertEquals(publicKey, signatureAccess.lastPublicKey)
		assertEquals(byteArrayOf(4, 5).toList(), signatureAccess.lastVerifiedData?.toList())
		assertEquals(byteArrayOf(6, 7).toList(), signatureAccess.lastVerifiedSignature?.toList())
	}

	@Test
	fun verifyRejectsMissingCertificate() {
		val operations = AndroidKeystoreOperations(
			AndroidKeystoreDependencies(keyStoreAccess = { RecordingKeyStoreAccess() }),
		)

		val error = assertThrows(IllegalArgumentException::class.java) {
			operations.verify("device_key", "payload", "signature")
		}

		assertEquals("certificate not found for alias: device_key", error.message)
	}

	@Test
	fun verifyRejectsNonEcPublicKey() {
		val operations = AndroidKeystoreOperations(
			AndroidKeystoreDependencies(
				keyStoreAccess = {
					RecordingKeyStoreAccess(publicKeys = mapOf("device_key" to FakePublicKey()))
				},
			),
		)

		val error = assertThrows(IllegalArgumentException::class.java) {
			operations.verify("device_key", "payload", "signature")
		}

		assertEquals("public key is not EC for alias: device_key", error.message)
	}

	@Test
	fun getPublicKeyJwkBuildsDeviceKeyMetadata() {
		val publicKey = FakeECPublicKey(x = BigInteger.valueOf(10), y = BigInteger.valueOf(20))
		val operations = AndroidKeystoreOperations(
			AndroidKeystoreDependencies(
				keyStoreAccess = { RecordingKeyStoreAccess(publicKeys = mapOf("device_key" to publicKey)) },
				base64Codec = RecordingBase64Codec(),
			),
		)

		val jwk = operations.getPublicKeyJwk("device_key")

		assertEquals(
			mapOf(
				"kty" to "EC",
				"use" to "sig",
				"crv" to "P-256",
				"x" to "url:32:10",
				"y" to "url:32:20",
				"alg" to "ES256",
			),
			jwk,
		)
	}

	@Test
	fun getPublicKeyJwkBuildsEncryptionKeyMetadata() {
		val publicKey = FakeECPublicKey(x = BigInteger.ONE, y = BigInteger.TWO)
		val operations = AndroidKeystoreOperations(
			AndroidKeystoreDependencies(
				keyStoreAccess = { RecordingKeyStoreAccess(publicKeys = mapOf("e2e_key" to publicKey)) },
				base64Codec = RecordingBase64Codec(),
			),
		)

		val jwk = operations.getPublicKeyJwk("e2e_key")

		assertEquals("enc", jwk["use"])
		assertEquals("ECDH-ES+A256KW", jwk["alg"])
	}

	@Test
	fun getPublicKeyJwkRejectsNonEcPublicKey() {
		val operations = AndroidKeystoreOperations(
			AndroidKeystoreDependencies(
				keyStoreAccess = {
					RecordingKeyStoreAccess(publicKeys = mapOf("device_key" to FakePublicKey()))
				},
			),
		)

		val error = assertThrows(IllegalArgumentException::class.java) {
			operations.getPublicKeyJwk("device_key")
		}

		assertEquals("public key is not EC for alias: device_key", error.message)
	}

	@Test
	fun requireSignAliasRejectsEncryptionOnlyAlias() {
		val error = assertThrows(IllegalArgumentException::class.java) {
			requireSignAlias("e2e_key")
		}

		assertEquals("alias does not support sign/verify: e2e_key", error.message)
	}

	@Test
	fun systemKeyStoreAccessDelegatesContainsAlias() {
		val spi = RecordingKeyStoreSpi(containsAliasResult = true)
		val access = SystemKeyStoreAccess(createTestKeyStore(spi))

		assertTrue(access.containsAlias("device_key"))
		assertEquals("device_key", spi.lastContainsAliasAlias)
	}

	@Test
	fun systemKeyStoreAccessDelegatesGetPrivateKeyAndNarrowsType() {
		val privateKey = FakePrivateKey()
		val privateKeySpi = RecordingKeyStoreSpi(keys = mapOf("device_key" to privateKey))
		val privateKeyAccess = SystemKeyStoreAccess(createTestKeyStore(privateKeySpi))

		assertEquals(privateKey, privateKeyAccess.getPrivateKey("device_key"))
		assertEquals("device_key", privateKeySpi.lastGetKeyAlias)

		val nonPrivateKeySpi = RecordingKeyStoreSpi(keys = mapOf("device_key" to FakeKey()))
		val nonPrivateKeyAccess = SystemKeyStoreAccess(createTestKeyStore(nonPrivateKeySpi))

		assertNull(nonPrivateKeyAccess.getPrivateKey("device_key"))
		assertEquals("device_key", nonPrivateKeySpi.lastGetKeyAlias)
	}

	@Test
	fun systemKeyStoreAccessDelegatesGetPublicKey() {
		val publicKey = FakePublicKey()
		val spi = RecordingKeyStoreSpi(
			certificates = mapOf("device_key" to FakeCertificate(publicKey)),
		)
		val access = SystemKeyStoreAccess(createTestKeyStore(spi))

		assertEquals(publicKey, access.getPublicKey("device_key"))
		assertEquals("device_key", spi.lastGetCertificateAlias)
	}

	@Test
	fun defaultKeyStoreAccessFactoryUsesInjectedSystemKeyStoreCreator() {
		val spi = RecordingKeyStoreSpi(containsAliasResult = true)
		val access = AndroidKeystoreDependencies(
			createSystemKeyStore = { createTestKeyStore(spi) },
		).keyStoreAccess()

		assertTrue(access is SystemKeyStoreAccess)
		assertTrue(access.containsAlias("device_key"))
		assertEquals("device_key", spi.lastContainsAliasAlias)
	}

	private fun createTestKeyStore(spi: KeyStoreSpi): KeyStore {
		val provider = object : Provider("TestProvider", 1.0, "Test provider") {}
		return object : KeyStore(spi, provider, "TestKeyStore") {}.apply { load(null, null) }
	}

	private class RecordingKeyStoreAccess(
		private val existingAliases: Set<String> = emptySet(),
		private val privateKeys: Map<String, PrivateKey> = emptyMap(),
		private val publicKeys: Map<String, PublicKey> = emptyMap(),
	) : KeyStoreAccess {
		override fun containsAlias(alias: String): Boolean = alias in existingAliases

		override fun getPrivateKey(alias: String): PrivateKey? = privateKeys[alias]

		override fun getPublicKey(alias: String): PublicKey? = publicKeys[alias]
	}

	private class RecordingKeyPairGeneratorAccess : KeyPairGeneratorAccess {
		var initializedWith: KeystoreKeyGenRequest? = null
		var generateCalls = 0

		override fun initialize(request: KeystoreKeyGenRequest) {
			initializedWith = request
		}

		override fun generateKeyPair() {
			generateCalls += 1
		}
	}

	private class RecordingSignatureAccess(
		private val signResult: ByteArray = byteArrayOf(1, 2, 3),
		private val verifyResult: Boolean = true,
	) : SignatureAccess {
		var lastPrivateKey: PrivateKey? = null
		var lastPublicKey: FakeECPublicKey? = null
		var lastSignedData: ByteArray? = null
		var lastVerifiedData: ByteArray? = null
		var lastVerifiedSignature: ByteArray? = null

		override fun sign(privateKey: PrivateKey, data: ByteArray): ByteArray {
			lastPrivateKey = privateKey
			lastSignedData = data
			return signResult
		}

		override fun verify(publicKey: java.security.interfaces.ECPublicKey, data: ByteArray, signature: ByteArray): Boolean {
			lastPublicKey = publicKey as FakeECPublicKey
			lastVerifiedData = data
			lastVerifiedSignature = signature
			return verifyResult
		}
	}

	private class RecordingBase64Codec(
		private val decodedValues: Map<String, ByteArray> = emptyMap(),
	) : Base64Codec {
		override fun decode(value: String): ByteArray {
			return decodedValues[value] ?: value.encodeToByteArray()
		}

		override fun encode(value: ByteArray): String {
			return "encoded:${value.joinToString(",")}" 
		}

		override fun encodeUrl(value: ByteArray): String {
			return "url:${value.size}:${value.last().toInt() and 0xff}"
		}
	}

	private class FakePrivateKey : PrivateKey {
		override fun getAlgorithm(): String = "EC"

		override fun getFormat(): String = "PKCS#8"

		override fun getEncoded(): ByteArray = byteArrayOf()
	}

	private class FakeKey : Key {
		override fun getAlgorithm(): String = "RAW"

		override fun getFormat(): String = "RAW"

		override fun getEncoded(): ByteArray = byteArrayOf(1)
	}

	private class FakePublicKey : PublicKey {
		override fun getAlgorithm(): String = "RSA"

		override fun getFormat(): String = "X.509"

		override fun getEncoded(): ByteArray = byteArrayOf()
	}

	private class FakeCertificate(
		private val publicKey: PublicKey,
	) : Certificate("X.509") {
		override fun getEncoded(): ByteArray = byteArrayOf()

		override fun verify(key: PublicKey) = Unit

		override fun verify(key: PublicKey, sigProvider: String) = Unit

		override fun toString(): String = "FakeCertificate"

		override fun getPublicKey(): PublicKey = publicKey
	}

	private class FakeECPublicKey(
		private val x: BigInteger,
		private val y: BigInteger,
	) : java.security.interfaces.ECPublicKey {
		override fun getW(): ECPoint = ECPoint(x, y)

		override fun getParams(): ECParameterSpec {
			val curve = EllipticCurve(ECFieldFp(BigInteger.valueOf(23)), BigInteger.ONE, BigInteger.ONE)
			return ECParameterSpec(curve, ECPoint(BigInteger.ONE, BigInteger.ONE), BigInteger.valueOf(19), 1)
		}

		override fun getAlgorithm(): String = "EC"

		override fun getFormat(): String = "X.509"

		override fun getEncoded(): ByteArray = byteArrayOf()
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

	private class RecordingKeyStoreSpi(
		private val containsAliasResult: Boolean = false,
		private val keys: Map<String, Key> = emptyMap(),
		private val certificates: Map<String, Certificate> = emptyMap(),
	) : KeyStoreSpi() {
		var lastContainsAliasAlias: String? = null
		var lastGetKeyAlias: String? = null
		var lastGetCertificateAlias: String? = null

		override fun engineContainsAlias(alias: String): Boolean {
			lastContainsAliasAlias = alias
			return containsAliasResult
		}

		override fun engineGetKey(alias: String, password: CharArray?): Key? {
			lastGetKeyAlias = alias
			return keys[alias]
		}

		override fun engineGetCertificate(alias: String): Certificate? {
			lastGetCertificateAlias = alias
			return certificates[alias]
		}

		override fun engineGetCertificateChain(alias: String): Array<Certificate>? = null

		override fun engineGetCreationDate(alias: String) = java.util.Date(0)

		override fun engineSetKeyEntry(alias: String, key: Key, password: CharArray?, chain: Array<Certificate>?) = Unit

		override fun engineSetKeyEntry(alias: String, key: ByteArray, chain: Array<Certificate>?) = Unit

		override fun engineSetCertificateEntry(alias: String, cert: Certificate) = Unit

		override fun engineDeleteEntry(alias: String) = Unit

		override fun engineAliases(): java.util.Enumeration<String> = java.util.Collections.enumeration(emptyList())

		override fun engineSize(): Int = keys.size + certificates.size

		override fun engineIsKeyEntry(alias: String): Boolean = keys.containsKey(alias)

		override fun engineIsCertificateEntry(alias: String): Boolean = certificates.containsKey(alias)

		override fun engineGetCertificateAlias(cert: Certificate): String? {
			return certificates.entries.firstOrNull { it.value == cert }?.key
		}

		override fun engineStore(stream: java.io.OutputStream?, password: CharArray?) = Unit

		override fun engineLoad(stream: java.io.InputStream?, password: CharArray?) = Unit
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
