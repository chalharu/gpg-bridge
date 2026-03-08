package com.example.gpg_bridge_mobile

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import java.io.IOException
import java.math.BigInteger
import java.security.GeneralSecurityException
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.ProviderException
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.concurrent.Executor
import java.util.concurrent.RejectedExecutionException

private const val KEYSTORE_PROVIDER = "AndroidKeyStore"
private const val CURVE_NAME = "secp256r1"
private const val SIGNATURE_ALGORITHM = "SHA256withECDSA"
private const val DEVICE_KEY_ALIAS = "device_key"
private const val E2E_KEY_ALIAS = "e2e_key"

private val supportedMethods = mapOf(
	"generateKeyPair" to SupportedMethod.GENERATE_KEY_PAIR,
	"sign" to SupportedMethod.SIGN,
	"verify" to SupportedMethod.VERIFY,
	"getPublicKeyJwk" to SupportedMethod.GET_PUBLIC_KEY_JWK,
)

internal enum class SupportedMethod {
	GENERATE_KEY_PAIR,
	SIGN,
	VERIFY,
	GET_PUBLIC_KEY_JWK,
}

internal enum class KeystoreAlias {
	DEVICE,
	E2E,
}

internal fun parseSupportedMethod(method: String): SupportedMethod? = supportedMethods[method]

internal fun parseKeystoreAlias(alias: String): KeystoreAlias {
	return when (alias) {
		DEVICE_KEY_ALIAS -> KeystoreAlias.DEVICE
		E2E_KEY_ALIAS -> KeystoreAlias.E2E
		else -> throw IllegalArgumentException("unsupported alias: $alias")
	}
}

internal fun requireKnownAlias(alias: String) {
	parseKeystoreAlias(alias)
}

internal fun requireSignAlias(alias: String) {
	if (alias == DEVICE_KEY_ALIAS) {
		return
	}

	throw IllegalArgumentException("alias does not support sign/verify: $alias")
}

interface KeystoreOperations {
	fun generateKeyPair(alias: String)
	fun sign(alias: String, dataBase64: String): String
	fun verify(alias: String, dataBase64: String, signatureBase64: String): Boolean
	fun getPublicKeyJwk(alias: String): Map<String, String>
}

class KeystoreMethodCallHandler(
	private val operations: KeystoreOperations,
	private val backgroundExecutor: Executor,
	private val postToMainThread: (Runnable) -> Unit,
) {
	fun onMethodCall(call: MethodCall, result: MethodChannel.Result) {
		val method = parseSupportedMethod(call.method)
		if (method == null) {
			result.notImplemented()
			return
		}

		try {
			backgroundExecutor.execute {
				try {
					val value = when (method) {
						SupportedMethod.GENERATE_KEY_PAIR -> {
							operations.generateKeyPair(call.requireStringArg("alias"))
							true
						}

						SupportedMethod.SIGN -> operations.sign(
							call.requireStringArg("alias"),
							call.requireStringArg("dataBase64"),
						)

						SupportedMethod.VERIFY -> operations.verify(
							call.requireStringArg("alias"),
							call.requireStringArg("dataBase64"),
							call.requireStringArg("signatureBase64"),
						)

						SupportedMethod.GET_PUBLIC_KEY_JWK -> operations.getPublicKeyJwk(
							call.requireStringArg("alias"),
						)
					}

					postToMainThread(Runnable { result.success(value) })
				} catch (error: IllegalArgumentException) {
					postToMainThread(Runnable { result.error("INVALID_ARGUMENT", error.message, null) })
				} catch (error: GeneralSecurityException) {
					postToMainThread(Runnable { result.error("KEYSTORE_ERROR", error.message, null) })
				} catch (error: ProviderException) {
					postToMainThread(Runnable { result.error("KEYSTORE_ERROR", error.message, null) })
				} catch (error: IOException) {
					postToMainThread(Runnable { result.error("KEYSTORE_ERROR", error.message, null) })
				} catch (error: IllegalStateException) {
					postToMainThread(Runnable { result.error("KEYSTORE_ERROR", error.message, null) })
				}
			}
		} catch (error: RejectedExecutionException) {
			postToMainThread(Runnable { result.error("KEYSTORE_ERROR", "executor rejected task", null) })
		}
	}

	private fun MethodCall.requireStringArg(name: String): String {
		return argument<String>(name)
			?: throw IllegalArgumentException("missing argument: $name")
	}
}

class AndroidKeystoreOperations : KeystoreOperations {
	override fun generateKeyPair(alias: String) {
		requireKnownAlias(alias)

		val keyStore = getKeyStore()
		if (keyStore.containsAlias(alias)) {
			return
		}

		val purposes = when (alias) {
			DEVICE_KEY_ALIAS -> KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
			E2E_KEY_ALIAS -> KeyProperties.PURPOSE_AGREE_KEY
			else -> throw IllegalArgumentException("unsupported alias: $alias")
		}

		val parameterSpec = KeyGenParameterSpec.Builder(alias, purposes)
			.setAlgorithmParameterSpec(ECGenParameterSpec(CURVE_NAME))
			.apply {
				if (alias == DEVICE_KEY_ALIAS) {
					setDigests(KeyProperties.DIGEST_SHA256)
				}
			}
			.setUserAuthenticationRequired(false)
			.build()

		KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEYSTORE_PROVIDER)
			.apply { initialize(parameterSpec) }
			.generateKeyPair()
	}

	override fun sign(alias: String, dataBase64: String): String {
		requireSignAlias(alias)
		val privateKey = getPrivateKey(alias)
		val data = decodeBase64(dataBase64)

		val signatureBytes = Signature.getInstance(SIGNATURE_ALGORITHM)
			.apply {
				initSign(privateKey)
				update(data)
			}
			.sign()

		return encodeBase64(signatureBytes)
	}

	override fun verify(alias: String, dataBase64: String, signatureBase64: String): Boolean {
		requireSignAlias(alias)
		val publicKey = getEcPublicKey(alias)
		val data = decodeBase64(dataBase64)
		val signature = decodeBase64(signatureBase64)

		return Signature.getInstance(SIGNATURE_ALGORITHM)
			.apply {
				initVerify(publicKey)
				update(data)
			}
			.verify(signature)
	}

	override fun getPublicKeyJwk(alias: String): Map<String, String> {
		requireKnownAlias(alias)
		val publicKey = getEcPublicKey(alias)
		val affineX = toUnsignedFixedLength(publicKey.w.affineX, 32)
		val affineY = toUnsignedFixedLength(publicKey.w.affineY, 32)

		return mapOf(
			"kty" to "EC",
			"use" to keyUse(alias),
			"crv" to "P-256",
			"x" to encodeBase64Url(affineX),
			"y" to encodeBase64Url(affineY),
			"alg" to keyAlg(alias),
		)
	}

	private fun keyUse(alias: String): String {
		return when (alias) {
			DEVICE_KEY_ALIAS -> "sig"
			E2E_KEY_ALIAS -> "enc"
			else -> throw IllegalArgumentException("unsupported alias for jwk: $alias")
		}
	}

	private fun keyAlg(alias: String): String {
		return when (alias) {
			DEVICE_KEY_ALIAS -> "ES256"
			E2E_KEY_ALIAS -> "ECDH-ES+A256KW"
			else -> throw IllegalArgumentException("unsupported alias for jwk: $alias")
		}
	}

	private fun getKeyStore(): KeyStore {
		return KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
	}

	private fun getPrivateKey(alias: String): java.security.PrivateKey {
		val key = getKeyStore().getKey(alias, null)
			?: throw IllegalArgumentException("key alias not found: $alias")
		return key as? java.security.PrivateKey
			?: throw IllegalArgumentException("private key is not available for alias: $alias")
	}

	private fun getEcPublicKey(alias: String): ECPublicKey {
		val certificate = getKeyStore().getCertificate(alias)
			?: throw IllegalArgumentException("certificate not found for alias: $alias")
		return certificate.publicKey as? ECPublicKey
			?: throw IllegalArgumentException("public key is not EC for alias: $alias")
	}

	private fun decodeBase64(value: String): ByteArray {
		return Base64.decode(value, Base64.DEFAULT)
	}

	private fun encodeBase64(value: ByteArray): String {
		return Base64.encodeToString(value, Base64.NO_WRAP)
	}

	private fun encodeBase64Url(value: ByteArray): String {
		return Base64.encodeToString(value, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
	}

	private fun toUnsignedFixedLength(value: BigInteger, length: Int): ByteArray {
		val raw = value.toByteArray().let { bytes ->
			if (bytes.size > length && bytes.first() == 0.toByte()) {
				bytes.copyOfRange(1, bytes.size)
			} else {
				bytes
			}
		}

		require(raw.size <= length) { "coordinate length overflow: ${raw.size}" }

		return ByteArray(length).also { out ->
			System.arraycopy(raw, 0, out, length - raw.size, raw.size)
		}
	}

	private fun requireKnownAlias(alias: String) {
		if (alias != DEVICE_KEY_ALIAS && alias != E2E_KEY_ALIAS) {
			throw IllegalArgumentException("unsupported alias: $alias")
		}
	}

	private fun requireSignAlias(alias: String) {
		if (alias != DEVICE_KEY_ALIAS) {
			throw IllegalArgumentException("alias does not support sign/verify: $alias")
		}
	}
}