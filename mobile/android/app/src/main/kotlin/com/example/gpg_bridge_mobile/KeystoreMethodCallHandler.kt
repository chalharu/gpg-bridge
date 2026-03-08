package com.example.gpg_bridge_mobile

import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import java.io.IOException
import java.security.GeneralSecurityException
import java.security.ProviderException
import java.util.concurrent.Executor
import java.util.concurrent.RejectedExecutionException

internal const val KEYSTORE_PROVIDER = "AndroidKeyStore"
internal const val CURVE_NAME = "secp256r1"
internal const val SIGNATURE_ALGORITHM = "SHA256withECDSA"
internal const val DEVICE_KEY_ALIAS = "device_key"
internal const val E2E_KEY_ALIAS = "e2e_key"

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
	require(alias == DEVICE_KEY_ALIAS) {
		"alias does not support sign/verify: $alias"
	}
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