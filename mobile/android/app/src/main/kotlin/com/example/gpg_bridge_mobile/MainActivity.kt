package com.example.gpg_bridge_mobile

import android.security.keystore.KeyProperties
import android.security.keystore.KeyGenParameterSpec
import android.util.Base64
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.embedding.android.FlutterActivity
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

class MainActivity : FlutterActivity() {
	companion object {
		private const val CHANNEL_NAME = "gpg_bridge/keystore"
		private const val KEYSTORE_PROVIDER = "AndroidKeyStore"
		private const val CURVE_NAME = "secp256r1"
		private const val SIGNATURE_ALGORITHM = "SHA256withECDSA"
		private const val DEVICE_KEY_ALIAS = "device_key"
		private const val E2E_KEY_ALIAS = "e2e_key"
	}

	override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
		super.configureFlutterEngine(flutterEngine)

		MethodChannel(flutterEngine.dartExecutor.binaryMessenger, CHANNEL_NAME)
			.setMethodCallHandler(::onMethodCall)
	}

	private fun onMethodCall(call: MethodCall, result: MethodChannel.Result) {
		try {
			when (call.method) {
				"generateKeyPair" -> {
					val alias = call.requireStringArg("alias")
					generateKeyPair(alias)
					result.success(true)
				}

				"sign" -> {
					val alias = call.requireStringArg("alias")
					val dataBase64 = call.requireStringArg("dataBase64")
					result.success(sign(alias, dataBase64))
				}

				"verify" -> {
					val alias = call.requireStringArg("alias")
					val dataBase64 = call.requireStringArg("dataBase64")
					val signatureBase64 = call.requireStringArg("signatureBase64")
					result.success(verify(alias, dataBase64, signatureBase64))
				}

				"getPublicKeyJwk" -> {
					val alias = call.requireStringArg("alias")
					result.success(getPublicKeyJwk(alias))
				}

				else -> result.notImplemented()
			}
		} catch (error: IllegalArgumentException) {
			result.error("INVALID_ARGUMENT", error.message, null)
		} catch (error: Throwable) {
			result.error("KEYSTORE_ERROR", error.message, null)
		}
	}

	private fun generateKeyPair(alias: String) {
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

		val parameterSpec = KeyGenParameterSpec.Builder(
			alias,
			purposes,
		)
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

	private fun sign(alias: String, dataBase64: String): String {
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

	private fun verify(alias: String, dataBase64: String, signatureBase64: String): Boolean {
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

	private fun getPublicKeyJwk(alias: String): Map<String, String> {
		requireKnownAlias(alias)
		val publicKey = getEcPublicKey(alias)
		val affineX = toUnsignedFixedLength(publicKey.w.affineX, 32)
		val affineY = toUnsignedFixedLength(publicKey.w.affineY, 32)
		val keyUse = keyUse(alias)
		val keyAlg = keyAlg(alias)

		return mapOf(
			"kty" to "EC",
			"use" to keyUse,
			"crv" to "P-256",
			"x" to encodeBase64Url(affineX),
			"y" to encodeBase64Url(affineY),
			"alg" to keyAlg,
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

	private fun MethodCall.requireStringArg(name: String): String {
		return argument<String>(name)
			?: throw IllegalArgumentException("missing argument: $name")
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
