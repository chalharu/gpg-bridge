package com.example.gpg_bridge_mobile

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

internal data class KeystoreKeyGenRequest(
	val alias: String,
	val purposes: Int,
	val includeSha256Digest: Boolean,
)

internal interface KeyStoreAccess {
	fun containsAlias(alias: String): Boolean
	fun getPrivateKey(alias: String): PrivateKey?
	fun getPublicKey(alias: String): PublicKey?
}

internal interface KeyPairGeneratorAccess {
	fun initialize(request: KeystoreKeyGenRequest)
	fun generateKeyPair()
}

internal interface SignatureAccess {
	fun sign(privateKey: PrivateKey, data: ByteArray): ByteArray
	fun verify(publicKey: ECPublicKey, data: ByteArray, signature: ByteArray): Boolean
}

internal interface Base64Codec {
	fun decode(value: String): ByteArray
	fun encode(value: ByteArray): String
	fun encodeUrl(value: ByteArray): String
}

internal fun loadSystemKeyStore(provider: String = KEYSTORE_PROVIDER): KeyStore {
	return KeyStore.getInstance(provider).apply { load(null) }
}

internal data class AndroidKeystoreDependencies(
	val createSystemKeyStore: () -> KeyStore = ::loadSystemKeyStore,
	val keyStoreAccess: () -> KeyStoreAccess = { SystemKeyStoreAccess(createSystemKeyStore()) },
	val keyPairGeneratorAccess: () -> KeyPairGeneratorAccess = { SystemKeyPairGeneratorAccess() },
	val signatureAccess: SignatureAccess = SystemSignatureAccess,
	val base64Codec: Base64Codec = AndroidBase64Codec,
)

internal class AndroidKeystoreOperations(
	private val dependencies: AndroidKeystoreDependencies = AndroidKeystoreDependencies(),
) : KeystoreOperations {
	override fun generateKeyPair(alias: String) {
		requireKnownAlias(alias)

		val keyStore = dependencies.keyStoreAccess()
		if (keyStore.containsAlias(alias)) {
			return
		}

		dependencies.keyPairGeneratorAccess()
			.apply { initialize(createKeyGenRequest(alias)) }
			.generateKeyPair()
	}

	override fun sign(alias: String, dataBase64: String): String {
		requireSignAlias(alias)
		val privateKey = dependencies.keyStoreAccess().getPrivateKey(alias)
			?: throw IllegalArgumentException("key alias not found: $alias")
		val signature = dependencies.signatureAccess.sign(
			privateKey = privateKey,
			data = dependencies.base64Codec.decode(dataBase64),
		)
		return dependencies.base64Codec.encode(signature)
	}

	override fun verify(alias: String, dataBase64: String, signatureBase64: String): Boolean {
		requireSignAlias(alias)
		return dependencies.signatureAccess.verify(
			publicKey = getEcPublicKey(alias),
			data = dependencies.base64Codec.decode(dataBase64),
			signature = dependencies.base64Codec.decode(signatureBase64),
		)
	}

	override fun getPublicKeyJwk(alias: String): Map<String, String> {
		requireKnownAlias(alias)
		val publicKey = getEcPublicKey(alias)
		val metadata = jwkMetadata(alias)

		return mapOf(
			"kty" to "EC",
			"use" to metadata.use,
			"crv" to "P-256",
			"x" to dependencies.base64Codec.encodeUrl(toUnsignedFixedLength(publicKey.w.affineX, 32)),
			"y" to dependencies.base64Codec.encodeUrl(toUnsignedFixedLength(publicKey.w.affineY, 32)),
			"alg" to metadata.alg,
		)
	}

	private fun createKeyGenRequest(alias: String): KeystoreKeyGenRequest {
		return when (parseKeystoreAlias(alias)) {
			KeystoreAlias.DEVICE -> KeystoreKeyGenRequest(
				alias = alias,
				purposes = KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
				includeSha256Digest = true,
			)

			KeystoreAlias.E2E -> KeystoreKeyGenRequest(
				alias = alias,
				purposes = KeyProperties.PURPOSE_AGREE_KEY,
				includeSha256Digest = false,
			)
		}
	}

	private fun getEcPublicKey(alias: String): ECPublicKey {
		val publicKey = dependencies.keyStoreAccess().getPublicKey(alias)
			?: throw IllegalArgumentException("certificate not found for alias: $alias")
		return publicKey as? ECPublicKey
			?: throw IllegalArgumentException("public key is not EC for alias: $alias")
	}

	private fun jwkMetadata(alias: String): JwkMetadata {
		return when (parseKeystoreAlias(alias)) {
			KeystoreAlias.DEVICE -> JwkMetadata(use = "sig", alg = "ES256")
			KeystoreAlias.E2E -> JwkMetadata(use = "enc", alg = "ECDH-ES+A256KW")
		}
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
}

private data class JwkMetadata(
	val use: String,
	val alg: String,
)

internal class SystemKeyStoreAccess(
	private val keyStore: KeyStore,
) : KeyStoreAccess {

	override fun containsAlias(alias: String): Boolean = keyStore.containsAlias(alias)

	override fun getPrivateKey(alias: String): PrivateKey? {
		return keyStore.getKey(alias, null) as? PrivateKey
	}

	override fun getPublicKey(alias: String): PublicKey? {
		return keyStore.getCertificate(alias)?.publicKey
	}
}

private class SystemKeyPairGeneratorAccess : KeyPairGeneratorAccess {
	private val delegate = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEYSTORE_PROVIDER)

	override fun initialize(request: KeystoreKeyGenRequest) {
		val parameterSpec = KeyGenParameterSpec.Builder(request.alias, request.purposes)
			.setAlgorithmParameterSpec(ECGenParameterSpec(CURVE_NAME))
			.apply {
				if (request.includeSha256Digest) {
					setDigests(KeyProperties.DIGEST_SHA256)
				}
			}
			.setUserAuthenticationRequired(false)
			.build()

		delegate.initialize(parameterSpec)
	}

	override fun generateKeyPair() {
		delegate.generateKeyPair()
	}
}

private object SystemSignatureAccess : SignatureAccess {
	override fun sign(privateKey: PrivateKey, data: ByteArray): ByteArray {
		return Signature.getInstance(SIGNATURE_ALGORITHM)
			.apply {
				initSign(privateKey)
				update(data)
			}
			.sign()
	}

	override fun verify(publicKey: ECPublicKey, data: ByteArray, signature: ByteArray): Boolean {
		return Signature.getInstance(SIGNATURE_ALGORITHM)
			.apply {
				initVerify(publicKey)
				update(data)
			}
			.verify(signature)
	}
}

private object AndroidBase64Codec : Base64Codec {
	override fun decode(value: String): ByteArray = Base64.decode(value, Base64.DEFAULT)

	override fun encode(value: ByteArray): String = Base64.encodeToString(value, Base64.NO_WRAP)

	override fun encodeUrl(value: ByteArray): String {
		return Base64.encodeToString(value, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
	}
}