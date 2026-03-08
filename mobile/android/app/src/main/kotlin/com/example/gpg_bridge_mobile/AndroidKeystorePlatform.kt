package com.example.gpg_bridge_mobile

import android.security.keystore.KeyGenParameterSpec
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.spec.AlgorithmParameterSpec

internal interface KeyGenParameterSpecBuilderAccessDelegate {
	fun setAlgorithmParameterSpec(spec: AlgorithmParameterSpec)
	fun setDigests(vararg digests: String)
	fun setUserAuthenticationRequired(required: Boolean)
	fun build(): AlgorithmParameterSpec
}

internal fun loadSystemKeyStore(provider: String): KeyStore {
	return KeyStore.getInstance(provider).apply { load(null) }
}

internal fun loadSystemKeyPairGenerator(
	algorithm: String,
	provider: String,
): KeyPairGenerator {
	return KeyPairGenerator.getInstance(algorithm, provider)
}

internal fun createSystemKeyGenParameterSpecBuilder(
	alias: String,
	purposes: Int,
	createDelegate: (String, Int) -> KeyGenParameterSpecBuilderAccessDelegate,
): KeyGenParameterSpecBuilderAccess {
	return AndroidKeyGenParameterSpecBuilderAccess(createDelegate(alias, purposes))
}

internal fun createPlatformKeyGenParameterSpecBuilderAccess(
	alias: String,
	purposes: Int,
): KeyGenParameterSpecBuilderAccess {
	return createSystemKeyGenParameterSpecBuilder(
		alias = alias,
		purposes = purposes,
		createDelegate = ::createPlatformKeyGenParameterSpecBuilderDelegate,
	)
}

private fun createPlatformKeyGenParameterSpecBuilderDelegate(
	alias: String,
	purposes: Int,
): KeyGenParameterSpecBuilderAccessDelegate {
	return PlatformKeyGenParameterSpecBuilderDelegate(KeyGenParameterSpec.Builder(alias, purposes))
}

private class PlatformKeyGenParameterSpecBuilderDelegate(
	private val delegate: KeyGenParameterSpec.Builder,
) : KeyGenParameterSpecBuilderAccessDelegate {
	override fun setAlgorithmParameterSpec(spec: AlgorithmParameterSpec) {
		delegate.setAlgorithmParameterSpec(spec)
	}

	override fun setDigests(vararg digests: String) {
		delegate.setDigests(*digests)
	}

	override fun setUserAuthenticationRequired(required: Boolean) {
		delegate.setUserAuthenticationRequired(required)
	}

	override fun build(): AlgorithmParameterSpec = delegate.build()
}