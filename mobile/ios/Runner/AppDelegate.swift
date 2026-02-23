import Flutter
import UIKit
import Security
import Foundation

@main
@objc class AppDelegate: FlutterAppDelegate, FlutterImplicitEngineDelegate {
  private var keystoreMethodHandler: IOSKeystoreMethodCallHandler?

  override func application(
    _ application: UIApplication,
    didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?
  ) -> Bool {
    return super.application(application, didFinishLaunchingWithOptions: launchOptions)
  }

  func didInitializeImplicitFlutterEngine(_ engineBridge: FlutterImplicitEngineBridge) {
    GeneratedPluginRegistrant.register(with: engineBridge.pluginRegistry)

    guard let registrar = engineBridge.pluginRegistry.registrar(forPlugin: "IOSKeystoreMethodCallHandler") else {
      return
    }

    let channel = FlutterMethodChannel(
      name: IOSKeystoreMethodCallHandler.channelName,
      binaryMessenger: registrar.messenger()
    )

    let handler = IOSKeystoreMethodCallHandler(operations: IOSSecureEnclaveOperations())
    channel.setMethodCallHandler(handler.onMethodCall)
    keystoreMethodHandler = handler
  }
}

enum KeystoreError: Error {
  case invalidArgument(String)
  case securityFailure(String)
}

enum KeystoreKeyLabels {
  static let deviceKey = "device_key"
  static let e2eKey = "e2e_key"

  static func validate(alias: String) throws {
    guard alias == deviceKey || alias == e2eKey else {
      throw KeystoreError.invalidArgument("unsupported alias: \(alias)")
    }
  }

  static func validateSignAlias(alias: String) throws {
    guard alias == deviceKey else {
      throw KeystoreError.invalidArgument("alias does not support sign/verify: \(alias)")
    }
  }

  static func keyUse(alias: String) throws -> String {
    switch alias {
    case deviceKey:
      return "sig"
    case e2eKey:
      return "enc"
    default:
      throw KeystoreError.invalidArgument("unsupported alias for jwk: \(alias)")
    }
  }

  static func keyAlg(alias: String) throws -> String {
    switch alias {
    case deviceKey:
      return "ES256"
    case e2eKey:
      return "ECDH-ES+A256KW"
    default:
      throw KeystoreError.invalidArgument("unsupported alias for jwk: \(alias)")
    }
  }

  static func applicationTag(alias: String) throws -> Data {
    try validate(alias: alias)
    return Data("gpg_bridge.ios.secure_enclave.\(alias)".utf8)
  }
}

protocol KeystoreOperations {
  func generateKeyPair(alias: String) throws
  func sign(alias: String, dataBase64: String) throws -> String
  func verify(alias: String, dataBase64: String, signatureBase64: String) throws -> Bool
  func getPublicKeyJwk(alias: String) throws -> [String: String]
}

final class IOSKeystoreMethodCallHandler {
  static let channelName = "gpg_bridge/keystore"

  private let operations: KeystoreOperations
  private let backgroundQueue: DispatchQueue

  init(operations: KeystoreOperations, backgroundQueue: DispatchQueue = .global(qos: .userInitiated)) {
    self.operations = operations
    self.backgroundQueue = backgroundQueue
  }

  func onMethodCall(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
    guard isSupportedMethod(call.method) else {
      result(FlutterMethodNotImplemented)
      return
    }

    backgroundQueue.async {
      do {
        let value: Any = try self.dispatch(call: call)
        DispatchQueue.main.async {
          result(value)
        }
      } catch KeystoreError.invalidArgument(let message) {
        DispatchQueue.main.async {
          result(FlutterError(code: "INVALID_ARGUMENT", message: message, details: nil))
        }
      } catch KeystoreError.securityFailure(let message) {
        DispatchQueue.main.async {
          result(FlutterError(code: "KEYSTORE_ERROR", message: message, details: nil))
        }
      } catch {
        DispatchQueue.main.async {
          result(FlutterError(code: "KEYSTORE_ERROR", message: "\(error)", details: nil))
        }
      }
    }
  }

  private func dispatch(call: FlutterMethodCall) throws -> Any {
    switch call.method {
    case "generateKeyPair":
      let alias = try requireStringArg(call: call, name: "alias")
      try operations.generateKeyPair(alias: alias)
      return true
    case "sign":
      let alias = try requireStringArg(call: call, name: "alias")
      let dataBase64 = try requireStringArg(call: call, name: "dataBase64")
      return try operations.sign(alias: alias, dataBase64: dataBase64)
    case "verify":
      let alias = try requireStringArg(call: call, name: "alias")
      let dataBase64 = try requireStringArg(call: call, name: "dataBase64")
      let signatureBase64 = try requireStringArg(call: call, name: "signatureBase64")
      return try operations.verify(alias: alias, dataBase64: dataBase64, signatureBase64: signatureBase64)
    case "getPublicKeyJwk":
      let alias = try requireStringArg(call: call, name: "alias")
      return try operations.getPublicKeyJwk(alias: alias)
    default:
      throw KeystoreError.invalidArgument("unsupported method: \(call.method)")
    }
  }

  private func isSupportedMethod(_ method: String) -> Bool {
    return method == "generateKeyPair"
      || method == "sign"
      || method == "verify"
      || method == "getPublicKeyJwk"
  }

  private func requireStringArg(call: FlutterMethodCall, name: String) throws -> String {
    guard
      let args = call.arguments as? [String: Any],
      let value = args[name] as? String
    else {
      throw KeystoreError.invalidArgument("missing argument: \(name)")
    }

    return value
  }
}

protocol IOSSecureEnclaveBackend {
  func makeAccessControl() throws -> SecAccessControl
  func queryPrivateKey(tag: Data) throws -> AnyObject?
  func createPrivateKey(tag: Data, access: SecAccessControl) throws
  func copyPublicKey(privateKey: AnyObject, alias: String) throws -> AnyObject
  func createSignature(privateKey: AnyObject, data: Data) throws -> Data
  func verifySignature(publicKey: AnyObject, data: Data, signature: Data) throws -> Bool
  func copyExternalRepresentation(publicKey: AnyObject) throws -> Data
}

final class SecurityFrameworkSecureEnclaveBackend: IOSSecureEnclaveBackend {
  func makeAccessControl() throws -> SecAccessControl {
    var error: Unmanaged<CFError>?
    guard let access = SecAccessControlCreateWithFlags(
      nil,
      kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
      .privateKeyUsage,
      &error
    ) else {
      throw mapSecError(prefix: "failed to create access control", error: error)
    }

    return access
  }

  func queryPrivateKey(tag: Data) throws -> AnyObject? {
    let query: [String: Any] = [
      kSecClass as String: kSecClassKey,
      kSecAttrApplicationTag as String: tag,
      kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
      kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
      kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
      kSecReturnRef as String: true,
    ]

    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)

    if status == errSecSuccess {
      guard let item else {
        throw KeystoreError.securityFailure("key lookup returned empty result")
      }
      guard let key = item as? SecKey else {
        throw KeystoreError.securityFailure("key lookup returned unexpected item type")
      }
      return key
    }

    if status == errSecItemNotFound {
      return nil
    }

    throw KeystoreError.securityFailure("key lookup failed: \(status)")
  }

  func createPrivateKey(tag: Data, access: SecAccessControl) throws {
    let attributes: [String: Any] = [
      kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
      kSecAttrKeySizeInBits as String: 256,
      kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
      kSecPrivateKeyAttrs as String: [
        kSecAttrIsPermanent as String: true,
        kSecAttrApplicationTag as String: tag,
        kSecAttrAccessControl as String: access,
      ],
    ]

    var error: Unmanaged<CFError>?
    let generated = SecKeyCreateRandomKey(attributes as CFDictionary, &error)
    if generated == nil {
      throw mapSecError(prefix: "failed to generate secure enclave key", error: error)
    }
  }

  func copyPublicKey(privateKey: AnyObject, alias: String) throws -> AnyObject {
    guard let privateSecKey = privateKey as? SecKey else {
      throw KeystoreError.securityFailure("private key has unexpected type for alias: \(alias)")
    }
    guard let publicKey = SecKeyCopyPublicKey(privateSecKey) else {
      throw KeystoreError.securityFailure("public key is not available for alias: \(alias)")
    }
    return publicKey
  }

  func createSignature(privateKey: AnyObject, data: Data) throws -> Data {
    guard let privateSecKey = privateKey as? SecKey else {
      throw KeystoreError.securityFailure("private key has unexpected type")
    }
    var error: Unmanaged<CFError>?
    guard let signature = SecKeyCreateSignature(
      privateSecKey,
      .ecdsaSignatureMessageX962SHA256,
      data as CFData,
      &error
    ) as Data? else {
      throw mapSecError(prefix: "failed to sign data", error: error)
    }

    return signature
  }

  func verifySignature(publicKey: AnyObject, data: Data, signature: Data) throws -> Bool {
    guard let publicSecKey = publicKey as? SecKey else {
      throw KeystoreError.securityFailure("public key has unexpected type")
    }

    var error: Unmanaged<CFError>?
    let verified = SecKeyVerifySignature(
      publicSecKey,
      .ecdsaSignatureMessageX962SHA256,
      data as CFData,
      signature as CFData,
      &error
    )

    if !verified, let secError = error {
      throw mapSecError(prefix: "failed to verify signature", error: secError)
    }

    return verified
  }

  func copyExternalRepresentation(publicKey: AnyObject) throws -> Data {
    guard let publicSecKey = publicKey as? SecKey else {
      throw KeystoreError.securityFailure("public key has unexpected type")
    }

    var error: Unmanaged<CFError>?
    guard let external = SecKeyCopyExternalRepresentation(publicSecKey, &error) as Data? else {
      throw mapSecError(prefix: "failed to extract public key", error: error)
    }

    return external
  }

  private func mapSecError(prefix: String, error: Unmanaged<CFError>?) -> KeystoreError {
    let detail = error?.takeRetainedValue().localizedDescription ?? "unknown"
    return KeystoreError.securityFailure("\(prefix): \(detail)")
  }
}

final class IOSSecureEnclaveOperations: KeystoreOperations {
  private let backend: IOSSecureEnclaveBackend

  init(backend: IOSSecureEnclaveBackend = SecurityFrameworkSecureEnclaveBackend()) {
    self.backend = backend
  }

  func generateKeyPair(alias: String) throws {
    try KeystoreKeyLabels.validate(alias: alias)
    if try queryPrivateKey(alias: alias) != nil {
      return
    }

    let access = try backend.makeAccessControl()
    let tag = try KeystoreKeyLabels.applicationTag(alias: alias)
    try backend.createPrivateKey(tag: tag, access: access)
  }

  func sign(alias: String, dataBase64: String) throws -> String {
    try KeystoreKeyLabels.validateSignAlias(alias: alias)
    let privateKey = try requirePrivateKey(alias: alias)
    let data = try decodeBase64(dataBase64)

    let signature = try backend.createSignature(privateKey: privateKey, data: data)
    return signature.base64EncodedString()
  }

  func verify(alias: String, dataBase64: String, signatureBase64: String) throws -> Bool {
    try KeystoreKeyLabels.validateSignAlias(alias: alias)
    let privateKey = try requirePrivateKey(alias: alias)
    let publicKey = try backend.copyPublicKey(privateKey: privateKey, alias: alias)

    let data = try decodeBase64(dataBase64)
    let signature = try decodeBase64(signatureBase64)
    return try backend.verifySignature(publicKey: publicKey, data: data, signature: signature)
  }

  func getPublicKeyJwk(alias: String) throws -> [String: String] {
    try KeystoreKeyLabels.validate(alias: alias)
    let privateKey = try requirePrivateKey(alias: alias)
    let publicKey = try backend.copyPublicKey(privateKey: privateKey, alias: alias)

    let coordinate = try extractCoordinates(publicKey: publicKey)

    return [
      "kty": "EC",
      "use": try KeystoreKeyLabels.keyUse(alias: alias),
      "crv": "P-256",
      "x": base64UrlEncode(coordinate.x),
      "y": base64UrlEncode(coordinate.y),
      "alg": try KeystoreKeyLabels.keyAlg(alias: alias),
    ]
  }

  private func queryPrivateKey(alias: String) throws -> AnyObject? {
    let tag = try KeystoreKeyLabels.applicationTag(alias: alias)
    return try backend.queryPrivateKey(tag: tag)
  }

  private func requirePrivateKey(alias: String) throws -> AnyObject {
    guard let key = try queryPrivateKey(alias: alias) else {
      throw KeystoreError.invalidArgument("key alias not found: \(alias)")
    }
    return key
  }

  private func decodeBase64(_ value: String) throws -> Data {
    guard let decoded = Data(base64Encoded: value) else {
      throw KeystoreError.invalidArgument("invalid base64 payload")
    }
    return decoded
  }

  private func base64UrlEncode(_ data: Data) -> String {
    return data.base64EncodedString()
      .replacingOccurrences(of: "+", with: "-")
      .replacingOccurrences(of: "/", with: "_")
      .replacingOccurrences(of: "=", with: "")
  }

  private func extractCoordinates(publicKey: AnyObject) throws -> (x: Data, y: Data) {
    let external = try backend.copyExternalRepresentation(publicKey: publicKey)

    guard external.count == 65, external.first == 0x04 else {
      throw KeystoreError.securityFailure("unexpected public key format")
    }

    return (
      x: external.subdata(in: 1..<33),
      y: external.subdata(in: 33..<65)
    )
  }
}
