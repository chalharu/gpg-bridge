import Flutter
import UIKit
import XCTest
@testable import Runner

class RunnerTests: XCTestCase {
  func testMethodChannelUnsupportedMethodReturnsNotImplemented() {
    let handler = IOSKeystoreMethodCallHandler(
      operations: MockKeystoreOperations(),
      backgroundQueue: DispatchQueue(label: "test.keystore.unsupported")
    )

    let expectation = expectation(description: "result callback")
    var callbackValue: Any?

    handler.onMethodCall(FlutterMethodCall(methodName: "noop", arguments: nil)) { value in
      callbackValue = value
      expectation.fulfill()
    }

    waitForExpectations(timeout: 1.0)
    XCTAssertTrue((callbackValue as AnyObject?) === (FlutterMethodNotImplemented as AnyObject))
  }

  func testMethodChannelMissingArgumentReturnsInvalidArgument() {
    let handler = IOSKeystoreMethodCallHandler(
      operations: MockKeystoreOperations(),
      backgroundQueue: DispatchQueue(label: "test.keystore.invalidarg")
    )

    let expectation = expectation(description: "result callback")
    var callbackValue: Any?

    handler.onMethodCall(
      FlutterMethodCall(methodName: "generateKeyPair", arguments: ["notAlias": "device_key"])
    ) { value in
      callbackValue = value
      expectation.fulfill()
    }

    waitForExpectations(timeout: 1.0)

    guard let error = callbackValue as? FlutterError else {
      XCTFail("expected FlutterError")
      return
    }

    XCTAssertEqual(error.code, "INVALID_ARGUMENT")
    XCTAssertEqual(error.message, "missing argument: alias")
  }

  func testMethodChannelSecurityFailureReturnsKeystoreErrorCode() {
    let mock = MockKeystoreOperations()
    mock.generateKeyPairHook = { _ in
      throw KeystoreError.securityFailure("failed")
    }

    let handler = IOSKeystoreMethodCallHandler(
      operations: mock,
      backgroundQueue: DispatchQueue(label: "test.keystore.security")
    )

    let expectation = expectation(description: "result callback")
    var callbackValue: Any?

    handler.onMethodCall(
      FlutterMethodCall(methodName: "generateKeyPair", arguments: ["alias": KeystoreKeyLabels.deviceKey])
    ) { value in
      callbackValue = value
      expectation.fulfill()
    }

    waitForExpectations(timeout: 1.0)

    guard let error = callbackValue as? FlutterError else {
      XCTFail("expected FlutterError")
      return
    }

    XCTAssertEqual(error.code, "KEYSTORE_ERROR")
    XCTAssertEqual(error.message, "failed")
  }

  func testAliasConstraintsForSignAndSupportedAliases() {
    XCTAssertNoThrow(try KeystoreKeyLabels.validate(alias: KeystoreKeyLabels.deviceKey))
    XCTAssertNoThrow(try KeystoreKeyLabels.validate(alias: KeystoreKeyLabels.e2eKey))

    XCTAssertThrowsError(try KeystoreKeyLabels.validate(alias: "other")) { error in
      guard case KeystoreError.invalidArgument(let message) = error else {
        XCTFail("expected invalidArgument")
        return
      }
      XCTAssertEqual(message, "unsupported alias: other")
    }

    XCTAssertNoThrow(try KeystoreKeyLabels.validateSignAlias(alias: KeystoreKeyLabels.deviceKey))
    XCTAssertThrowsError(try KeystoreKeyLabels.validateSignAlias(alias: KeystoreKeyLabels.e2eKey)) { error in
      guard case KeystoreError.invalidArgument(let message) = error else {
        XCTFail("expected invalidArgument")
        return
      }
      XCTAssertEqual(message, "alias does not support sign/verify: e2e_key")
    }
  }

  func testIOSSecureEnclaveGenerateKeyPairIsIdempotent() throws {
    let backend = MockSecureEnclaveBackend()
    let operations = IOSSecureEnclaveOperations(backend: backend)

    try operations.generateKeyPair(alias: KeystoreKeyLabels.deviceKey)
    XCTAssertEqual(backend.createPrivateKeyCallCount, 1)

    try operations.generateKeyPair(alias: KeystoreKeyLabels.deviceKey)
    XCTAssertEqual(backend.createPrivateKeyCallCount, 1)
  }

  func testIOSSecureEnclaveSignVerifySuccessAndFailureFlows() throws {
    let backend = MockSecureEnclaveBackend()
    let operations = IOSSecureEnclaveOperations(backend: backend)
    try operations.generateKeyPair(alias: KeystoreKeyLabels.deviceKey)

    let payload = Data("hello-secure-enclave".utf8)
    let signature = try operations.sign(
      alias: KeystoreKeyLabels.deviceKey,
      dataBase64: payload.base64EncodedString()
    )
    XCTAssertFalse(signature.isEmpty)

    let verified = try operations.verify(
      alias: KeystoreKeyLabels.deviceKey,
      dataBase64: payload.base64EncodedString(),
      signatureBase64: signature
    )
    XCTAssertTrue(verified)

    let tamperedVerified = try operations.verify(
      alias: KeystoreKeyLabels.deviceKey,
      dataBase64: Data("tampered".utf8).base64EncodedString(),
      signatureBase64: signature
    )
    XCTAssertFalse(tamperedVerified)

    XCTAssertThrowsError(
      try operations.sign(alias: KeystoreKeyLabels.e2eKey, dataBase64: payload.base64EncodedString())
    ) { error in
      guard case KeystoreError.invalidArgument(let message) = error else {
        XCTFail("expected invalidArgument")
        return
      }
      XCTAssertEqual(message, "alias does not support sign/verify: e2e_key")
    }

    XCTAssertThrowsError(
      try operations.verify(
        alias: KeystoreKeyLabels.deviceKey,
        dataBase64: "not-base64",
        signatureBase64: signature
      )
    ) { error in
      guard case KeystoreError.invalidArgument(let message) = error else {
        XCTFail("expected invalidArgument")
        return
      }
      XCTAssertEqual(message, "invalid base64 payload")
    }
  }

  func testIOSSecureEnclaveGetPublicKeyJwkHasExpectedShapeAndValues() throws {
    let backend = MockSecureEnclaveBackend()
    let operations = IOSSecureEnclaveOperations(backend: backend)

    try operations.generateKeyPair(alias: KeystoreKeyLabels.deviceKey)
    let jwk = try operations.getPublicKeyJwk(alias: KeystoreKeyLabels.deviceKey)

    XCTAssertEqual(jwk["kty"], "EC")
    XCTAssertEqual(jwk["use"], "sig")
    XCTAssertEqual(jwk["crv"], "P-256")
    XCTAssertEqual(jwk["alg"], "ES256")
    XCTAssertEqual(jwk["x"]?.count, 43)
    XCTAssertEqual(jwk["y"]?.count, 43)
    XCTAssertNotNil(jwk["x"]?.range(of: "^[A-Za-z0-9_-]{43}$", options: .regularExpression))
    XCTAssertNotNil(jwk["y"]?.range(of: "^[A-Za-z0-9_-]{43}$", options: .regularExpression))

    try operations.generateKeyPair(alias: KeystoreKeyLabels.e2eKey)
    let e2eJwk = try operations.getPublicKeyJwk(alias: KeystoreKeyLabels.e2eKey)
    XCTAssertEqual(e2eJwk["use"], "enc")
    XCTAssertEqual(e2eJwk["alg"], "ECDH-ES+A256KW")
  }

  func testIOSSecureEnclaveQueryPrivateKeyUnexpectedTypeMapsToSecurityFailure() {
    let backend = MockSecureEnclaveBackend()
    backend.queryResult = NSString(string: "not-a-key")
    let operations = IOSSecureEnclaveOperations(backend: backend)

    // queryPrivateKey returns the non-nil NSString, so generateKeyPair
    // treats it as an existing key and returns early.  The type mismatch
    // surfaces when the value is actually *used* (e.g. createSignature).
    XCTAssertThrowsError(
      try operations.sign(alias: KeystoreKeyLabels.deviceKey, dataBase64: "AAAA")
    ) { error in
      guard case KeystoreError.securityFailure(let message) = error else {
        XCTFail("expected securityFailure")
        return
      }
      XCTAssertEqual(message, "private key has unexpected type")
    }
  }

  private final class MockKeystoreOperations: KeystoreOperations {
    var generateKeyPairHook: ((String) throws -> Void)?

    func generateKeyPair(alias: String) throws {
      if let hook = generateKeyPairHook {
        try hook(alias)
      }
    }

    func sign(alias: String, dataBase64: String) throws -> String {
      return ""
    }

    func verify(alias: String, dataBase64: String, signatureBase64: String) throws -> Bool {
      return true
    }

    func getPublicKeyJwk(alias: String) throws -> [String : String] {
      return [:]
    }
  }

  private final class MockSecureEnclaveBackend: IOSSecureEnclaveBackend {
    var queryResult: AnyObject?
    var createPrivateKeyCallCount = 0
    private var keys: [String: PseudoPrivateKey] = [:]

    func makeAccessControl() throws -> SecAccessControl {
      let flags = SecAccessControlCreateFlags(rawValue: 0)
      guard let access = SecAccessControlCreateWithFlags(
        nil,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        flags,
        nil
      ) else {
        throw KeystoreError.securityFailure("failed to create test access control")
      }
      return access
    }

    func queryPrivateKey(tag: Data) throws -> AnyObject? {
      if let queryResult {
        return queryResult
      }
      return keys[tag.base64EncodedString()]
    }

    func createPrivateKey(tag: Data, access: SecAccessControl) throws {
      _ = access
      createPrivateKeyCallCount += 1
      keys[tag.base64EncodedString()] = PseudoPrivateKey(secret: tag)
    }

    func copyPublicKey(privateKey: AnyObject, alias: String) throws -> AnyObject {
      _ = alias
      guard let privateKey = privateKey as? PseudoPrivateKey else {
        throw KeystoreError.securityFailure("private key has unexpected type")
      }
      return PseudoPublicKey(secret: privateKey.secret)
    }

    func createSignature(privateKey: AnyObject, data: Data) throws -> Data {
      guard let privateKey = privateKey as? PseudoPrivateKey else {
        throw KeystoreError.securityFailure("private key has unexpected type")
      }
      return pseudoSign(secret: privateKey.secret, data: data)
    }

    func verifySignature(publicKey: AnyObject, data: Data, signature: Data) throws -> Bool {
      guard let publicKey = publicKey as? PseudoPublicKey else {
        throw KeystoreError.securityFailure("public key has unexpected type")
      }
      let expected = pseudoSign(secret: publicKey.secret, data: data)
      return expected == signature
    }

    func copyExternalRepresentation(publicKey: AnyObject) throws -> Data {
      guard let publicKey = publicKey as? PseudoPublicKey else {
        throw KeystoreError.securityFailure("public key has unexpected type")
      }

      let seed = pseudoSign(secret: publicKey.secret, data: Data("public".utf8))
      let x = Data(seed.prefix(32))
      let y = Data(seed.suffix(32))
      return Data([0x04]) + x + y
    }

    private func pseudoSign(secret: Data, data: Data) -> Data {
      let combined = Data(secret + data)
      if combined.isEmpty {
        return Data(repeating: 0, count: 64)
      }
      return Data((0..<64).map { index in
        combined[index % combined.count] ^ UInt8(index & 0xff)
      })
    }
  }

  private final class PseudoPrivateKey: NSObject {
    let secret: Data

    init(secret: Data) {
      self.secret = secret
    }
  }

  private final class PseudoPublicKey: NSObject {
    let secret: Data

    init(secret: Data) {
      self.secret = secret
    }
  }

}
