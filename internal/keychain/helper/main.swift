import Foundation
import LocalAuthentication
import Security

// ghostenv-keychain: Touch ID-gated keychain access
// Stores keys in the regular keychain, but requires Touch ID via LAContext
// before returning them. No developer entitlements needed.
//
// Usage:
//   ghostenv-keychain store <account> <hex-key>
//   ghostenv-keychain load <account>
//   ghostenv-keychain delete <account>

let args = CommandLine.arguments

func exit(_ msg: String) -> Never {
    fputs("error: \(msg)\n", stderr)
    Foundation.exit(1)
}

func hexToData(_ hex: String) -> Data? {
    var data = Data()
    var temp = ""
    for char in hex {
        temp += String(char)
        if temp.count == 2 {
            guard let byte = UInt8(temp, radix: 16) else { return nil }
            data.append(byte)
            temp = ""
        }
    }
    return temp.isEmpty ? data : nil
}

func dataToHex(_ data: Data) -> String {
    return data.map { String(format: "%02x", $0) }.joined()
}

// Require Touch ID authentication before proceeding.
func requireTouchID() {
    let context = LAContext()
    var authError: NSError?

    guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &authError) else {
        // No biometrics available — allow access (headless/remote/no Touch ID hardware)
        return
    }

    let semaphore = DispatchSemaphore(value: 0)
    var success = false

    context.evaluatePolicy(
        .deviceOwnerAuthenticationWithBiometrics,
        localizedReason: "ghostenv needs to access your secrets"
    ) { result, error in
        success = result
        semaphore.signal()
    }

    semaphore.wait()

    if !success {
        exit("Touch ID authentication failed or canceled")
    }
}

func store(account: String, hexKey: String) {
    guard let keyData = hexToData(hexKey) else {
        exit("invalid hex key")
    }

    // Delete existing entry first
    let deleteQuery: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: "ghostenv",
        kSecAttrAccount as String: account,
    ]
    SecItemDelete(deleteQuery as CFDictionary)

    // Store in keychain (no biometry flag — works without entitlements)
    let addQuery: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: "ghostenv",
        kSecAttrAccount as String: account,
        kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        kSecValueData as String: keyData,
    ]

    let status = SecItemAdd(addQuery as CFDictionary, nil)
    if status != errSecSuccess {
        exit("keychain store failed: \(SecCopyErrorMessageString(status, nil) ?? "unknown" as CFString)")
    }

    print("ok")
}

func load(account: String) {
    // Require Touch ID BEFORE accessing the key
    requireTouchID()

    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: "ghostenv",
        kSecAttrAccount as String: account,
        kSecReturnData as String: true,
    ]

    var result: AnyObject?
    let status = SecItemCopyMatching(query as CFDictionary, &result)

    if status == errSecItemNotFound {
        exit("key not found in keychain")
    }
    if status != errSecSuccess {
        exit("keychain load failed: \(SecCopyErrorMessageString(status, nil) ?? "unknown" as CFString)")
    }

    guard let data = result as? Data else {
        exit("unexpected keychain data format")
    }

    print(dataToHex(data))
}

func delete(account: String) {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: "ghostenv",
        kSecAttrAccount as String: account,
    ]

    let status = SecItemDelete(query as CFDictionary)
    if status != errSecSuccess && status != errSecItemNotFound {
        exit("keychain delete failed: \(SecCopyErrorMessageString(status, nil) ?? "unknown" as CFString)")
    }
    print("ok")
}

// Main
guard args.count >= 3 else {
    exit("usage: ghostenv-keychain <store|load|delete> <account> [hex-key]")
}

let command = args[1]
let account = args[2]

switch command {
case "store":
    guard args.count >= 4 else {
        exit("usage: ghostenv-keychain store <account> <hex-key>")
    }
    store(account: account, hexKey: args[3])
case "load":
    load(account: account)
case "delete":
    delete(account: account)
default:
    exit("unknown command: \(command). Use store, load, or delete")
}
