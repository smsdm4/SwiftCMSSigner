# SwiftCMSSigner

`SwiftCMSSigner` is a Swift library that enables developers to generate CMS (Cryptographic Message Syntax) signatures using OpenSSL under the hood. Built for Apple platforms (iOS and macOS) and fully compatible with Swift Package Manager, this library provides a simple and modular API for cryptographic signing operations based on industry standards.

> **Powered by [krzyzanowskim/OpenSSL-Package](https://github.com/krzyzanowskim/OpenSSL-Package)**

---

## 🔐 What is CMS (Cryptographic Message Syntax)?

CMS is a standard developed by the IETF ([RFC 5652](https://datatracker.ietf.org/doc/html/rfc5652)) for securely signing, encrypting, or authenticating digital messages. It is the successor to PKCS#7 and is widely used in many security-sensitive applications, such as:

- Secure email (S/MIME)
- PDF and document signing
- Signed software updates or bundles
- Secure HTTP payload signing

SwiftCMSSigner focuses on **CMS detached signatures**, where the original content is not embedded in the signed output—ideal for use cases like signing PDFs or external content in distributed systems.

---

## ✨ Features

- 📄 CMS (PKCS#7) Detached Signature Creation
- 📦 DER format with Base64 encoding
- 🔒 Built on OpenSSL 3.3.3001 (via binary package)
- 🧩 Modular and reusable Swift API
- ✅ Works on both iOS and macOS platforms

---

## 📦 Installation (via Swift Package Manager)

In your `Package.swift` file:

```swift
.package(url: "https://github.com/smsdm4/SwiftCMSSigner.git", from: "1.0.0")
```

and then as a dependency for the Package target utilizing OpenSSL:

```swift
.target(
    name: "MyApp",
    dependencies: [
        .product(name: "SwiftCMSSigner", package: "SwiftCMSSigner")
    ]
),
```
Or, in Xcode:
*Go to File > Add Packages...
*Paste the URL of the repository
*Choose version

---

## ✅ **Usage Example**

```swift
import SwiftCMSSigner

let signer = SwiftCMSSigner()
let inputData = Data("Hello, CMS!".utf8)

let certPEM = """
-----BEGIN CERTIFICATE-----
...Your certificate PEM here...
-----END CERTIFICATE-----
"""

let keyPEM = """
-----BEGIN PRIVATE KEY-----
...Your private key PEM here...
-----END PRIVATE KEY-----
"""

if let base64CMS = signer.createCMSSignedMessageBase64(inputData: inputData, certPEM: certPEM, keyPEM: keyPEM) {
    print("Signed CMS (Base64):")
    print(base64CMS)
}
```
