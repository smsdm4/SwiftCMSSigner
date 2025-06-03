// swift-tools-version: 6.1
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription


let package = Package(
    name: "SwiftCMSSigner",
    platforms: [
        .iOS(.v15),
        .macOS(.v11)
    ],
    products: [
        .library(
            name: "SwiftCMSSigner",
            targets: ["SwiftCMSSigner"]),
    ],
    dependencies: [
        .package(url: "https://github.com/krzyzanowskim/OpenSSL-Package.git", exact: "3.3.3001")
    ],
    targets: [
        .target(
            name: "SwiftCMSSigner",
            dependencies: [
                .product(name: "OpenSSL", package: "OpenSSL-Package")
            ]
        ),
        .testTarget(
            name: "SwiftCMSSignerTests",
            dependencies: ["SwiftCMSSigner"]),
    ]
)
