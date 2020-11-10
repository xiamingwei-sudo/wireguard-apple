// SPDX-License-Identifier: MIT
// Copyright © 2018-2019 WireGuard LLC. All Rights Reserved.

import Foundation
import WireGuardKit

struct Curve25519 {

    static let keyLength: Int = 32

    static func generatePrivateKey() -> Data {
        var privateKey = [UInt8](repeating: 0, count: TunnelConfiguration.keyLength)
        curve25519_generate_private_key(&privateKey)
        return Data(privateKey)
    }

    static func generatePublicKey(fromPrivateKey privateKey: Data) -> Data {
        assert(privateKey.count == TunnelConfiguration.keyLength)
        var publicKeyBytes = [UInt8](repeating: 0, count: TunnelConfiguration.keyLength)
        var privateKeyBytes = [UInt8](privateKey)
        curve25519_derive_public_key(&publicKeyBytes, &privateKeyBytes)
        return Data(publicKeyBytes)
    }
}

extension InterfaceConfiguration {
    var publicKey: Data {
        return Curve25519.generatePublicKey(fromPrivateKey: privateKey)
    }
}
