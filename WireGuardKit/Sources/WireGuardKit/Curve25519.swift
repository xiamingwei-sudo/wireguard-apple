// SPDX-License-Identifier: MIT
// Copyright © 2018-2019 WireGuard LLC. All Rights Reserved.

import Foundation
import WireGuardKitCTarget

public enum Curve25519 {}

extension Curve25519 {
    public static let keyLength: Int = 32

    public static func generatePrivateKey() -> Data {
        var privateKey = [UInt8](repeating: 0, count: TunnelConfiguration.keyLength)
        curve25519_generate_private_key(&privateKey)
        return Data(privateKey)
    }

    public static func generatePublicKey(fromPrivateKey privateKey: Data) -> Data? {
        assert(privateKey.count == TunnelConfiguration.keyLength)

        return privateKey.withUnsafeBytes { rawBufferPointer -> Data? in
            guard let privateKeyBytes = rawBufferPointer.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                return nil
            }
            var publicKeyBytes = [UInt8](repeating: 0, count: TunnelConfiguration.keyLength)
            curve25519_derive_public_key(&publicKeyBytes, privateKeyBytes)
            return Data(publicKeyBytes)
        }
    }
}
