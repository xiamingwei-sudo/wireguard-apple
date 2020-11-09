// SPDX-License-Identifier: MIT
// Copyright © 2018-2019 WireGuard LLC. All Rights Reserved.

import Foundation
import NetworkExtension
import WireGuardKit

class PacketTunnelProvider: WireGuardPacketTunnelProvider {
    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)? = nil) {
        if messageData.count == 1 && messageData[0] == 0 {
            getWireGuardConfiguration { settings in
                if let settings = settings {
                    let data = settings.data(using: .utf8)!
                    completionHandler?(data)
                } else {
                    completionHandler?(nil)
                }
            }
        } else {
            completionHandler?(nil)
        }
    }
}
