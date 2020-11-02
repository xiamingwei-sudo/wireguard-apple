// SPDX-License-Identifier: MIT
// Copyright © 2018-2019 WireGuard LLC. All Rights Reserved.

import Foundation
import NetworkExtension

open class WireGuardPacketTunnelProvider: NEPacketTunnelProvider {

    open override func startTunnel(options: [String: NSObject]?, completionHandler startTunnelCompletionHandler: @escaping (Error?) -> Void) {
        fatalError()
    }

    open override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        fatalError()
    }

    open override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)? = nil) {
        fatalError()
    }

}
