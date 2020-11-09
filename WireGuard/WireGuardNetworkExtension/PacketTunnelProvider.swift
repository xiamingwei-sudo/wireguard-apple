// SPDX-License-Identifier: MIT
// Copyright © 2018-2019 WireGuard LLC. All Rights Reserved.

import Foundation
import NetworkExtension
import os
import WireGuardKit

class PacketTunnelProvider: WireGuardPacketTunnelProvider {
    private var errorNotifier: ErrorNotifier?

    override func startTunnel(options: [String: NSObject]?, completionHandler startTunnelCompletionHandler: @escaping (Error?) -> Void) {
        Logger.configureGlobal(tagged: "NET", withFilePath: FileManager.logFileURL?.path)

        super.startTunnel(options: options, completionHandler: startTunnelCompletionHandler)
    }

    open override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        ErrorNotifier.removeLastErrorFile()

        super.stopTunnel(with: reason, completionHandler: completionHandler)
    }

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

    // MARK: - Subclassing

    override func handleTunnelError(_ error: PacketTunnelProviderError) {
        super.handleTunnelError(error)
        if self.errorNotifier == nil {
            self.errorNotifier = ErrorNotifier(activationAttemptId: self.activationAttemptId)
        }

        self.errorNotifier?.notify(error)
    }

    override func logLine(level: PacketTunnelLogLevel, message: String) {
        wg_log(level.osLogType, message: message)
    }

    override func getTunnelConfiguration(from tunnelProviderProtocol: NETunnelProviderProtocol) throws -> TunnelConfiguration {
        if let tunnelConfiguration = tunnelProviderProtocol.asTunnelConfiguration() {
            return tunnelConfiguration
        } else {
            throw InvalidTunnelConfigurationError()
        }
    }
}

extension PacketTunnelLogLevel {
    var osLogType: OSLogType {
        switch self {
        case .info:
            return .info
        case .debug:
            return .debug
        case .error:
            return .error
        }
    }
}

struct InvalidTunnelConfigurationError: LocalizedError {
    var errorDescription: String? {
        return "Invalid tunnel configuration"
    }
}
