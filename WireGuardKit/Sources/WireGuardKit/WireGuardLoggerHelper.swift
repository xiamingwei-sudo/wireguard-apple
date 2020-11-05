// SPDX-License-Identifier: MIT
// Copyright © 2018-2019 WireGuard LLC. All Rights Reserved.

import Foundation
import libwg_go

/// A private (singleton) log helper class for WireGuard backend
class WireGuardLoggerHelper {
    typealias LogHandler = (PacketTunnelLogLevel, String) -> Void

    /// Shared instance
    static var shared = WireGuardLoggerHelper()

    /// Queue used for synchronizing access to `WireGuardLoggerHelper` members
    private static let loggingQueue = DispatchQueue(label: "WireGuardLoggerHelper", qos: .utility)

    /// Log handler invoked on each new message from WireGuard backend
    private var logHandler: LogHandler?

    /// Private initializer
    private init() {}

    /// Set global log handler for WireGuard backend
    func setLogHandler(block: LogHandler?) {
        WireGuardLoggerHelper.loggingQueue.async {
            self.logHandler = block
        }

        wgSetLogger { (level, message) in
            guard let message = message else { return }

            let swiftString = String(cString: message).trimmingCharacters(in: .newlines)
            let logLevel = PacketTunnelLogLevel(rawValue: level) ?? .debug

            WireGuardLoggerHelper.shared.dispatchLogEntry(level: logLevel, message: swiftString)
        }
    }

    private func dispatchLogEntry(level: PacketTunnelLogLevel, message: String) {
        WireGuardLoggerHelper.loggingQueue.async {
            self.logHandler?(level, message)
        }
    }
}
