// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import Foundation
import NetworkExtension
import os

class PacketTunnelProvider: NEPacketTunnelProvider {

    // MARK: - Properties

    private lazy var adapter: WireGuardAdapter = {
        return WireGuardAdapter(with: self) { logLevel, message in
            wg_log(logLevel.osLogLevel, message: message)
        }
    }()

    /// True when this tunnel was started as a per-app VPN via MDM applayer payload.
    private var isPerAppVPN: Bool = false

    /// Handle returned by wgTurnOnPerApp — only valid when isPerAppVPN == true.
    private var perAppHandle: Int32 = -1

    /// Controls the relay loops between NEPacketTunnelFlow and wg-go.
    private var relayRunning = false

    /// Background queue for draining wg-go outbound packets.
    private let drainQueue = DispatchQueue(label: "WireGuardPerAppDrainQueue", qos: .userInteractive)

    // MARK: - Tunnel Lifecycle

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        let activationAttemptId = options?["activationAttemptId"] as? String
        let errorNotifier = ErrorNotifier(activationAttemptId: activationAttemptId)

        Logger.configureGlobal(tagged: "NET", withFilePath: FileManager.logFileURL?.path)

        wg_log(.info, message: "Starting tunnel from the " + (activationAttemptId == nil ? "OS directly, rather than the app" : "app"))

        guard let tunnelProviderProtocol = self.protocolConfiguration as? NETunnelProviderProtocol,
              let tunnelConfiguration = tunnelProviderProtocol.asTunnelConfiguration() else {
            errorNotifier.notify(PacketTunnelProviderError.savedProtocolConfigurationIsInvalid)
            completionHandler(PacketTunnelProviderError.savedProtocolConfigurationIsInvalid)
            return
        }

        isPerAppVPN = detectPerAppVPN(from: tunnelProviderProtocol)
        wg_log(.info, message: "Per-app VPN mode: \(isPerAppVPN)")

        if isPerAppVPN {
            startPerAppTunnel(
                tunnelConfiguration: tunnelConfiguration,
                errorNotifier: errorNotifier,
                completionHandler: completionHandler
            )
        } else {
            startDeviceTunnel(
                tunnelConfiguration: tunnelConfiguration,
                errorNotifier: errorNotifier,
                completionHandler: completionHandler
            )
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        wg_log(.info, staticMessage: "Stopping tunnel")

        relayRunning = false

        if perAppHandle >= 0 {
            wgTurnOff(perAppHandle)
            perAppHandle = -1
            ErrorNotifier.removeLastErrorFile()
            completionHandler()
        } else {
            adapter.stop { error in
                ErrorNotifier.removeLastErrorFile()
                if let error = error {
                    wg_log(.error, message: "Failed to stop WireGuard adapter: \(error.localizedDescription)")
                }
                completionHandler()

                #if os(macOS)
                // HACK: This is a filthy hack to work around Apple bug 32073323 (dup'd by us as 47526107).
                // Remove it when they finally fix this upstream and the fix has been rolled out to
                // sufficient quantities of users.
                exit(0)
                #endif
            }
        }
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)? = nil) {
        guard let completionHandler = completionHandler else { return }

        if messageData.count == 1 && messageData[0] == 0 {
            adapter.getRuntimeConfiguration { settings in
                var data: Data?
                if let settings = settings {
                    data = settings.data(using: .utf8)!
                }
                completionHandler(data)
            }
        } else {
            completionHandler(nil)
        }
    }

    // MARK: - Device-wide VPN (stock path, unchanged)

    private func startDeviceTunnel(
        tunnelConfiguration: TunnelConfiguration,
        errorNotifier: ErrorNotifier,
        completionHandler: @escaping (Error?) -> Void
    ) {
        adapter.start(tunnelConfiguration: tunnelConfiguration) { adapterError in
            guard let adapterError = adapterError else {
                let interfaceName = self.adapter.interfaceName ?? "unknown"
                wg_log(.info, message: "Tunnel interface is \(interfaceName)")
                completionHandler(nil)
                return
            }
            self.handleAdapterError(adapterError, errorNotifier: errorNotifier, completionHandler: completionHandler)
        }
    }

    // MARK: - Per-App VPN Path

    /// Starts the tunnel using `wgTurnOnPerApp` — a ChannelTUN-backed WireGuard
    /// device that has NO utun fd involvement.
    ///
    /// `wgTurnOn` wraps the utun fd with `tun.CreateTUNFromFile`. In per-app VPN
    /// mode iOS writes packets to the utun with Apple's per-app flow framing (not
    /// raw IP), so wg-go sees a non-IP first byte and logs
    /// "Received packet with unknown IP version".
    ///
    /// `wgTurnOnPerApp` gives wg-go a Go channel-backed TUN. It only ever
    /// sees raw IP packets that we explicitly push via `wgSendPacket` from
    /// `NEPacketTunnelFlow` — Apple's framing bytes never reach wg-go at all.
    private func startPerAppTunnel(
        tunnelConfiguration: TunnelConfiguration,
        errorNotifier: ErrorNotifier,
        completionHandler: @escaping (Error?) -> Void
    ) {
        guard let wgConfig = buildUAPIConfig(from: tunnelConfiguration) else {
            wg_log(.error, staticMessage: "Per-app VPN: failed to build UAPI config")
            errorNotifier.notify(PacketTunnelProviderError.savedProtocolConfigurationIsInvalid)
            completionHandler(PacketTunnelProviderError.savedProtocolConfigurationIsInvalid)
            return
        }

        let networkSettings = buildNetworkSettings(from: tunnelConfiguration)

        setTunnelNetworkSettings(networkSettings) { error in
            if let error = error {
                wg_log(.error, message: "Per-app VPN: setTunnelNetworkSettings failed: \(error.localizedDescription)")
                errorNotifier.notify(PacketTunnelProviderError.couldNotSetNetworkSettings)
                completionHandler(PacketTunnelProviderError.couldNotSetNetworkSettings)
                return
            }

            let handle = wgConfig.withCString { wgTurnOnPerApp($0) }
            guard handle >= 0 else {
                wg_log(.error, message: "Per-app VPN: wgTurnOnPerApp returned \(handle)")
                errorNotifier.notify(PacketTunnelProviderError.couldNotStartBackend)
                completionHandler(PacketTunnelProviderError.couldNotStartBackend)
                return
            }

            self.perAppHandle = handle
            wg_log(.info, message: "Per-app tunnel started, handle=\(handle)")

            #if os(iOS)
            wgDisableSomeRoamingForBrokenMobileSemantics(handle)
            #endif

            self.relayRunning = true
            self.startInboundRelay()
            self.startOutboundDrain()

            completionHandler(nil)
        }
    }

    // MARK: - Relay: NEPacketTunnelFlow → wg-go  (Inbound)

    /// Reads packets iOS delivers for per-app VPN flows and pushes raw IP
    /// into wg-go via `wgSendPacket`. `NEPacketTunnelFlow` strips Apple's
    /// per-app framing — `packet.data` is always a raw IP packet.
    private func startInboundRelay() {
        packetFlow.readPacketObjects { [weak self] packets in
            guard let self = self, self.relayRunning, self.perAppHandle >= 0 else { return }

            for packet in packets {
                let data = packet.data
                guard self.isValidIPPacket(data) else {
                    wg_log(.error, message: "Inbound relay: dropping non-IP packet (first byte=\(data.first.map { String(format: "0x%02x", $0) } ?? "nil"))")
                    continue
                }
                data.withUnsafeBytes { ptr in
                    guard let base = ptr.baseAddress else { return }
                    wgSendPacket(self.perAppHandle, base, Int32(data.count))
                }
            }

            if self.relayRunning {
                self.startInboundRelay()
            }
        }
    }

    // MARK: - Relay: wg-go → NEPacketTunnelFlow  (Outbound)

    /// Drains decrypted packets from wg-go and injects them back into the OS
    /// via `NEPacketTunnelFlow` so the app's sockets receive the responses.
    private func startOutboundDrain() {
        drainQueue.async { [weak self] in
            guard let self = self else { return }

            let bufferSize = 65535
            var buffer = [UInt8](repeating: 0, count: bufferSize)

            while self.relayRunning, self.perAppHandle >= 0 {
                let n = buffer.withUnsafeMutableBytes { ptr -> Int32 in
                    guard let base = ptr.baseAddress else { return 0 }
                    return wgReceivePacket(self.perAppHandle, base, Int32(bufferSize))
                }

                if n < 0 { break }
                if n == 0 {
                    usleep(200)
                    continue
                }

                let packetData = Data(bytes: buffer, count: Int(n))
                guard let version = self.ipVersion(of: packetData) else {
                    wg_log(.error, message: "Outbound drain: wg-go produced packet with unknown IP version")
                    continue
                }

                let family: sa_family_t = version == 4 ? sa_family_t(AF_INET) : sa_family_t(AF_INET6)
                self.packetFlow.writePacketObjects([NEPacket(data: packetData, protocolFamily: family)])
            }

            wg_log(.info, staticMessage: "Per-app outbound drain stopped")
        }
    }

    // MARK: - Config / Settings Builders

    private func buildUAPIConfig(from config: TunnelConfiguration) -> String? {
        let endpoints = config.peers.map { $0.endpoint }
        let resolved = DNSResolver.resolveSync(endpoints: endpoints)

        var s = ""
        s += "private_key=\(config.interface.privateKey.hexKey)\n"
        if let port = config.interface.listenPort { s += "listen_port=\(port)\n" }
        if !config.peers.isEmpty { s += "replace_peers=true\n" }

        for (peer, result) in zip(config.peers, resolved) {
            s += "public_key=\(peer.publicKey.hexKey)\n"
            if let psk = peer.preSharedKey?.hexKey { s += "preshared_key=\(psk)\n" }
            if let r = result, case .success(let ep) = r {
                s += "endpoint=\(ep.stringRepresentation)\n"
            }
            s += "persistent_keepalive_interval=\(peer.persistentKeepAlive ?? 0)\n"
            if !peer.allowedIPs.isEmpty {
                s += "replace_allowed_ips=true\n"
                peer.allowedIPs.forEach { s += "allowed_ip=\($0.stringRepresentation)\n" }
            }
        }
        return s
    }

    private func buildNetworkSettings(from config: TunnelConfiguration) -> NEPacketTunnelNetworkSettings {
        let endpoints = config.peers.map { $0.endpoint }
        let resolved = DNSResolver.resolveSync(endpoints: endpoints)
        let remoteAddress: String = resolved
            .compactMap { $0 }
            .compactMap { result -> String? in
                guard case .success(let ep) = result else { return nil }
                switch ep.host {
                case .ipv4(let a): return "\(a)"
                case .ipv6(let a): return "\(a)"
                case .name:        return nil
                }
            }
            .first ?? "127.0.0.1"

        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: remoteAddress)

        if !config.interface.dns.isEmpty || !config.interface.dnsSearch.isEmpty {
            let dns = NEDNSSettings(servers: config.interface.dns.map { $0.stringRepresentation })
            dns.searchDomains = config.interface.dnsSearch
            if !config.interface.dns.isEmpty { dns.matchDomains = [""] }
            settings.dnsSettings = dns
        }

        let mtu = config.interface.mtu ?? 0
        if mtu == 0 {
            #if os(iOS)
            settings.mtu = NSNumber(value: 1280)
            #elseif os(macOS)
            settings.tunnelOverheadBytes = 80
            #else
            #error("Unimplemented")
            #endif
        } else {
            settings.mtu = NSNumber(value: mtu)
        }

        var v4addr = [String]()
        var v4mask = [String]()
        var v4routes = [NEIPv4Route]()
        for addr in config.interface.addresses where addr.address is IPv4Address {
            v4addr.append("\(addr.address)")
            v4mask.append("\(addr.subnetMask())")
            let r = NEIPv4Route(destinationAddress: "\(addr.maskedAddress())", subnetMask: "\(addr.subnetMask())")
            r.gatewayAddress = "\(addr.address)"
            v4routes.append(r)
        }
        for peer in config.peers {
            for addr in peer.allowedIPs where addr.address is IPv4Address {
                v4routes.append(NEIPv4Route(destinationAddress: "\(addr.address)", subnetMask: "\(addr.subnetMask())"))
            }
        }
        let ipv4 = NEIPv4Settings(addresses: v4addr, subnetMasks: v4mask)
        ipv4.includedRoutes = v4routes
        settings.ipv4Settings = ipv4

        var v6addr = [String]()
        var v6prefix = [NSNumber]()
        var v6routes = [NEIPv6Route]()
        for addr in config.interface.addresses where addr.address is IPv6Address {
            v6addr.append("\(addr.address)")
            v6prefix.append(NSNumber(value: min(120, addr.networkPrefixLength)))
            let r = NEIPv6Route(destinationAddress: "\(addr.maskedAddress())", networkPrefixLength: NSNumber(value: addr.networkPrefixLength))
            r.gatewayAddress = "\(addr.address)"
            v6routes.append(r)
        }
        for peer in config.peers {
            for addr in peer.allowedIPs where addr.address is IPv6Address {
                v6routes.append(NEIPv6Route(destinationAddress: "\(addr.address)", networkPrefixLength: NSNumber(value: addr.networkPrefixLength)))
            }
        }
        let ipv6 = NEIPv6Settings(addresses: v6addr, networkPrefixLengths: v6prefix)
        ipv6.includedRoutes = v6routes
        settings.ipv6Settings = ipv6

        return settings
    }

    // MARK: - Helpers

    /// Detects per-app VPN mode.
    ///
    /// Priority: explicit `PerAppVPN` flag in VendorConfig > auto-detect.
    ///
    /// Auto-detect: when iOS activates a tunnel from an MDM
    /// `com.apple.vpn.managed.applayer` profile, `passwordReference` is nil
    /// and the WireGuard config lives in `providerConfiguration["WgQuickConfig"]`.
    /// App-configured device-wide VPN always stores the config in the keychain
    /// (`passwordReference` is set). This distinction reliably identifies
    /// MDM per-app VPN without requiring extra keys in the MDM payload.
    private func detectPerAppVPN(from proto: NETunnelProviderProtocol) -> Bool {
        let config = proto.providerConfiguration
        if let flag = config?["PerAppVPN"] as? Bool { return flag }
        if let flag = config?["IsPerAppVPN"] as? String { return flag == "true" }
        if proto.passwordReference == nil && config?["WgQuickConfig"] != nil {
            return true
        }
        return false
    }

    private func isValidIPPacket(_ data: Data) -> Bool {
        guard let first = data.first else { return false }
        let v = first >> 4
        return v == 4 || v == 6
    }

    private func ipVersion(of data: Data) -> Int? {
        guard let first = data.first else { return nil }
        let v = Int(first >> 4)
        return (v == 4 || v == 6) ? v : nil
    }

    private func handleAdapterError(_ error: WireGuardAdapterError, errorNotifier: ErrorNotifier, completionHandler: @escaping (Error?) -> Void) {
        switch error {
        case .cannotLocateTunnelFileDescriptor:
            wg_log(.error, staticMessage: "Starting tunnel failed: could not determine file descriptor")
            errorNotifier.notify(PacketTunnelProviderError.couldNotDetermineFileDescriptor)
            completionHandler(PacketTunnelProviderError.couldNotDetermineFileDescriptor)

        case .dnsResolution(let dnsErrors):
            let hostnamesWithDnsResolutionFailure = dnsErrors.map { $0.address }
                .joined(separator: ", ")
            wg_log(.error, message: "DNS resolution failed for the following hostnames: \(hostnamesWithDnsResolutionFailure)")
            errorNotifier.notify(PacketTunnelProviderError.dnsResolutionFailure)
            completionHandler(PacketTunnelProviderError.dnsResolutionFailure)

        case .setNetworkSettings(let error):
            wg_log(.error, message: "Starting tunnel failed with setTunnelNetworkSettings returning \(error.localizedDescription)")
            errorNotifier.notify(PacketTunnelProviderError.couldNotSetNetworkSettings)
            completionHandler(PacketTunnelProviderError.couldNotSetNetworkSettings)

        case .startWireGuardBackend(let errorCode):
            wg_log(.error, message: "Starting tunnel failed with wgTurnOn returning \(errorCode)")
            errorNotifier.notify(PacketTunnelProviderError.couldNotStartBackend)
            completionHandler(PacketTunnelProviderError.couldNotStartBackend)

        case .invalidState:
            fatalError()
        }
    }
}

extension WireGuardLogLevel {
    var osLogLevel: OSLogType {
        switch self {
        case .verbose:
            return .debug
        case .error:
            return .error
        }
    }
}
