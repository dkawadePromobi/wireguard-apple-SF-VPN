// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import Foundation

/// Options that affect how `NEPacketTunnelNetworkSettings` are built (e.g. MDM per-app VPN).
public struct WireGuardNetworkSettingsOptions {
    /// When `true`, IPv4/IPv6 default routes are included in `includedRoutes` in addition to
    /// WireGuard `AllowedIPs`. Required for some **per-app VPN** (App-Layer / `routingMethod == .sourceApplication`)
    /// configurations where the system routes by originating app; narrow destination-only routes may not
    /// receive traffic otherwise. WireGuard still enforces `AllowedIPs` for what is encrypted to the peer.
    public var perAppVPNIncludeDefaultRoutes: Bool

    public init(perAppVPNIncludeDefaultRoutes: Bool = false) {
        self.perAppVPNIncludeDefaultRoutes = perAppVPNIncludeDefaultRoutes
    }
}
