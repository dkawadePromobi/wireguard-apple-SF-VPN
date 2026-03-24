// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import Foundation

/// Keys for `NETunnelProviderProtocol.providerConfiguration` / MDM `VendorConfig` beyond `WgQuickConfig`.
public enum WireGuardVendorConfigKeys {
    /// When `true` as `NSNumber`, the tunnel may merge `0.0.0.0/0` and `::/0` into a single peer’s
    /// `AllowedIPs` for MDM per-app VPN. When `false`, never merge. Omitted = implementation-defined.
    public static let expandAllowedIPsToRouteAllInternet = "ExpandAllowedIPsToRouteAllInternet"
}
