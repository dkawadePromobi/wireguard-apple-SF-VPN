// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import Foundation

public final class TunnelConfiguration {
    public var name: String?
    public var interface: InterfaceConfiguration
    public let peers: [PeerConfiguration]

    public init(name: String?, interface: InterfaceConfiguration, peers: [PeerConfiguration]) {
        self.interface = interface
        self.peers = peers
        self.name = name

        let peerPublicKeysArray = peers.map { $0.publicKey }
        let peerPublicKeysSet = Set<PublicKey>(peerPublicKeysArray)
        if peerPublicKeysArray.count != peerPublicKeysSet.count {
            fatalError("Two or more peers cannot have the same public key")
        }
    }
}

extension TunnelConfiguration: Equatable {
    public static func == (lhs: TunnelConfiguration, rhs: TunnelConfiguration) -> Bool {
        return lhs.name == rhs.name &&
            lhs.interface == rhs.interface &&
            Set(lhs.peers) == Set(rhs.peers)
    }
}

extension TunnelConfiguration {
    /// `true` when any peer has an `AllowedIPs` entry with prefix length 0 (`0.0.0.0/0` or `::/0`).
    /// Used for DNS (`matchDomains`) and for apps extending split-tunnel vs full-tunnel behavior.
    public var routesAllTrafficThroughWireGuard: Bool {
        for peer in peers {
            for range in peer.allowedIPs where range.networkPrefixLength == 0 {
                return true
            }
        }
        return false
    }
}
