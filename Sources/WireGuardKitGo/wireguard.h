/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2018-2023 WireGuard LLC. All Rights Reserved.
 */

#ifndef WIREGUARD_H
#define WIREGUARD_H

#include <sys/types.h>
#include <stdint.h>
#include <stdbool.h>

typedef void(*logger_fn_t)(void *context, int level, const char *msg);
extern void wgSetLogger(void *context, logger_fn_t logger_fn);
extern int wgTurnOn(const char *settings, int32_t tun_fd);
extern void wgTurnOff(int handle);
extern int64_t wgSetConfig(int handle, const char *settings);
extern char *wgGetConfig(int handle);
extern void wgBumpSockets(int handle);
extern void wgDisableSomeRoamingForBrokenMobileSemantics(int handle);
extern const char *wgVersion();

/* Per-app VPN — ChannelTUN-backed, no utun fd required.
 *
 *   1. handle = wgTurnOnPerApp(settings)
 *   2. wgSendPacket(handle, ptr, len)        // NEPacketTunnelFlow -> wg-go
 *   3. n = wgReceivePacket(handle, buf, cap)  // wg-go -> NEPacketTunnelFlow
 *   4. wgTurnOff(handle)
 */
extern int wgTurnOnPerApp(const char *settings);
extern void wgSendPacket(int handle, const void *packetData, int packetLen);
extern int wgReceivePacket(int handle, void *buffer, int bufferLen);

#endif
