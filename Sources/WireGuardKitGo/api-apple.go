/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2018-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

package main

// #include <stdlib.h>
// #include <sys/types.h>
// static void callLogger(void *func, void *ctx, int level, const char *msg)
// {
// 	((void(*)(void *, int, const char *))func)(ctx, level, msg);
// }
import "C"

import (
	"fmt"
	"math"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

var loggerFunc unsafe.Pointer
var loggerCtx unsafe.Pointer

type CLogger int

func cstring(s string) *C.char {
	b, err := unix.BytePtrFromString(s)
	if err != nil {
		b := [1]C.char{}
		return &b[0]
	}
	return (*C.char)(unsafe.Pointer(b))
}

func (l CLogger) Printf(format string, args ...interface{}) {
	if uintptr(loggerFunc) == 0 {
		return
	}
	C.callLogger(loggerFunc, loggerCtx, C.int(l), cstring(fmt.Sprintf(format, args...)))
}

type tunnelHandle struct {
	*device.Device
	*device.Logger
}

var tunnelHandles = make(map[int32]tunnelHandle)
var channelTUNHandles = make(map[int32]*ChannelTUN)

func init() {
	signals := make(chan os.Signal)
	signal.Notify(signals, unix.SIGUSR2)
	go func() {
		buf := make([]byte, os.Getpagesize())
		for {
			select {
			case <-signals:
				n := runtime.Stack(buf, true)
				buf[n] = 0
				if uintptr(loggerFunc) != 0 {
					C.callLogger(loggerFunc, loggerCtx, 0, (*C.char)(unsafe.Pointer(&buf[0])))
				}
			}
		}
	}()
}

// ---------------------------------------------------------------------------
// ChannelTUN: software TUN backed by Go channels for per-app VPN.
//
// In per-app VPN mode, iOS delivers packets to NEPacketTunnelFlow with
// Apple-specific framing. If wg-go reads directly from the utun fd it
// sees non-IP bytes and logs "Received packet with unknown IP version".
//
// ChannelTUN removes the utun fd from the picture entirely. Swift reads
// clean IP packets from NEPacketTunnelFlow and pushes them into the
// Inbound channel via wgSendPacket; wg-go encrypts them and sends them
// to the peer. Decrypted responses go to the Outbound channel and Swift
// drains them via wgReceivePacket back into NEPacketTunnelFlow.
// ---------------------------------------------------------------------------

type ChannelTUN struct {
	Inbound  chan []byte
	Outbound chan []byte
	closed   chan struct{}
	once     sync.Once
	events   chan tun.Event
	mtu      int
}

func NewChannelTUN(mtu int) *ChannelTUN {
	return &ChannelTUN{
		Inbound:  make(chan []byte, 256),
		Outbound: make(chan []byte, 256),
		closed:   make(chan struct{}),
		events:   make(chan tun.Event, 16),
		mtu:      mtu,
	}
}

func (t *ChannelTUN) File() *os.File { return nil }

func (t *ChannelTUN) Read(buf []byte, offset int) (int, error) {
	select {
	case <-t.closed:
		return 0, os.ErrClosed
	case pkt := <-t.Inbound:
		n := copy(buf[offset:], pkt)
		return n, nil
	}
}

func (t *ChannelTUN) Write(buf []byte, offset int) (int, error) {
	pkt := make([]byte, len(buf)-offset)
	copy(pkt, buf[offset:])
	select {
	case <-t.closed:
		return 0, os.ErrClosed
	case t.Outbound <- pkt:
	}
	return len(pkt), nil
}

func (t *ChannelTUN) Flush() error              { return nil }
func (t *ChannelTUN) MTU() (int, error)          { return t.mtu, nil }
func (t *ChannelTUN) Name() (string, error)      { return "perapp0", nil }
func (t *ChannelTUN) Events() <-chan tun.Event   { return t.events }

func (t *ChannelTUN) Close() error {
	t.once.Do(func() {
		close(t.closed)
		t.events <- tun.EventDown
		close(t.events)
	})
	return nil
}

// ---------------------------------------------------------------------------
// Logger & standard tunnel (device-wide) — original, unchanged
// ---------------------------------------------------------------------------

//export wgSetLogger
func wgSetLogger(context, loggerFn uintptr) {
	loggerCtx = unsafe.Pointer(context)
	loggerFunc = unsafe.Pointer(loggerFn)
}

//export wgTurnOn
func wgTurnOn(settings *C.char, tunFd int32) int32 {
	logger := &device.Logger{
		Verbosef: CLogger(0).Printf,
		Errorf:   CLogger(1).Printf,
	}
	dupTunFd, err := unix.Dup(int(tunFd))
	if err != nil {
		logger.Errorf("Unable to dup tun fd: %v", err)
		return -1
	}

	err = unix.SetNonblock(dupTunFd, true)
	if err != nil {
		logger.Errorf("Unable to set tun fd as non blocking: %v", err)
		unix.Close(dupTunFd)
		return -1
	}
	tun, err := tun.CreateTUNFromFile(os.NewFile(uintptr(dupTunFd), "/dev/tun"), 0)
	if err != nil {
		logger.Errorf("Unable to create new tun device from fd: %v", err)
		unix.Close(dupTunFd)
		return -1
	}
	logger.Verbosef("Attaching to interface")
	dev := device.NewDevice(tun, conn.NewStdNetBind(), logger)

	err = dev.IpcSet(C.GoString(settings))
	if err != nil {
		logger.Errorf("Unable to set IPC settings: %v", err)
		unix.Close(dupTunFd)
		return -1
	}

	dev.Up()
	logger.Verbosef("Device started")

	var i int32
	for i = 0; i < math.MaxInt32; i++ {
		if _, exists := tunnelHandles[i]; !exists {
			break
		}
	}
	if i == math.MaxInt32 {
		unix.Close(dupTunFd)
		return -1
	}
	tunnelHandles[i] = tunnelHandle{dev, logger}
	return i
}

// ---------------------------------------------------------------------------
// Per-app tunnel — uses ChannelTUN, NO utun fd involved
// ---------------------------------------------------------------------------

//export wgTurnOnPerApp
func wgTurnOnPerApp(settings *C.char) int32 {
	logger := &device.Logger{
		Verbosef: CLogger(0).Printf,
		Errorf:   CLogger(1).Printf,
	}

	tunDev := NewChannelTUN(1280)

	logger.Verbosef("Creating per-app ChannelTUN device")
	dev := device.NewDevice(tunDev, conn.NewStdNetBind(), logger)

	err := dev.IpcSet(C.GoString(settings))
	if err != nil {
		logger.Errorf("Per-app: unable to set IPC settings: %v", err)
		dev.Close()
		return -1
	}

	dev.Up()
	logger.Verbosef("Per-app device started")

	var i int32
	for i = 0; i < math.MaxInt32; i++ {
		if _, exists := tunnelHandles[i]; !exists {
			break
		}
	}
	if i == math.MaxInt32 {
		return -1
	}
	tunnelHandles[i] = tunnelHandle{dev, logger}
	channelTUNHandles[i] = tunDev
	return i
}

//export wgSendPacket
func wgSendPacket(handle int32, packetData unsafe.Pointer, packetLen C.int) {
	ct, ok := channelTUNHandles[handle]
	if !ok || ct == nil {
		return
	}
	pkt := C.GoBytes(packetData, packetLen)
	select {
	case ct.Inbound <- pkt:
	default:
		CLogger(1).Printf("wgSendPacket: inbound channel full, dropping packet")
	}
}

//export wgReceivePacket
func wgReceivePacket(handle int32, buffer unsafe.Pointer, bufferLen C.int) C.int {
	ct, ok := channelTUNHandles[handle]
	if !ok || ct == nil {
		return -1
	}
	select {
	case pkt := <-ct.Outbound:
		if len(pkt) > int(bufferLen) {
			CLogger(1).Printf("wgReceivePacket: packet too large, dropping")
			return 0
		}
		copy((*[1 << 20]byte)(buffer)[:len(pkt)], pkt)
		return C.int(len(pkt))
	default:
		return 0
	}
}

// ---------------------------------------------------------------------------
// Common control functions
// ---------------------------------------------------------------------------

//export wgTurnOff
func wgTurnOff(tunnelHandle int32) {
	dev, ok := tunnelHandles[tunnelHandle]
	if !ok {
		return
	}
	if ct, ok := channelTUNHandles[tunnelHandle]; ok {
		ct.Close()
		delete(channelTUNHandles, tunnelHandle)
	}
	delete(tunnelHandles, tunnelHandle)
	dev.Close()
}

//export wgSetConfig
func wgSetConfig(tunnelHandle int32, settings *C.char) int64 {
	dev, ok := tunnelHandles[tunnelHandle]
	if !ok {
		return 0
	}
	err := dev.IpcSet(C.GoString(settings))
	if err != nil {
		dev.Errorf("Unable to set IPC settings: %v", err)
		if ipcErr, ok := err.(*device.IPCError); ok {
			return ipcErr.ErrorCode()
		}
		return -1
	}
	return 0
}

//export wgGetConfig
func wgGetConfig(tunnelHandle int32) *C.char {
	device, ok := tunnelHandles[tunnelHandle]
	if !ok {
		return nil
	}
	settings, err := device.IpcGet()
	if err != nil {
		return nil
	}
	return C.CString(settings)
}

//export wgBumpSockets
func wgBumpSockets(tunnelHandle int32) {
	dev, ok := tunnelHandles[tunnelHandle]
	if !ok {
		return
	}
	go func() {
		for i := 0; i < 10; i++ {
			err := dev.BindUpdate()
			if err == nil {
				dev.SendKeepalivesToPeersWithCurrentKeypair()
				return
			}
			dev.Errorf("Unable to update bind, try %d: %v", i+1, err)
			time.Sleep(time.Second / 2)
		}
		dev.Errorf("Gave up trying to update bind; tunnel is likely dysfunctional")
	}()
}

//export wgDisableSomeRoamingForBrokenMobileSemantics
func wgDisableSomeRoamingForBrokenMobileSemantics(tunnelHandle int32) {
	dev, ok := tunnelHandles[tunnelHandle]
	if !ok {
		return
	}
	dev.DisableSomeRoamingForBrokenMobileSemantics()
}

//export wgVersion
func wgVersion() *C.char {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return C.CString("unknown")
	}
	for _, dep := range info.Deps {
		if dep.Path == "golang.zx2c4.com/wireguard" {
			parts := strings.Split(dep.Version, "-")
			if len(parts) == 3 && len(parts[2]) == 12 {
				return C.CString(parts[2][:7])
			}
			return C.CString(dep.Version)
		}
	}
	return C.CString("unknown")
}

func main() {}
