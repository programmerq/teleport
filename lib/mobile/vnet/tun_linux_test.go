// Teleport
// Copyright (C) 2026 Gravitational, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

//go:build linux

package vnet

import (
	"errors"
	"net"
	"os"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// TestTUNDeviceAgainstKernelTUN drives the adapter against a real kernel TUN
// device, which is what it will be given on Android.
//
// The point is not just that packets move: it is that the adapter needs no
// ioctl of its own. wireguard-go's tun.CreateUnmonitoredTUNFromFD issues
// TUNGETIFF and TUNSETIFF and opens a netlink socket against the interface,
// none of which an app may do to the interface VpnService created for it. This
// test wraps a descriptor the same way the Android service does - as an opaque
// fd - and checks that reading and writing still work.
func TestTUNDeviceAgainstKernelTUN(t *testing.T) {
	fd, name := createKernelTUN(t)

	device, err := newTUNDeviceFromFD(fd, "android-style")
	require.NoError(t, err)
	t.Cleanup(func() { _ = device.Close() })

	// The adapter reports the name it was given, never the kernel's, because on
	// Android the kernel's is not knowable.
	reported, err := device.Name()
	require.NoError(t, err)
	require.Equal(t, "android-style", reported)
	require.NotEqual(t, name, reported)

	// 10.123.0.0/24 is routed to the interface once it is up and addressed, so
	// anything sent to 10.123.0.2 arrives on the descriptor.
	configureInterface(t, name, "10.123.0.1", "255.255.255.0")

	type readResult struct {
		packet []byte
		err    error
	}
	reads := make(chan readResult, 1)
	go func() {
		bufs := [][]byte{make([]byte, 2048)}
		sizes := make([]int, 1)
		const offset = 16 // a nonzero offset, as VNet uses
		n, err := device.Read(bufs, sizes, offset)
		if err != nil {
			reads <- readResult{err: err}
			return
		}
		if n != 1 {
			reads <- readResult{err: errors.New("expected exactly one packet")}
			return
		}
		reads <- readResult{packet: bufs[0][offset : offset+sizes[0]]}
	}()

	conn, err := net.Dial("udp", "10.123.0.2:9999")
	require.NoError(t, err)
	defer conn.Close()
	_, err = conn.Write([]byte("teleport"))
	require.NoError(t, err)

	select {
	case result := <-reads:
		require.NoError(t, result.err)
		packet := result.packet
		require.GreaterOrEqual(t, len(packet), 20, "short packet: %x", packet)
		require.Equal(t, byte(4), packet[0]>>4, "expected an IPv4 packet, got %x", packet)
		// Destination address sits at bytes 16..20 of an IPv4 header.
		require.Equal(t, net.IP{10, 123, 0, 2}, net.IP(packet[16:20]))
		require.Contains(t, string(packet), "teleport", "payload should be carried through")
	case <-time.After(15 * time.Second):
		t.Fatal("no packet arrived on the TUN device")
	}

	// Writing an IP packet back into the kernel must be accepted. The packet is
	// addressed to the interface itself so it is simply delivered and dropped.
	require.NoError(t, writeProbePacket(device))
}

// writeProbePacket sends a minimal well-formed UDP/IPv4 packet into the device.
func writeProbePacket(device *tunDeviceFromFD) error {
	const offset = 16
	payload := []byte("probe")
	total := 20 + 8 + len(payload)

	packet := make([]byte, offset+total)
	ip := packet[offset:]
	ip[0] = 0x45 // IPv4, 5 word header
	ip[2] = byte(total >> 8)
	ip[3] = byte(total)
	ip[8] = 64 // TTL
	ip[9] = unix.IPPROTO_UDP
	copy(ip[12:16], []byte{10, 123, 0, 2}) // source
	copy(ip[16:20], []byte{10, 123, 0, 1}) // destination: the interface itself
	putIPChecksum(ip[:20])

	udp := ip[20:]
	udp[0], udp[1] = 0x27, 0x0F // source port 9999
	udp[2], udp[3] = 0x27, 0x0F // destination port 9999
	length := 8 + len(payload)
	udp[4] = byte(length >> 8)
	udp[5] = byte(length)
	copy(udp[8:], payload)

	written, err := device.Write([][]byte{packet}, offset)
	if err != nil {
		return err
	}
	if written != 1 {
		return errors.New("expected one packet to be written")
	}
	return nil
}

func putIPChecksum(header []byte) {
	header[10], header[11] = 0, 0
	var sum uint32
	for i := 0; i < len(header); i += 2 {
		sum += uint32(header[i])<<8 | uint32(header[i+1])
	}
	for sum>>16 > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	checksum := ^uint16(sum)
	header[10] = byte(checksum >> 8)
	header[11] = byte(checksum)
}

// ifreq mirrors struct ifreq for the ioctls used below.
type ifreq struct {
	name  [unix.IFNAMSIZ]byte
	union [24]byte
}

// createKernelTUN allocates a TUN interface and returns a descriptor for it
// along with the kernel's name for the interface. It skips the test when the
// environment cannot provide one.
func createKernelTUN(t *testing.T) (int, string) {
	t.Helper()

	file, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		t.Skipf("cannot open /dev/net/tun: %v", err)
	}

	var req ifreq
	copy(req.name[:], "vnettest0")
	// IFF_NO_PI matches Android, which delivers bare IP packets with no prefix.
	flags := uint16(unix.IFF_TUN | unix.IFF_NO_PI)
	*(*uint16)(unsafe.Pointer(&req.union[0])) = flags

	if _, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		file.Fd(),
		uintptr(unix.TUNSETIFF),
		uintptr(unsafe.Pointer(&req)),
	); errno != 0 {
		file.Close()
		t.Skipf("cannot create a TUN interface (needs CAP_NET_ADMIN): %v", errno)
	}

	name := string(req.name[:clen(req.name[:])])

	// Hand the raw descriptor over the way Android's detachFd() does, so the
	// os.File does not close it underneath the adapter.
	fd, err := unix.Dup(int(file.Fd()))
	require.NoError(t, err)
	require.NoError(t, file.Close())

	return fd, name
}

// configureInterface brings the interface up with an address, using the classic
// socket ioctls rather than netlink so the test needs no extra dependency.
func configureInterface(t *testing.T, name, addr, netmask string) {
	t.Helper()

	sock, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	require.NoError(t, err)
	defer unix.Close(sock)

	set := func(request uintptr, req *ifreq) error {
		_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(sock), request, uintptr(unsafe.Pointer(req)))
		if errno != 0 {
			return errno
		}
		return nil
	}

	sockaddr := func(ip string) [24]byte {
		var union [24]byte
		*(*uint16)(unsafe.Pointer(&union[0])) = unix.AF_INET
		copy(union[4:8], net.ParseIP(ip).To4())
		return union
	}

	var req ifreq
	copy(req.name[:], name)

	req.union = sockaddr(addr)
	if err := set(unix.SIOCSIFADDR, &req); err != nil {
		t.Skipf("cannot set an address on %s: %v", name, err)
	}

	req.union = sockaddr(netmask)
	require.NoError(t, set(unix.SIOCSIFNETMASK, &req))

	req.union = [24]byte{}
	*(*uint16)(unsafe.Pointer(&req.union[0])) = unix.IFF_UP | unix.IFF_RUNNING
	require.NoError(t, set(unix.SIOCSIFFLAGS, &req))
}

func clen(b []byte) int {
	for i, c := range b {
		if c == 0 {
			return i
		}
	}
	return len(b)
}
