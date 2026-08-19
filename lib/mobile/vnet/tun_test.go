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
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// newTestTUNPair returns a tunDeviceFromFD and the peer end of a datagram
// socket pair standing in for the kernel side of the TUN device. A datagram
// socket preserves packet boundaries the same way a TUN descriptor opened with
// IFF_NO_PI does, so it exercises the same read and write semantics without
// needing the privileges to create a real interface.
func newTestTUNPair(t *testing.T) (*tunDeviceFromFD, *os.File) {
	t.Helper()

	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	require.NoError(t, err)

	device, err := newTUNDeviceFromFD(fds[0], "tun-test")
	require.NoError(t, err)
	t.Cleanup(func() { _ = device.Close() })

	peer := os.NewFile(uintptr(fds[1]), "peer")
	t.Cleanup(func() { _ = peer.Close() })

	return device, peer
}

func TestTUNDeviceName(t *testing.T) {
	device, _ := newTestTUNPair(t)

	// The name is synthetic: unlike wireguard-go's constructor this must not
	// issue a TUNGETIFF ioctl, which an app cannot make against a descriptor
	// from VpnService.
	name, err := device.Name()
	require.NoError(t, err)
	require.Equal(t, "tun-test", name)
}

func TestTUNDeviceReadPreservesPacketBoundaries(t *testing.T) {
	device, peer := newTestTUNPair(t)

	packets := [][]byte{
		[]byte("first packet"),
		[]byte("second, rather longer, packet"),
	}
	for _, packet := range packets {
		_, err := peer.Write(packet)
		require.NoError(t, err)
	}

	// VNet reads with a nonzero offset, so the read must land at bufs[0][offset:]
	// and report the packet length in sizes[0], not the offset plus the length.
	const offset = 4
	for _, want := range packets {
		bufs := [][]byte{make([]byte, 1500)}
		sizes := make([]int, 1)

		n, err := device.Read(bufs, sizes, offset)
		require.NoError(t, err)
		require.Equal(t, 1, n, "each read should yield exactly one packet")
		require.Equal(t, len(want), sizes[0])
		require.Equal(t, want, bufs[0][offset:offset+sizes[0]])
	}
}

func TestTUNDeviceWrite(t *testing.T) {
	device, peer := newTestTUNPair(t)

	const offset = 4
	packets := [][]byte{
		append(make([]byte, offset), []byte("outgoing one")...),
		append(make([]byte, offset), []byte("outgoing two")...),
	}

	written, err := device.Write(packets, offset)
	require.NoError(t, err)
	require.Equal(t, len(packets), written)

	for _, packet := range packets {
		buf := make([]byte, 1500)
		n, err := peer.Read(buf)
		require.NoError(t, err)
		// The offset region must be stripped, not sent.
		require.Equal(t, packet[offset:], buf[:n])
	}
}

func TestTUNDeviceWriteSkipsEmptyPackets(t *testing.T) {
	device, _ := newTestTUNPair(t)

	written, err := device.Write([][]byte{make([]byte, 4)}, 4)
	require.NoError(t, err)
	require.Zero(t, written)
}

func TestTUNDeviceCloseUnblocksRead(t *testing.T) {
	device, _ := newTestTUNPair(t)

	readErr := make(chan error, 1)
	go func() {
		bufs := [][]byte{make([]byte, 1500)}
		_, err := device.Read(bufs, make([]int, 1), 0)
		readErr <- err
	}()

	// Give the read a moment to block in the poller before closing under it.
	// Without the non-blocking descriptor this Close would not interrupt it.
	time.Sleep(50 * time.Millisecond)
	require.NoError(t, device.Close())

	select {
	case err := <-readErr:
		require.Error(t, err, "Read should fail once the device is closed")
	case <-time.After(10 * time.Second):
		t.Fatal("Read did not return after Close")
	}
}

func TestTUNDeviceCloseIsIdempotent(t *testing.T) {
	device, _ := newTestTUNPair(t)

	require.NoError(t, device.Close())
	// The second close must not return "file already closed", so that a
	// deferred Close in Start does not mask the real shutdown error.
	require.NoError(t, device.Close())
}

func TestTUNDeviceRejectsInvalidFD(t *testing.T) {
	_, err := newTUNDeviceFromFD(-1, "tun")
	assert.Error(t, err)
}

func TestTUNDeviceBatchSize(t *testing.T) {
	device, _ := newTestTUNPair(t)
	require.Equal(t, 1, device.BatchSize())
}
