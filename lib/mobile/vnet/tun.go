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
	"sync"

	"github.com/gravitational/trace"
	"golang.org/x/sys/unix"

	libvnet "github.com/gravitational/teleport/lib/vnet"
)

// tunDeviceFromFD adapts a raw TUN file descriptor to [libvnet.TUNDevice].
//
// It exists because wireguard-go's tun.CreateUnmonitoredTUNFromFD cannot be
// used with a descriptor obtained from Android's VpnService: that constructor
// calls Name(), which issues a TUNGETIFF ioctl, and then initFromFlags, which
// issues TUNGETIFF/TUNSETIFF and opens a netlink socket. An app process does
// not own the interface created by VpnService, so those calls are not
// available to it. All VNet needs from the device is packet I/O and a name for
// logging, both of which this type provides without any ioctl.
//
// The descriptor must be owned by the caller of newTUNDeviceFromFD: on Android
// that means calling ParcelFileDescriptor.detachFd(), not getFd(), so that the
// Java side does not close the descriptor out from under Go. Close closes it.
type tunDeviceFromFD struct {
	file      *os.File
	name      string
	closeOnce sync.Once
	closeErr  error
}

// newTUNDeviceFromFD wraps fd in a [libvnet.TUNDevice]. The descriptor is put
// into non-blocking mode so that reads are served by the Go runtime poller and
// a concurrent Close unblocks a pending Read.
func newTUNDeviceFromFD(fd int, name string) (*tunDeviceFromFD, error) {
	if fd < 0 {
		return nil, trace.BadParameter("invalid TUN file descriptor %d", fd)
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		return nil, trace.Wrap(err, "setting TUN descriptor non-blocking")
	}
	return &tunDeviceFromFD{
		file: os.NewFile(uintptr(fd), name),
		name: name,
	}, nil
}

// Name implements [libvnet.TUNDevice]. The name is synthetic: VNet only uses it
// for logging and to pass to the host configuration callback, and on Android
// the real interface name is not visible to the app.
func (t *tunDeviceFromFD) Name() (string, error) {
	return t.name, nil
}

// Read implements [libvnet.TUNDevice]. Android's TUN descriptor is opened with
// IFF_NO_PI, so each read yields exactly one bare IP packet with no prefix.
func (t *tunDeviceFromFD) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	if len(bufs) == 0 {
		return 0, nil
	}
	if len(sizes) < 1 {
		return 0, trace.BadParameter("sizes must have room for at least one packet")
	}
	n, err := t.file.Read(bufs[0][offset:])
	if err != nil {
		return 0, err
	}
	sizes[0] = n
	return 1, nil
}

// Write implements [libvnet.TUNDevice]. It returns the number of packets
// written, stopping at the first error.
func (t *tunDeviceFromFD) Write(bufs [][]byte, offset int) (int, error) {
	var written int
	for _, buf := range bufs {
		packet := buf[offset:]
		if len(packet) == 0 {
			continue
		}
		if _, err := t.file.Write(packet); err != nil {
			return written, err
		}
		written++
	}
	return written, nil
}

// BatchSize implements [libvnet.TUNDevice]. Batching is a wireguard-go
// optimization built on the TUN device's own GSO/GRO support, which is not
// available through a VpnService descriptor, so packets are handled one at a
// time.
func (t *tunDeviceFromFD) BatchSize() int {
	return 1
}

// Close implements [libvnet.TUNDevice]. It is safe to call while a Read is in
// flight; the pending Read returns os.ErrClosed.
func (t *tunDeviceFromFD) Close() error {
	t.closeOnce.Do(func() {
		t.closeErr = t.file.Close()
	})
	return trace.Wrap(t.closeErr)
}

var _ libvnet.TUNDevice = (*tunDeviceFromFD)(nil)
