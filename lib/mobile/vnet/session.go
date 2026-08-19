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

// Package vnet runs Teleport VNet inside a mobile app process, on top of a TUN
// file descriptor the app already owns. It is written for Android, where the
// descriptor comes from VpnService.Builder.establish(), but nothing here is
// Android-specific beyond the documentation, so it builds and is tested on
// Linux too.
//
// # How this differs from tsh and Teleport Connect
//
// On desktop, VNet is split across two processes: an unprivileged client
// application that holds the user's credentials, and a privileged process that
// creates the TUN device and edits the host's routing table and DNS resolver.
// Android needs neither half of that split. VpnService hands an app a TUN
// descriptor with no elevation, and the routing and DNS configuration is
// expressed by the same builder that produced the descriptor, so there is
// nothing to escalate for. This package therefore builds on
// [libvnet.EmbeddedVNet], the single-process embedding of VNet, and bridges its
// two host-facing seams - the host configuration callback and the upstream
// nameserver source - to the app through [Host].
//
// # Status
//
// This is a proof of concept. It compiles for android/arm64 and its packet I/O
// path is covered by tests on Linux, but it has never been run on a device, and
// [libvnet.EmbeddedApplicationService] - which resolves Teleport DNS names and
// issues client certificates - is supplied by the caller rather than
// implemented here. See mobile/android-vnet.md for what remains.
package vnet

import (
	"context"
	"sync"

	"github.com/gravitational/trace"

	libvnet "github.com/gravitational/teleport/lib/vnet"
)

// Config configures a VNet [Session].
type Config struct {
	// TUNFD is the TUN file descriptor VNet reads packets from and writes
	// packets to. On Android it is the result of calling detachFd() on the
	// ParcelFileDescriptor returned by VpnService.Builder.establish(). The
	// session takes ownership of it and closes it on Stop.
	TUNFD int

	// TUNName is the name reported for the TUN interface. It is only used for
	// logging, because an app cannot see the real interface name that
	// VpnService created. Defaults to "tun".
	TUNName string

	// Host lets VNet apply its desired network configuration to the app's
	// VpnService and discover the device's real DNS resolvers. Required.
	Host Host

	// ApplicationService resolves Teleport DNS names and issues the client
	// certificates VNet uses to dial applications. It is a Go-side dependency
	// rather than something the app implements, because it needs a Teleport
	// client. Required.
	ApplicationService libvnet.EmbeddedApplicationService
}

func (c *Config) checkAndSetDefaults() error {
	if c.TUNFD < 0 {
		return trace.BadParameter("TUNFD is required")
	}
	if c.Host == nil {
		return trace.BadParameter("Host is required")
	}
	if c.ApplicationService == nil {
		return trace.BadParameter("ApplicationService is required")
	}
	if c.TUNName == "" {
		c.TUNName = "tun"
	}
	return nil
}

// Session is a running VNet. It is created by [Start] and runs until [Stop] is
// called or VNet fails.
type Session struct {
	cancel context.CancelFunc
	done   chan struct{}

	mu  sync.Mutex
	err error

	stopOnce sync.Once
}

// Start takes ownership of cfg.TUNFD and runs VNet against it in the
// background. The caller should hold the returned Session for the lifetime of
// the VpnService and call Stop when the service is torn down.
func Start(cfg Config) (*Session, error) {
	if err := cfg.checkAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}

	device, err := newTUNDeviceFromFD(cfg.TUNFD, cfg.TUNName)
	if err != nil {
		return nil, trace.Wrap(err, "wrapping TUN file descriptor")
	}

	bridge := hostBridge{host: cfg.Host}
	net, err := libvnet.NewEmbeddedVNet(libvnet.EmbeddedVNetConfig{
		Device:                   device,
		ApplicationService:       cfg.ApplicationService,
		ConfigureHost:            bridge.configureHost,
		UpstreamNameserverSource: bridge,
	})
	if err != nil {
		device.Close()
		return nil, trace.Wrap(err, "creating embedded VNet")
	}

	ctx, cancel := context.WithCancel(context.Background())
	session := &Session{
		cancel: cancel,
		done:   make(chan struct{}),
	}
	go func() {
		defer close(session.done)
		defer device.Close()
		err := net.Run(ctx)
		session.mu.Lock()
		session.err = err
		session.mu.Unlock()
	}()
	return session, nil
}

// Stop shuts VNet down and closes the TUN file descriptor. It blocks until the
// session has finished, and is safe to call more than once.
func (s *Session) Stop() {
	s.stopOnce.Do(s.cancel)
	<-s.done
}

// Wait blocks until the session finishes and returns the error that ended it,
// if any. A session that was stopped cleanly returns nil.
func (s *Session) Wait() error {
	<-s.done
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

// Err returns the message of the error that ended the session, or an empty
// string if the session is still running or ended cleanly. It exists because
// gomobile maps a Go error return onto a thrown Java exception, which is
// awkward to poll from a VpnService.
func (s *Session) Err() string {
	select {
	case <-s.done:
	default:
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err == nil {
		return ""
	}
	return s.err.Error()
}
