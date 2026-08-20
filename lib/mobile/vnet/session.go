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

// Package vnet runs Teleport VNet inside an Android app, on top of the TUN file
// descriptor returned by VpnService.Builder.establish(). It is bound into an
// Android library with gomobile, so every exported name here is part of the
// app's Java/Kotlin API.
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
// # gomobile constraints
//
// Only a narrow set of types crosses the JNI boundary, so lists are passed as
// newline-separated strings and field names avoid a leading acronym, which
// trips https://github.com/golang/go/issues/32008. No exported method may be
// named after a final method on java.lang.Object, which is why the session is
// awaited with AwaitExit rather than Wait.
//
// # Status
//
// This is a prototype. It supports app access to TCP applications in a single
// root cluster; databases, SSH, leaf clusters and multiple simultaneous
// profiles are not implemented. See mobile/android-vnet.md.
package vnet

import (
	"context"
	"log/slog"
	"sync"

	"github.com/gravitational/trace"

	libvnet "github.com/gravitational/teleport/lib/vnet"
)

// sessionConfig configures a VNet [Session]. It is not exported because it
// holds Go-side dependencies that gomobile cannot bind; the app reaches this
// through [Client.StartVNet].
type sessionConfig struct {
	// tunFD is the TUN file descriptor VNet reads packets from and writes
	// packets to. On Android it is the result of calling detachFd() on the
	// ParcelFileDescriptor returned by VpnService.Builder.establish(). The
	// session takes ownership of it and closes it on Stop.
	tunFD int

	// tunName is the name reported for the TUN interface. It is only used for
	// logging, because an app cannot see the real interface name that
	// VpnService created.
	tunName string

	// host lets VNet apply its desired network configuration to the app's
	// VpnService and discover the device's real DNS resolvers.
	host Host

	// applicationService resolves Teleport DNS names and issues the client
	// certificates VNet uses to dial applications.
	applicationService libvnet.EmbeddedApplicationService

	logger *slog.Logger
}

func (c *sessionConfig) checkAndSetDefaults() error {
	if c.tunFD < 0 {
		return trace.BadParameter("a TUN file descriptor is required")
	}
	if c.host == nil {
		return trace.BadParameter("a host is required")
	}
	if c.applicationService == nil {
		return trace.BadParameter("an application service is required")
	}
	if c.tunName == "" {
		c.tunName = "tun"
	}
	if c.logger == nil {
		c.logger = slog.Default()
	}
	return nil
}

// Session is a running VNet. The app holds it for the lifetime of its
// VpnService and calls Stop when the service is torn down.
type Session struct {
	cancel context.CancelFunc
	done   chan struct{}

	mu  sync.Mutex
	err error

	stopOnce sync.Once
}

// startSession takes ownership of cfg.tunFD and runs VNet against it in the
// background.
func startSession(cfg sessionConfig) (*Session, error) {
	if err := cfg.checkAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}

	device, err := newTUNDeviceFromFD(cfg.tunFD, cfg.tunName)
	if err != nil {
		return nil, trace.Wrap(err, "wrapping TUN file descriptor")
	}

	bridge := hostBridge{host: cfg.host}
	net, err := libvnet.NewEmbeddedVNet(libvnet.EmbeddedVNetConfig{
		Device:                   device,
		ApplicationService:       cfg.applicationService,
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
		cfg.logger.InfoContext(ctx, "VNet starting", "tun_fd", cfg.tunFD)
		err := net.Run(ctx)
		if err != nil {
			cfg.logger.ErrorContext(ctx, "VNet stopped with an error", "error", err)
		} else {
			cfg.logger.InfoContext(ctx, "VNet stopped")
		}
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

// AwaitExit blocks until the session finishes and returns the error that ended
// it, if any. A session that was stopped cleanly returns no error.
//
// It is not named Wait because gomobile would map that onto Object.wait, which
// is final in Java.
func (s *Session) AwaitExit() error {
	<-s.done
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

// IsRunning reports whether the session is still running.
func (s *Session) IsRunning() bool {
	select {
	case <-s.done:
		return false
	default:
		return true
	}
}

// ErrorMessage returns the message of the error that ended the session, or an
// empty string if the session is still running or ended cleanly. It exists
// because gomobile maps a Go error return onto a thrown Java exception, which
// is awkward to poll from a VpnService.
func (s *Session) ErrorMessage() string {
	if s.IsRunning() {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err == nil {
		return ""
	}
	return s.err.Error()
}
