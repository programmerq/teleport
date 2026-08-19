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
	"context"
	"strings"

	"github.com/gravitational/trace"

	libvnet "github.com/gravitational/teleport/lib/vnet"
)

// Host is implemented by the Android app, in Kotlin or Java, and lets VNet
// drive the VpnService that owns the TUN interface.
//
// Its method signatures are restricted to the types gomobile can bind across
// the JNI boundary: no slices of strings, no context, no variadic arguments.
// Lists are therefore passed as newline-separated strings, and a Go context is
// not threaded through - the app should treat every call as cancellable by
// stopping the session.
type Host interface {
	// ConfigureNetwork is called with the network configuration VNet wants the
	// host to apply, and is called again roughly every ten seconds, so it must
	// be idempotent: the app should compare against the configuration it last
	// applied and only re-establish the VpnService when something changed.
	//
	// Applying a change means building a new VpnService.Builder with the given
	// addresses, routes and DNS servers and calling establish() again. That
	// returns a fresh descriptor, so the app must then restart the session with
	// the new descriptor - a VNet session is bound to the descriptor it was
	// started with.
	ConfigureNetwork(cfg *NetworkConfig) error

	// TeardownNetwork is called once when VNet shuts down. The app should close
	// the VpnService interface.
	TeardownNetwork() error

	// UpstreamNameservers returns the resolvers VNet forwards non-Teleport DNS
	// queries to, one "ip:port" per line. On Android these come from
	// ConnectivityManager.getLinkProperties(activeNetwork).getDnsServers() for
	// the underlying (non-VPN) network. Returning an empty string makes VNet
	// fail those queries rather than forward them.
	UpstreamNameservers() (string, error)
}

// NetworkConfig mirrors [libvnet.EmbeddedVNetHostConfig] using only types that
// gomobile can bind. Every list-valued field is a newline-separated string.
//
// Field names avoid a leading acronym to work around
// https://github.com/golang/go/issues/32008, the same gomobile bug already
// documented in lib/mobile/verify/enroll.
type NetworkConfig struct {
	// AddressIPv4 is the IPv4 address to assign to the TUN interface, without a
	// prefix length. Pass it to VpnService.Builder.addAddress.
	AddressIPv4 string
	// AddressIPv6 is the IPv6 address to assign to the TUN interface, without a
	// prefix length.
	AddressIPv6 string
	// Routes holds the CIDR ranges that should be routed into the TUN
	// interface, one per line. Pass each to VpnService.Builder.addRoute. This
	// is a split tunnel: only Teleport app traffic is captured.
	Routes string
	// Nameservers holds the addresses VNet serves DNS on, one per line. Pass
	// each to VpnService.Builder.addDnsServer. They are inside Routes, so
	// queries reach VNet through the TUN interface.
	Nameservers string
	// SearchDomains holds the DNS zones VNet is authoritative for, one per
	// line. Android has no split-DNS control comparable to macOS, so these
	// cannot be used to scope which queries reach VNet; they are still useful
	// for VpnService.Builder.addSearchDomain and for showing the user which
	// zones the session covers.
	SearchDomains string
}

// hostBridge adapts a [Host] to the callbacks [libvnet.EmbeddedVNet] expects.
type hostBridge struct {
	host Host
}

// configureHost implements [libvnet.EmbeddedConfigureHostFunc]. VNet passes a
// nil config to signal shutdown.
func (b hostBridge) configureHost(_ context.Context, cfg *libvnet.EmbeddedVNetHostConfig) error {
	if cfg == nil {
		return trace.Wrap(b.host.TeardownNetwork(), "tearing down host network configuration")
	}
	return trace.Wrap(b.host.ConfigureNetwork(&NetworkConfig{
		AddressIPv4:   cfg.DeviceIPv4,
		AddressIPv6:   cfg.DeviceIPv6,
		Routes:        strings.Join(cfg.CIDRRanges, "\n"),
		Nameservers:   strings.Join(cfg.DNSAddrs, "\n"),
		SearchDomains: strings.Join(cfg.DNSZones, "\n"),
	}), "applying host network configuration")
}

// UpstreamNameservers implements [dns.UpstreamNameserverSource].
func (b hostBridge) UpstreamNameservers(context.Context) ([]string, error) {
	joined, err := b.host.UpstreamNameservers()
	if err != nil {
		return nil, trace.Wrap(err, "getting upstream nameservers from host")
	}
	var nameservers []string
	for _, line := range strings.Split(joined, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			nameservers = append(nameservers, line)
		}
	}
	return nameservers, nil
}
