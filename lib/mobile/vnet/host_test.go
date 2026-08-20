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
	"testing"

	"github.com/stretchr/testify/require"

	libvnet "github.com/gravitational/teleport/lib/vnet"
)

type fakeHost struct {
	configured  []*NetworkConfig
	tornDown    int
	nameservers string
	err         error
}

func (h *fakeHost) ConfigureNetwork(cfg *NetworkConfig) error {
	h.configured = append(h.configured, cfg)
	return h.err
}

func (h *fakeHost) TeardownNetwork() error {
	h.tornDown++
	return h.err
}

func (h *fakeHost) UpstreamNameservers() (string, error) {
	return h.nameservers, h.err
}

var _ Host = (*fakeHost)(nil)

func TestHostBridgeConfigureHost(t *testing.T) {
	host := &fakeHost{}
	bridge := hostBridge{host: host}

	require.NoError(t, bridge.configureHost(t.Context(), &libvnet.EmbeddedVNetHostConfig{
		DeviceIPv4: "100.64.0.1",
		DeviceIPv6: "fdec:146c:95f6::1",
		CIDRRanges: []string{"100.64.0.0/10", "fdec:146c:95f6::/64"},
		DNSAddrs:   []string{"100.64.0.2", "fdec:146c:95f6::2"},
		DNSZones:   []string{"teleport.example.com", "internal.example.com"},
	}))

	require.Len(t, host.configured, 1)
	require.Equal(t, &NetworkConfig{
		AddressIPv4:   "100.64.0.1",
		AddressIPv6:   "fdec:146c:95f6::1",
		Routes:        "100.64.0.0/10\nfdec:146c:95f6::/64",
		Nameservers:   "100.64.0.2\nfdec:146c:95f6::2",
		SearchDomains: "teleport.example.com\ninternal.example.com",
	}, host.configured[0])
	require.Zero(t, host.tornDown)
}

func TestHostBridgeTearsDownOnNilConfig(t *testing.T) {
	host := &fakeHost{}
	bridge := hostBridge{host: host}

	// VNet signals shutdown by passing a nil config rather than a separate call.
	require.NoError(t, bridge.configureHost(t.Context(), nil))
	require.Equal(t, 1, host.tornDown)
	require.Empty(t, host.configured)
}

func TestHostBridgeUpstreamNameservers(t *testing.T) {
	for _, test := range []struct {
		name string
		raw  string
		want []string
	}{
		{
			name: "several",
			raw:  "8.8.8.8:53\n1.1.1.1:53",
			want: []string{"8.8.8.8:53", "1.1.1.1:53"},
		},
		{
			// Kotlin's joinToString and a trailing newline are both easy to
			// produce by accident, so blank lines must not become nameservers.
			name: "blank lines ignored",
			raw:  "\n8.8.8.8:53\n\n  \n",
			want: []string{"8.8.8.8:53"},
		},
		{
			name: "none",
			raw:  "",
			want: nil,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			bridge := hostBridge{host: &fakeHost{nameservers: test.raw}}
			got, err := bridge.UpstreamNameservers(t.Context())
			require.NoError(t, err)
			require.Equal(t, test.want, got)
		})
	}
}

func TestHostBridgePropagatesErrors(t *testing.T) {
	hostErr := errors.New("vpn service is not prepared")
	bridge := hostBridge{host: &fakeHost{err: hostErr}}

	require.ErrorIs(t, bridge.configureHost(t.Context(), &libvnet.EmbeddedVNetHostConfig{}), hostErr)
	require.ErrorIs(t, bridge.configureHost(t.Context(), nil), hostErr)

	_, err := bridge.UpstreamNameservers(t.Context())
	require.ErrorIs(t, err, hostErr)
}

func TestStartSessionRejectsIncompleteConfig(t *testing.T) {
	_, err := startSession(sessionConfig{tunFD: 3})
	require.Error(t, err)

	_, err = startSession(sessionConfig{tunFD: 3, host: &fakeHost{}})
	require.Error(t, err)
}
