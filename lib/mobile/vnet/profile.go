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
	"sync"

	"github.com/gravitational/trace"

	vnetv1 "github.com/gravitational/teleport/gen/proto/go/teleport/lib/vnet/v1"
	"github.com/gravitational/teleport/lib/client"
)

// profileClient owns the Teleport client for one logged-in profile and caches
// the cluster connection, which is expensive to establish.
type profileClient struct {
	name     string
	store    *client.Store
	insecure bool

	mu      sync.Mutex
	cluster *client.ClusterClient
}

func newProfileClient(store *client.Store, profileName string, insecure bool) *profileClient {
	return &profileClient{
		name:     profileName,
		store:    store,
		insecure: insecure,
	}
}

// teleportClient builds a fresh [client.TeleportClient] from the stored profile.
func (p *profileClient) teleportClient() (*client.TeleportClient, error) {
	cfg := &client.Config{ClientStore: p.store}
	if err := cfg.LoadProfile(p.name); err != nil {
		return nil, trace.Wrap(err, "loading profile %s", p.name)
	}
	cfg.InsecureSkipVerify = p.insecure
	tc, err := client.NewClient(cfg)
	if err != nil {
		return nil, trace.Wrap(err, "creating Teleport client for profile %s", p.name)
	}
	return tc, nil
}

// clusterClient returns a connected cluster client, establishing one on first
// use. Callers must not close it; it lives as long as the profileClient.
func (p *profileClient) clusterClient(ctx context.Context) (*client.ClusterClient, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cluster != nil {
		return p.cluster, nil
	}

	tc, err := p.teleportClient()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	cluster, err := tc.ConnectToCluster(ctx)
	if err != nil {
		return nil, trace.Wrap(err, "connecting to cluster for profile %s", p.name)
	}
	p.cluster = cluster
	return cluster, nil
}

// close releases the cached cluster connection.
func (p *profileClient) close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cluster != nil {
		_ = p.cluster.Close()
		p.cluster = nil
	}
}

// status returns the stored profile status, which carries the active access
// requests that app certificates have to be issued against.
func (p *profileClient) status() (*client.ProfileStatus, error) {
	status, err := p.store.ReadProfileStatus(p.name)
	return status, trace.Wrap(err, "reading profile status for %s", p.name)
}

// dialOptions returns the ALPN dial options VNet uses to reach the proxy.
func (p *profileClient) dialOptions(ctx context.Context) (*vnetv1.DialOptions, error) {
	profile, err := p.store.GetProfile(p.name)
	if err != nil {
		return nil, trace.Wrap(err, "loading profile %s", p.name)
	}
	opts := vnetv1.DialOptions_builder{
		WebProxyAddr:            profile.WebProxyAddr,
		AlpnConnUpgradeRequired: profile.TLSRoutingConnUpgradeRequired,
		InsecureSkipVerify:      p.insecure,
	}.Build()

	tc, err := p.teleportClient()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	certPool, err := tc.RootClusterCACertPoolPEM(ctx)
	if err != nil {
		return nil, trace.Wrap(err, "loading root cluster CA cert pool")
	}
	opts.SetRootClusterCaCertPool(certPool)
	return opts, nil
}
