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
	"crypto"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/gravitational/trace"

	apiclient "github.com/gravitational/teleport/api/client"
	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/types"
	typesvnet "github.com/gravitational/teleport/api/types/vnet"
	vnetv1 "github.com/gravitational/teleport/gen/proto/go/teleport/lib/vnet/v1"
	"github.com/gravitational/teleport/lib/client"
	"github.com/gravitational/teleport/lib/utils"
	libvnet "github.com/gravitational/teleport/lib/vnet"
)

// osConfigCacheTTL bounds how often the cluster is asked for its VNet config.
// The OS configuration loop runs every ten seconds, so without a cache every
// tick would cost two round trips to the proxy.
const osConfigCacheTTL = 30 * time.Second

// appService implements [libvnet.EmbeddedApplicationService] against a single
// logged-in Teleport profile.
//
// It is modelled on lib/tbot/services/beams/vnet_service.go, which does the same
// job for a bot identity. Like that one it is deliberately single-cluster: it
// resolves names against one profile and does not follow trusted-cluster links.
// Multi-profile and leaf-cluster support is what the full ClientApplication
// interface in lib/vnet provides, and reaching it needs the in-process user
// process described in mobile/android-vnet.md.
type appService struct {
	profile *profileClient
	logger  *slog.Logger
	cache   *utils.FnCache

	// signers holds the private key for each certificate handed out by
	// GetAppCert, so that a later GetAppSigner for the same app can sign with
	// it. VNet always calls GetAppCert before GetAppSigner.
	mu      sync.Mutex
	signers map[appSignerKey]crypto.Signer
}

type appSignerKey struct {
	profile     string
	leafCluster string
	name        string
	port        uint16
}

func newAppService(profile *profileClient, logger *slog.Logger) (*appService, error) {
	cache, err := utils.NewFnCache(utils.FnCacheConfig{TTL: osConfigCacheTTL})
	if err != nil {
		return nil, trace.Wrap(err, "creating cluster config cache")
	}
	return &appService{
		profile: profile,
		logger:  logger,
		cache:   cache,
		signers: make(map[appSignerKey]crypto.Signer),
	}, nil
}

// clusterConfig is the cluster-derived state both DNS resolution and OS
// configuration need.
type clusterConfig struct {
	proxyPublicAddr string
	clusterName     string
	dnsZones        []string
	ipv4CIDRRange   string
}

// clusterConfig pings the cluster and reads its vnet_config, caching the result.
func (s *appService) clusterConfig(ctx context.Context) (*clusterConfig, error) {
	return utils.FnCacheGet(ctx, s.cache, "clusterConfig", func(ctx context.Context) (*clusterConfig, error) {
		clusterClient, err := s.profile.clusterClient(ctx)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		authClient := clusterClient.CurrentCluster()

		pong, err := authClient.Ping(ctx)
		if err != nil {
			return nil, trace.Wrap(err, "pinging cluster")
		}

		// The proxy's own public address is always a VNet zone; apps default to
		// <app-name>.<proxy-public-addr>.
		zones := []string{hostname(pong.GetProxyPublicAddr())}
		cidrRange := typesvnet.DefaultIPv4CIDRRange

		vnetConfig, err := authClient.GetVnetConfig(ctx)
		switch {
		case trace.IsNotFound(err) || trace.IsNotImplemented(err) || trace.IsAccessDenied(err):
			// No cluster VNet config, or the user cannot read it. Defaults are
			// enough to serve apps at their default public address.
			s.logger.DebugContext(ctx, "No cluster vnet_config, using defaults", "error", err)
		case err != nil:
			return nil, trace.Wrap(err, "reading cluster vnet_config")
		default:
			for _, zone := range vnetConfig.GetSpec().GetCustomDnsZones() {
				zones = append(zones, zone.GetSuffix())
			}
			if custom := vnetConfig.GetSpec().GetIpv4CidrRange(); custom != "" {
				cidrRange = custom
			}
		}

		return &clusterConfig{
			proxyPublicAddr: pong.GetProxyPublicAddr(),
			clusterName:     pong.GetClusterName(),
			dnsZones:        zones,
			ipv4CIDRRange:   cidrRange,
		}, nil
	})
}

// GetTargetOSConfiguration implements [libvnet.EmbeddedApplicationService].
func (s *appService) GetTargetOSConfiguration(ctx context.Context) (*vnetv1.TargetOSConfiguration, error) {
	cfg, err := s.clusterConfig(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return vnetv1.TargetOSConfiguration_builder{
		DnsZones:       cfg.dnsZones,
		Ipv4CidrRanges: []string{cfg.ipv4CIDRRange},
	}.Build(), nil
}

// ResolveFQDN implements [libvnet.EmbeddedApplicationService]. An empty
// response means "not a Teleport name", and VNet forwards the query upstream.
func (s *appService) ResolveFQDN(ctx context.Context, fqdn string) (*vnetv1.ResolveFQDNResponse, error) {
	cfg, err := s.clusterConfig(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// The proxy's own name must keep resolving through normal DNS, or logging
	// in and reissuing certs would route through VNet and deadlock.
	if fqdn == fullyQualify(hostname(cfg.proxyPublicAddr)) {
		return &vnetv1.ResolveFQDNResponse{}, nil
	}

	var inZone bool
	for _, zone := range cfg.dnsZones {
		if isDescendantSubdomain(fqdn, zone) {
			inZone = true
			break
		}
	}
	if !inZone {
		s.logger.DebugContext(ctx, "FQDN is not under any VNet DNS zone, forwarding upstream",
			"fqdn", fqdn, "dns_zones", cfg.dnsZones)
		return &vnetv1.ResolveFQDNResponse{}, nil
	}

	clusterClient, err := s.profile.clusterClient(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Filter server-side rather than listing every app in the cluster. Apps may
	// be registered with or without the trailing dot, so match both.
	expr := fmt.Sprintf(`resource.spec.public_addr == %+q || resource.spec.public_addr == %+q`,
		fqdn, strings.TrimSuffix(fqdn, "."))
	page, err := apiclient.GetResourcePage[types.AppServer](ctx, clusterClient.CurrentCluster(), &proto.ListResourcesRequest{
		ResourceType:        types.KindAppServer,
		PredicateExpression: expr,
		Limit:               1,
	})
	if err != nil {
		return nil, trace.Wrap(err, "listing application servers for %s", fqdn)
	}
	if len(page.Resources) == 0 {
		s.logger.DebugContext(ctx, "No app matches FQDN", "fqdn", fqdn)
		return &vnetv1.ResolveFQDNResponse{}, nil
	}

	app, ok := page.Resources[0].GetApp().(*types.AppV3)
	if !ok {
		return nil, trace.BadParameter("expected *types.AppV3, got %T", page.Resources[0].GetApp())
	}

	dialOptions, err := s.profile.dialOptions(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	appInfo := vnetv1.AppInfo_builder{
		AppKey: vnetv1.AppKey_builder{
			Profile: s.profile.name,
			Name:    app.GetName(),
		}.Build(),
		App:           app,
		Ipv4CidrRange: cfg.ipv4CIDRRange,
		Cluster:       cfg.clusterName,
		DialOptions:   dialOptions,
	}.Build()

	switch {
	case app.IsTCP():
		s.logger.InfoContext(ctx, "Resolved FQDN to TCP app", "fqdn", fqdn, "app", app.GetName())
		return vnetv1.ResolveFQDNResponse_builder{
			MatchedTcpApp: vnetv1.MatchedTCPApp_builder{AppInfo: appInfo}.Build(),
		}.Build(), nil
	default:
		// HTTP apps need the HTTPS-in-mTLS tunnel, which browsers on the device
		// would have no way to trust. Leave them to the web UI.
		s.logger.DebugContext(ctx, "App protocol is not supported by VNet",
			"fqdn", fqdn, "app", app.GetName(), "uri", app.GetURI())
		return &vnetv1.ResolveFQDNResponse{}, nil
	}
}

// GetAppCert implements [libvnet.EmbeddedApplicationService].
func (s *appService) GetAppCert(ctx context.Context, appInfo *vnetv1.AppInfo, port uint16) (*tls.Certificate, error) {
	appKey := appInfo.GetAppKey()
	s.logger.InfoContext(ctx, "Issuing app certificate",
		"app", appKey.GetName(), "profile", appKey.GetProfile(), "port", port)

	clusterClient, err := s.profile.clusterClient(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	profileStatus, err := s.profile.status()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	result, err := clusterClient.IssueUserCertsWithMFA(ctx, client.ReissueParams{
		RouteToCluster: appKey.GetLeafCluster(),
		RouteToApp:     *libvnet.RouteToApp(appInfo, port),
		AccessRequests: profileStatus.ActiveRequests,
		RequesterName:  proto.UserCertsRequest_TSH_APP_LOCAL_PROXY,
	})
	if err != nil {
		return nil, trace.Wrap(err, "issuing certificate for app %s", appKey.GetName())
	}

	cert, err := result.KeyRing.AppTLSCert(appKey.GetName())
	if err != nil {
		return nil, trace.Wrap(err, "extracting app certificate from key ring")
	}

	signer, ok := cert.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, trace.BadParameter("app certificate private key of type %T is not a crypto.Signer", cert.PrivateKey)
	}
	s.mu.Lock()
	s.signers[appSignerKey{
		profile:     appKey.GetProfile(),
		leafCluster: appKey.GetLeafCluster(),
		name:        appKey.GetName(),
		port:        port,
	}] = signer
	s.mu.Unlock()

	return &cert, nil
}

// GetAppSigner implements [libvnet.EmbeddedApplicationService]. VNet calls
// GetAppCert first, so a miss here means the cert was evicted or never issued.
func (s *appService) GetAppSigner(_ context.Context, appKey *vnetv1.AppKey, port uint16) (crypto.Signer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	signer, ok := s.signers[appSignerKey{
		profile:     appKey.GetProfile(),
		leafCluster: appKey.GetLeafCluster(),
		name:        appKey.GetName(),
		port:        port,
	}]
	if !ok {
		return nil, trace.NotFound("no certificate has been issued for app %s", appKey.GetName())
	}
	return signer, nil
}

// GetDBCert implements [libvnet.EmbeddedApplicationService]. Database access
// over VNet is out of scope for this prototype.
func (s *appService) GetDBCert(context.Context, *vnetv1.DatabaseInfo) (*tls.Certificate, error) {
	return nil, trace.NotImplemented("database access is not supported by the Android prototype")
}

// GetDBSigner implements [libvnet.EmbeddedApplicationService].
func (s *appService) GetDBSigner(context.Context, *vnetv1.DatabaseKey) (crypto.Signer, error) {
	return nil, trace.NotImplemented("database access is not supported by the Android prototype")
}

func isDescendantSubdomain(fqdn, zone string) bool {
	return strings.HasSuffix(fqdn, "."+fullyQualify(zone))
}

func fullyQualify(domain string) string {
	if strings.HasSuffix(domain, ".") {
		return domain
	}
	return domain + "."
}

func hostname(hostPort string) string {
	if !strings.Contains(hostPort, ":") {
		return hostPort
	}
	host, _, err := net.SplitHostPort(hostPort)
	if err != nil {
		return hostPort
	}
	return host
}

var _ libvnet.EmbeddedApplicationService = (*appService)(nil)
