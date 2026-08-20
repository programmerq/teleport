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
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gravitational/trace"

	"github.com/gravitational/teleport"
	apiclient "github.com/gravitational/teleport/api/client"
	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/client/webclient"
	"github.com/gravitational/teleport/api/constants"
	"github.com/gravitational/teleport/api/types"
	apiutils "github.com/gravitational/teleport/api/utils"
	"github.com/gravitational/teleport/lib/auth/authclient"
	"github.com/gravitational/teleport/lib/client"
	"github.com/gravitational/teleport/lib/services"
)

// BrowserOpener is implemented by the Android app to show a URL to the user,
// normally in a Chrome Custom Tab. Login flows that authenticate in a browser
// call it with the URL to open, then block until the browser reports back to
// the cluster.
type BrowserOpener interface {
	OpenURL(url string) error
}

// Client is the top-level handle the Android app holds. It owns the Teleport
// profile store and, once a VNet session is started, the running VNet.
type Client struct {
	homeDir string
	store   *client.Store
	logger  *slog.Logger

	mu       sync.Mutex
	insecure bool
	session  *Session
	profile  *profileClient
}

// NewClient returns a Client storing profiles under homeDir, which should be
// the app's private directory (Context.getFilesDir()).
func NewClient(homeDir string) *Client {
	return &Client{
		homeDir: homeDir,
		store:   client.NewFSClientStore(homeDir),
		logger:  slog.Default().With("component", "mobile-vnet"),
	}
}

// SetInsecure disables TLS verification against the Teleport proxy. It exists
// for testing against clusters with self-signed certificates and must not be
// used otherwise.
func (c *Client) SetInsecure(insecure bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.insecure = insecure
}

// ClusterInfo describes what a proxy supports, so the app can offer the login
// methods that will actually work. Newline-separated lists are used because
// gomobile cannot bind slices of strings.
type ClusterInfo struct {
	// ProxyAddr is the proxy's web address.
	ProxyAddr string
	// ClusterName is the cluster's name.
	ClusterName string
	// AuthType is the cluster's default authentication type, e.g. "local",
	// "github", "saml" or "oidc".
	AuthType string
	// SecondFactor describes the cluster's second factor requirement.
	SecondFactor string
	// LocalAuthEnabled reports whether username and password login is allowed.
	LocalAuthEnabled bool
	// HeadlessAllowed reports whether headless login is allowed. Headless is
	// the most useful flow on Android, because the whole authentication
	// ceremony, including a security key, happens in the browser.
	HeadlessAllowed bool
	// Connectors lists the SSO connectors, one "id|display name|type" per line.
	Connectors string
}

// PingProxy contacts a Teleport proxy and reports what it supports. It does not
// require credentials.
func (c *Client) PingProxy(proxyAddr string) (*ClusterInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	c.mu.Lock()
	insecure := c.insecure
	c.mu.Unlock()

	pong, err := webclient.Ping(&webclient.Config{
		Context:   ctx,
		ProxyAddr: proxyAddr,
		Insecure:  insecure,
	})
	if err != nil {
		return nil, trace.Wrap(err, "pinging proxy %s", proxyAddr)
	}

	info := &ClusterInfo{
		ProxyAddr:        pong.Proxy.SSH.PublicAddr,
		ClusterName:      pong.ClusterName,
		AuthType:         pong.Auth.Type,
		SecondFactor:     string(pong.Auth.SecondFactor),
		LocalAuthEnabled: pong.Auth.Local != nil,
		HeadlessAllowed:  pong.Auth.AllowHeadless,
	}
	if info.ProxyAddr == "" {
		info.ProxyAddr = proxyAddr
	}

	// The ping response only advertises the cluster's default connector of each
	// kind, which is all the app needs to offer a "log in with SSO" button.
	var connectors []string
	if oidc := pong.Auth.OIDC; oidc != nil {
		connectors = append(connectors, connectorLine(oidc.Name, oidc.Display, constants.OIDC))
	}
	if saml := pong.Auth.SAML; saml != nil {
		connectors = append(connectors, connectorLine(saml.Name, saml.Display, constants.SAML))
	}
	if github := pong.Auth.Github; github != nil {
		connectors = append(connectors, connectorLine(github.Name, github.Display, constants.Github))
	}
	info.Connectors = strings.Join(connectors, "\n")
	return info, nil
}

func connectorLine(name, display, kind string) string {
	if display == "" {
		display = name
	}
	return strings.Join([]string{name, display, kind}, "|")
}

// newTeleportClient builds a client for a proxy that has not been logged in to
// yet.
func (c *Client) newTeleportClient(proxyAddr, username string) (*client.TeleportClient, error) {
	c.mu.Lock()
	insecure := c.insecure
	c.mu.Unlock()

	cfg := &client.Config{
		WebProxyAddr:       proxyAddr,
		SSHProxyAddr:       proxyAddr,
		Username:           username,
		ClientStore:        c.store,
		InsecureSkipVerify: insecure,
		// The app has no terminal, so nothing may try to read a prompt.
		AllowStdinHijack: false,
		// BrowserNone stops lib/client from shelling out to xdg-open, which
		// does not exist on Android. Flows that need a browser open it through
		// a BrowserOpener instead.
		Browser: teleport.BrowserNone,
	}
	if err := cfg.ParseProxyHost(proxyAddr); err != nil {
		return nil, trace.Wrap(err, "parsing proxy address %s", proxyAddr)
	}
	tc, err := client.NewClient(cfg)
	if err != nil {
		return nil, trace.Wrap(err, "creating Teleport client")
	}
	return tc, nil
}

// LoginHeadless logs in using Teleport's headless authentication flow. It opens
// the cluster's headless approval page in the browser, where the user completes
// the whole ceremony, including a hardware security key or a platform passkey,
// using the credentials the browser already has.
//
// This is the recommended flow on Android: no WebAuthn support is needed in the
// app itself, and it works whether the cluster uses local or SSO auth. The
// cluster must have headless authentication enabled.
//
// It returns the name of the stored profile.
func (c *Client) LoginHeadless(proxyAddr, username string, browser BrowserOpener) (string, error) {
	if username == "" {
		return "", trace.BadParameter("a username is required for headless login")
	}
	if browser == nil {
		return "", trace.BadParameter("a browser opener is required for headless login")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	tc, err := c.newTeleportClient(proxyAddr, username)
	if err != nil {
		return "", trace.Wrap(err)
	}

	loginFn := func(ctx context.Context, keyRing *client.KeyRing) (*authclient.CLILoginResponse, error) {
		// The approval page is addressed by a digest of the public key being
		// signed, which binds the browser approval to this exact key pair.
		id := services.NewHeadlessAuthenticationID(keyRing.SSHPrivateKey.MarshalSSHPublicKey())
		approvalURL, err := url.JoinPath("https://"+tc.WebProxyAddr, "web", "headless", id)
		if err != nil {
			return nil, trace.Wrap(err, "building headless approval URL")
		}

		sshLogin, err := tc.NewSSHLogin(keyRing)
		if err != nil {
			return nil, trace.Wrap(err)
		}

		c.logger.InfoContext(ctx, "Opening headless approval page", "url", approvalURL)
		if err := browser.OpenURL(approvalURL); err != nil {
			return nil, trace.Wrap(err, "opening headless approval page")
		}

		response, err := client.SSHAgentHeadlessLogin(ctx, client.SSHLoginHeadless{
			SSHLogin:                 sshLogin,
			User:                     username,
			HeadlessAuthenticationID: id,
		})
		return response, trace.Wrap(err, "waiting for headless approval")
	}

	return c.finishLogin(ctx, tc, loginFn)
}

// LoginSSO logs in through an SSO connector, opening the identity provider in
// the browser. connectorID may be empty to use the cluster's default connector.
//
// It returns the name of the stored profile.
func (c *Client) LoginSSO(proxyAddr, connectorID string, browser BrowserOpener) (string, error) {
	if browser == nil {
		return "", trace.BadParameter("a browser opener is required for SSO login")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	info, err := c.PingProxy(proxyAddr)
	if err != nil {
		return "", trace.Wrap(err)
	}
	connectorType := info.AuthType
	if connectorID == "" {
		connectorID = info.AuthType
	}
	for _, line := range strings.Split(info.Connectors, "\n") {
		parts := strings.Split(line, "|")
		if len(parts) == 3 && parts[0] == connectorID {
			connectorType = parts[2]
		}
	}
	if connectorType == constants.Local {
		return "", trace.BadParameter("cluster %s has no SSO connector configured", proxyAddr)
	}

	tc, err := c.newTeleportClient(proxyAddr, "")
	if err != nil {
		return "", trace.Wrap(err)
	}
	tc.AuthConnector = connectorID

	// lib/client builds the SSO redirector internally and only reports the URL
	// to open by writing it to a writer captured from os.Stderr at construction
	// time. Swapping os.Stderr for a pipe is the only way to intercept it
	// without changing lib/client. Doing that properly - a HandleRedirect hook
	// on client.Config - is the small upstream change this flow wants; see
	// mobile/android-vnet.md.
	restore, urls := captureStderrURLs()
	defer restore()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for redirectURL := range urls {
			c.logger.InfoContext(ctx, "Opening SSO login page", "url", redirectURL)
			if err := browser.OpenURL(redirectURL); err != nil {
				c.logger.ErrorContext(ctx, "Failed to open SSO login page", "error", err)
			}
		}
	}()

	profileName, err := c.finishLogin(ctx, tc, tc.SSOLoginFn(connectorID, connectorID, connectorType))
	restore()
	<-done
	return profileName, trace.Wrap(err)
}

// finishLogin runs the login function and persists the resulting profile.
func (c *Client) finishLogin(ctx context.Context, tc *client.TeleportClient, loginFn client.SSHLoginFunc) (string, error) {
	keyRing, err := tc.SSHLogin(ctx, loginFn)
	if err != nil {
		return "", trace.Wrap(err, "logging in to %s", tc.WebProxyAddr)
	}

	// ConnectToRootCluster stores the key ring in the profile directory as a
	// side effect, which is what makes the profile usable afterwards.
	clusterClient, rootAuthClient, err := tc.ConnectToRootCluster(ctx, keyRing)
	if err != nil {
		return "", trace.Wrap(err, "connecting to root cluster after login")
	}
	defer func() {
		_ = rootAuthClient.Close()
		_ = clusterClient.Close()
	}()

	if err := tc.SaveProfile(true); err != nil {
		return "", trace.Wrap(err, "saving profile")
	}

	profileName := tc.WebProxyHost()
	c.logger.InfoContext(ctx, "Login complete", "profile", profileName, "user", tc.Username)
	return profileName, nil
}

// CurrentProfile returns the name of the most recently used profile, or an
// empty string if the user has never logged in.
func (c *Client) CurrentProfile() string {
	name, err := c.store.CurrentProfile()
	if err != nil {
		return ""
	}
	return name
}

// ProfileStatusText returns a human-readable summary of a profile for the app
// to display: user, cluster, roles and certificate expiry.
func (c *Client) ProfileStatusText(profileName string) (string, error) {
	status, err := c.store.ReadProfileStatus(profileName)
	if err != nil {
		return "", trace.Wrap(err, "reading profile %s", profileName)
	}
	expiry := "expired"
	if remaining := time.Until(status.ValidUntil); remaining > 0 {
		expiry = fmt.Sprintf("valid for %s", remaining.Round(time.Minute))
	}
	return fmt.Sprintf("user: %s\ncluster: %s\nroles: %s\ncertificate: %s",
		status.Username,
		status.Cluster,
		strings.Join(status.Roles, ", "),
		expiry,
	), nil
}

// Logout removes the stored credentials for a profile.
func (c *Client) Logout(profileName string) error {
	c.StopVNet()
	tc, err := c.newTeleportClient(profileName, "")
	if err != nil {
		return trace.Wrap(err)
	}
	if err := tc.Logout(); err != nil && !trace.IsNotFound(err) {
		return trace.Wrap(err, "logging out of %s", profileName)
	}
	return nil
}

// ListTCPApps returns the TCP applications visible to the user, one
// "name<tab>public address" per line, so the app can show the user which names
// VNet will answer for.
func (c *Client) ListTCPApps(profileName string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	c.mu.Lock()
	insecure := c.insecure
	c.mu.Unlock()

	profile := newProfileClient(c.store, profileName, insecure)
	defer profile.close()

	clusterClient, err := profile.clusterClient(ctx)
	if err != nil {
		return "", trace.Wrap(err)
	}

	var lines []string
	req := &proto.ListResourcesRequest{
		ResourceType: types.KindAppServer,
		Limit:        100,
	}
	for {
		page, err := apiclient.GetResourcePage[types.AppServer](ctx, clusterClient.CurrentCluster(), req)
		if err != nil {
			return "", trace.Wrap(err, "listing application servers")
		}
		for _, appServer := range page.Resources {
			app := appServer.GetApp()
			if !app.IsTCP() {
				continue
			}
			addr := app.GetPublicAddr()
			if addr == "" {
				continue
			}
			lines = append(lines, app.GetName()+"\t"+addr)
		}
		if page.NextKey == "" {
			break
		}
		req.StartKey = page.NextKey
	}

	lines = apiutils.Deduplicate(lines)
	return strings.Join(lines, "\n"), nil
}

// StartVNet runs VNet for the given profile over the TUN file descriptor from
// VpnService.Builder.establish(). The Client takes ownership of tunFD and
// closes it when the session stops.
func (c *Client) StartVNet(profileName string, tunFD int, host Host) (*Session, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.session != nil {
		return nil, trace.AlreadyExists("a VNet session is already running")
	}

	profile := newProfileClient(c.store, profileName, c.insecure)
	appSvc, err := newAppService(profile, c.logger)
	if err != nil {
		profile.close()
		return nil, trace.Wrap(err)
	}

	session, err := startSession(sessionConfig{
		tunFD:              tunFD,
		host:               host,
		applicationService: appSvc,
		logger:             c.logger,
	})
	if err != nil {
		profile.close()
		return nil, trace.Wrap(err)
	}

	c.session = session
	c.profile = profile
	return session, nil
}

// StopVNet stops any running VNet session. It is safe to call when nothing is
// running.
func (c *Client) StopVNet() {
	c.mu.Lock()
	session, profile := c.session, c.profile
	c.session, c.profile = nil, nil
	c.mu.Unlock()

	if session != nil {
		session.Stop()
	}
	if profile != nil {
		profile.close()
	}
}

// VNetRunning reports whether a VNet session is currently running.
func (c *Client) VNetRunning() bool {
	c.mu.Lock()
	session := c.session
	c.mu.Unlock()
	return session != nil && session.IsRunning()
}

// PlanNetwork returns the tunnel configuration VNet will ask for, before VNet
// is started, so the app can call VpnService.Builder.establish() once and not
// have to tear the tunnel down and rebuild it.
//
// This is possible because VNet derives its IPv4 addresses deterministically
// from the cluster's configured CIDR range: the TUN address is the first
// address in the range and the DNS server is the second. It contacts the
// cluster to read that range and the DNS zones, so it requires a valid profile.
//
// The returned configuration is IPv4 only. VNet also serves DNS over an IPv6
// ULA address, but it generates a fresh random ULA prefix on every run, so an
// Android app cannot route it without re-establishing the tunnel and thereby
// restarting VNet, which would generate another prefix. See the IPv6 note in
// mobile/android-vnet.md.
func (c *Client) PlanNetwork(profileName string) (*NetworkConfig, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	c.mu.Lock()
	insecure := c.insecure
	c.mu.Unlock()

	profile := newProfileClient(c.store, profileName, insecure)
	defer profile.close()

	appSvc, err := newAppService(profile, c.logger)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	clusterCfg, err := appSvc.clusterConfig(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	tunIP, ipNet, dnsIP, err := ipsForCIDR(clusterCfg.ipv4CIDRRange)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	prefixLen, _ := ipNet.Mask.Size()

	return &NetworkConfig{
		AddressIPv4:   tunIP.String(),
		PrefixIPv4:    prefixLen,
		Routes:        clusterCfg.ipv4CIDRRange,
		Nameservers:   dnsIP.String(),
		SearchDomains: strings.Join(clusterCfg.dnsZones, "\n"),
	}, nil
}

// ipsForCIDR mirrors the unexported derivation in lib/vnet: the TUN address is
// the first address in the range and the DNS server is the second.
func ipsForCIDR(cidrRange string) (tunIP net.IP, ipNet *net.IPNet, dnsIP net.IP, err error) {
	_, ipNet, err = net.ParseCIDR(cidrRange)
	if err != nil {
		return nil, nil, nil, trace.Wrap(err, "parsing CIDR range %q", cidrRange)
	}
	tunIP = append(net.IP(nil), ipNet.IP...)
	tunIP[len(tunIP)-1]++
	dnsIP = append(net.IP(nil), tunIP...)
	dnsIP[len(dnsIP)-1]++
	return tunIP, ipNet, dnsIP, nil
}
