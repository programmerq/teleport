# Teleport VNet for Android — prototype

A minimal Android app that runs [Teleport VNet](../android-vnet.md) over
`VpnService`. Log in to a cluster, turn the tunnel on, and TCP applications
resolve and connect by their public address from any app on the device.

This is a prototype, not a product. See [Scope](#scope) for what it does and
does not do.

## Architecture

```
Kotlin
  MainActivity ................. login, connect, list apps
  TeleportVpnService ........... VpnService.Builder, foreground service
    | JNI (gomobile AAR)
Go: lib/mobile/vnet
  Client ....................... login flows, profile store, VNet lifecycle
  appService ................... FQDN resolution + app certificate issuance
  tunDeviceFromFD .............. VpnService descriptor -> vnet.TUNDevice
Go: lib/vnet (unmodified)
  EmbeddedVNet -> gVisor netstack -> ALPN tunnel to the proxy
```

The app never implements VNet. It owns the `VpnService`, hands Go the TUN
descriptor, and displays state.

Unlike the desktop clients, there is no privileged helper process: `VpnService`
gives an ordinary app a TUN descriptor after one consent dialog, so the whole
thing runs in one process on top of `vnet.EmbeddedVNet`.

## Building

Requires the Android SDK with NDK, and Go with `gomobile`.

```shell
# 1. Build the Go library into an AAR. Takes a few minutes the first time.
export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/<version>"
go install golang.org/x/mobile/cmd/gobind@latest   # gomobile shells out to it

cd <teleport>
go tool gomobile bind \
  -target=android/arm64,android/amd64 \
  -androidapi 26 \
  -ldflags="-s -w" \
  -javapkg com.goteleport.vnet \
  -o mobile/android/app/libs/vnet.aar \
  ./lib/mobile/vnet

# 2. Build the APK.
cd mobile/android
echo "sdk.dir=$ANDROID_HOME" > local.properties
gradle :app:assembleDebug
```

APKs land in `app/build/outputs/apk/debug/`:

| File | Use |
| --- | --- |
| `app-arm64-v8a-debug.apk` | phones and tablets |
| `app-x86_64-debug.apk` | emulators |
| `app-universal-debug.apk` | both, roughly twice the size |

`app/libs/vnet.aar` is a build artifact and is not committed.

`-ldflags="-s -w"` matters: without it the Go shared library is over 130 MB per
ABI and Gradle cannot strip it, because it is not a standard NDK build product.

Or just run [`build.sh`](build.sh), which does both steps and prints where the
APKs landed.

## Building against v18

This tree is `master` (19.0.0-prealpha), but the prototype builds against
`branch/v18` with a single change, in `lib/mobile/vnet/appservice.go`. v18 keys
apps in the key ring by scope-qualified name:

```go
routeToApp := libvnet.RouteToApp(appInfo, port)
// ... IssueUserCertsWithMFA with RouteToApp: *routeToApp ...

// v18: apps are keyed by scope-qualified name.
cert, err := result.KeyRing.AppTLSCert(scopes.QualifiedName{
    Name:  routeToApp.Name,
    Scope: routeToApp.Scope,
})

// master: a bare name.
cert, err := result.KeyRing.AppTLSCert(appKey.GetName())
```

with `"github.com/gravitational/teleport/lib/scopes"` added to the imports.
Everything else compiles unchanged: `vnet.EmbeddedVNet` and its whole config
surface, the protobuf builders, `client.SSHAgentHeadlessLogin`,
`services.NewHeadlessAuthenticationID` and `vnet.RouteToApp` are all present in
18.10.

v18 does not declare `gomobile` as a tool in `go.mod`, so run
`go get -tool golang.org/x/mobile/cmd/gobind` in the v18 tree first.

**Match the build to your cluster.** A v19-prealpha client against a v18 cluster
is not a combination anyone tests.

## Installing

```shell
adb install -r app/build/outputs/apk/debug/app-arm64-v8a-debug.apk
```

The app is signed with the standard Android debug key, so it sideloads without
any key management. It is not suitable for distribution.

## Using it

1. Enter your proxy address, e.g. `teleport.example.com:443`.
2. **Check cluster** confirms the proxy is reachable and reports which login
   methods it offers.
3. Enter your Teleport username and tap **Log in (headless)**, or tap
   **Log in (SSO)** if the cluster has an SSO connector.
4. **Connect**. Android asks for VPN permission the first time.
5. **List TCP apps** shows the names the tunnel will answer for.

### Why login happens in Chrome

Both login flows hand a URL to a Chrome Custom Tab and wait. Chrome runs the
whole authentication ceremony, so a hardware security key over USB-C or NFC and
a platform passkey both work exactly as they do when signing in to the web UI —
the app itself needs no WebAuthn support.

Headless login is usually the better choice: it works whether the cluster uses
local or SSO authentication, and it binds the browser approval to the exact key
pair being signed. It needs headless authentication enabled on the cluster,
which **Check cluster** reports.

Username and password login is not implemented. `lib/client` reads the password
from a terminal, and an app does not have one.

## Watching what it does

```shell
adb logcat -s TeleportVNet
```

Every Go log line is bridged to that tag, including `lib/vnet`'s own DNS and
connection logs. The **Debug logging** checkbox switches Go's log level between
debug and info; leave it on when reporting a problem.

Useful things to look for:

| Log line | Meaning |
| --- | --- |
| `Tunnel plan: address=… routes=… dns=…` | what the app is about to give `VpnService.Builder` |
| `Tunnel established, handing fd N to VNet` | `establish()` succeeded |
| `Resolved FQDN to TCP app` | VNet matched a DNS query to an app |
| `FQDN is not under any VNet DNS zone` | query forwarded upstream, as intended |
| `Issuing app certificate` | a connection is being set up |
| `Upstream nameservers: […]` | the device resolvers VNet forwards to |

## Scope

Implemented:

- Headless and SSO login, both through the browser
- One root cluster, one profile at a time
- TCP application access by public address, including custom DNS zones from the
  cluster's `vnet_config`
- Forwarding of non-Teleport DNS queries to the device's real resolvers

Not implemented:

- Databases, SSH, leaf clusters, several profiles at once. Reaching those means
  implementing `vnet.ClientApplication` rather than
  `vnet.EmbeddedApplicationService`; see [the research notes](../android-vnet.md).
- HTTP applications. They need the HTTPS-in-mTLS tunnel, which a browser on the
  device has no way to trust.
- Hardware-backed key storage. The Teleport private key is a file in the app's
  private directory, not an Android Keystore key.
- Re-establishing the tunnel when the cluster's configuration changes. See
  below.
- Per-session MFA. If a role requires MFA for each app connection, issuing the
  certificate needs a WebAuthn ceremony the app cannot perform, and the
  connection fails. Logging in works; connecting to that app does not.
- Re-login when certificates expire. The cluster connection is established once
  and kept; once the certificate expires, connections start failing and you have
  to log in again by hand.

### IPv4 only, and why

`VpnService` will not let an app change a live interface: new routes mean a new
`Builder` and another `establish()`, which returns a new descriptor and so
requires restarting VNet.

VNet's IPv4 addresses are derived deterministically from the cluster's CIDR
range — the TUN address is the first address in the range, the DNS server the
second — so the app asks Go for them with `planNetwork()` before establishing,
and gets the tunnel right on the first attempt.

Its IPv6 addresses are not: VNet generates a fresh random ULA prefix on every
run. Routing it would mean establishing, reading the prefix, re-establishing,
and restarting VNet — which would generate a different prefix, and never
converge. So the tunnel carries no IPv6, and `Host.configureNetwork` is a
logging checkpoint rather than an action.

VNet still answers AAAA queries with a ULA address that the device cannot route.
In practice clients fall back to IPv4, but this is the most likely source of
odd behaviour and the first thing to check if a connection stalls. Fixing it
properly means letting the embedder supply the IPv6 prefix.

### DNS goes through VNet for everything

Android has no per-suffix DNS routing. Once the tunnel sets a DNS server, every
query on the device reaches VNet's resolver, which answers for Teleport names
and forwards the rest to the device's real resolvers. That works, but it puts
VNet on the critical path for all DNS while the tunnel is up.

### Private DNS has to be Off or Automatic

Android's Private DNS setting is device-wide; there is no per-zone
configuration, and a VPN app cannot scope it.

- **Off** or **Automatic** — fine. In automatic mode the resolver probes the
  tunnel's DNS server on port 853, gets nothing, and falls back to cleartext on
  53, which is what VNet serves.
- **Private DNS provider hostname** (strict mode) — breaks it. Every query goes
  to that DoT resolver instead of the tunnel's, so Teleport names never reach
  VNet. This is the first thing to check if nothing resolves.

Google's own documentation notes that on Android 9 a VPN's DNS overrode Private
DNS entirely, and that this
[changed in Android 10](https://developers.google.com/speed/public-dns/docs/using#android),
so behaviour differs by version and is worth confirming on the device you test
on.

Also still worth watching: whether Android honours the tunnel's DNS server at
all when the tunnel only installs split routes, which has been
[inconsistent historically](https://issuetracker.google.com/issues/116257079).

### Making VNet answer for your own zone

Setting up DoT or DoH for a zone does not help here — Android cannot be told to
route one suffix differently. What makes VNet answer for a name is the cluster's
`vnet_config`:

```yaml
kind: vnet_config
version: v1
metadata:
  name: vnet-config
spec:
  # Defaults to 100.64.0.0/10. The tunnel routes exactly this range.
  ipv4_cidr_range: "100.64.0.0/10"
  # Only needed if your apps use a public_addr that is not under the proxy
  # address. Apps at <app>.<proxy-address> work with no config at all.
  custom_dns_zones:
    - suffix: internal.example.com
```

Apply it with `tctl create -f vnet_config.yaml`. The app reads it at connect
time and passes each suffix to `VpnService.Builder.addSearchDomain`; **List TCP
apps** shows which names will resolve.
