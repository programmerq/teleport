# Teleport VNet on Android

Research notes on what it would take to ship an Android app that provides VNet.
Everything here was checked against this tree; commands that were run are shown
so they can be re-run as the fork catches up to upstream.

## Summary

Neither of the two obvious framings — "port `tsh`" or "port Teleport Connect" —
is the right shape. Both `tsh` and Connect are *client applications* that drive a
VNet library; what an Android app needs is a third client application of the same
library, with a native UI. The precedent already exists in this repo:
`mobile/Verify` is an iOS app that consumes Teleport Go code through a
`gomobile`-generated framework.

The load-bearing discovery is that VNet already has a single-process embedding
API, [`vnet.EmbeddedVNet`][embedded], added for the tbot "beams" service. It
takes a caller-supplied TUN device and a host-configuration callback, and does
not fork a privileged helper. That is exactly the shape Android needs, because
`VpnService` hands an app a TUN descriptor with no elevation and expresses
routing and DNS through the same builder that produced it.

Rough sizing for the minimal scope asked about — auth plus a split-tunnel VPN
matching domain suffixes:

| Piece | Estimate | Notes |
| --- | --- | --- |
| Go: TUN descriptor adapter | done | in this branch, ~130 lines + tests |
| Go: host-config / nameserver bridge | done | in this branch, ~130 lines + tests |
| Go: `EmbeddedApplicationService` over a `tsh` profile | ~400 lines | model on `lib/tbot/services/beams` |
| Go: login façade (SSO + local) | ~300 lines | `lib/client` already has every seam |
| Go: gomobile façade types | ~200 lines | same constraints as `lib/mobile/verify/enroll` |
| Kotlin: `VpnService` + foreground service | ~400 lines | |
| Kotlin: UI (login, cluster list, status) | ~1500 lines | `mobile/Verify` is ~1.3k lines of Swift for comparison |
| Build wiring (`gomobile bind` → AAR → Gradle) | ~1 day | `gomobile` is already a tool in `go.mod` |

The unknowns that decide the schedule are Android's DNS behaviour and APK size,
not the VNet port itself. Both are discussed under [Risks](#risks).

[embedded]: ../lib/vnet/embedded.go

## What VNet actually is

[RFD 163](../rfd/0163-vnet.md) is the design doc; the implementation lives in
[`lib/vnet`](../lib/vnet) (13.2k non-test lines). Stripped to its mechanism:

1. Create a TUN interface and route a CGNAT range (`100.64.0.0/10` by default)
   and a randomly-generated IPv6 ULA prefix into it.
2. Run [gVisor's userspace netstack][netstack] over that interface, so TCP and
   UDP are terminated in-process rather than by the kernel.
3. Serve DNS on an address inside those ranges. When a query matches a Teleport
   proxy address or a `vnet_config` custom DNS zone, look the app up in the
   cluster, assign it a free IP from the range, and answer authoritatively.
   Everything else is forwarded to the host's real resolvers.
4. When a TCP connection arrives on an assigned IP, issue a client certificate
   for that app and proxy the connection to the cluster over an authenticated
   ALPN tunnel — the same thing `tsh proxy app` does, minus the manual setup.

The "matching domain suffixes" behaviour asked about is step 3, and it is
already entirely handled by [`fqdn_resolver.go`](../lib/vnet/fqdn_resolver.go)
and [`clusterconfigcache.go`](../lib/vnet/clusterconfigcache.go). Nothing about
it is platform-specific.

[netstack]: https://pkg.go.dev/gvisor.dev/gvisor/pkg/tcpip/stack

### The desktop process split, and why Android does not need it

On macOS, Linux and Windows, VNet runs as two processes:

- The **client application** (`tsh` or Connect) holds the user's credentials and
  implements [`vnet.ClientApplication`](../lib/vnet/user_process.go): list
  profiles, get cluster clients, reissue app certs.
- The **admin process** creates the TUN device, edits the routing table and
  reconfigures the system resolver. It talks back to the client application over
  gRPC on a unix socket, because it runs as root.

`RunUserProcess` wires the two together, and `runPlatformUserProcess` is the
per-OS seam that launches the privileged half — on Linux by starting the
`teleport-vnet` systemd unit over D-Bus
([`escalate_linux.go`](../lib/vnet/escalate_linux.go)).

None of that applies to Android. `VpnService` gives an ordinary app a TUN
descriptor after a one-time user consent dialog, and routing and DNS are
declared on `VpnService.Builder` rather than written to the system. There is
nothing to escalate to, and no privilege boundary that the gRPC hop is
protecting.

## How well the existing code travels

### `lib/vnet` compiles for Android unchanged

```
$ GOOS=android GOARCH=arm64 CGO_ENABLED=0 go build ./lib/vnet/...   # exit 0
$ GOOS=android GOARCH=arm64 CGO_ENABLED=0 go build ./lib/client/... # exit 0
```

These were run with cgo off, since there is no NDK in this environment;
`gomobile bind` compiles with cgo on, so the file selection is not identical and
a real AAR build is still the check that counts.

This is worth being precise about, because it is true and misleading at the same
time. Go treats `android` as satisfying the `linux` build constraint, and that
applies to filename suffixes as well as `//go:build` lines, so an Android build
selects every `*_linux.go` file:

```
$ GOOS=android GOARCH=arm64 go list -f '{{join .GoFiles "\n"}}' ./lib/vnet/
...
dbus_client_linux.go
escalate_linux.go
osconfig_linux.go
user_process_linux.go
...
```

So VNet *builds* for Android and would *fail at runtime*: `runPlatformUserProcess`
would try to open a unix socket in `XDG_RUNTIME_DIR` and start a systemd unit
over the system D-Bus, none of which exist. Nine `*_linux.go` files across
`lib/vnet` and `lib/vnet/dns` are in this category, plus the `systemdresolved`
and `polkit` helper packages. They do not need to be *ported* — they need to be
*excluded*, and replaced by a single in-process path.

`tool/tsh/common` is the only tree that fails outright, on one symbol:

```
# github.com/gravitational/teleport/session/shell
session/shell/shell.go:37:18: undefined: getLoginShell
```

That one is an artifact of how the check above was run rather than a real
portability problem: `session/shell/shell_unix.go` is a cgo file, so
`CGO_ENABLED=0` drops it and leaves `getLoginShell` undefined. `gomobile bind`
compiles with cgo enabled against the NDK, so it would likely resolve — though
`getpwnam_r` against Android's Bionic is its own question. Either way, see
[Do not port `tsh`](#do-not-port-tsh): this file should not be on the path.

### The embedding API already exists

[`vnet.EmbeddedVNet`](../lib/vnet/embedded.go) is a single-process VNet. Its
config is four fields:

```go
type EmbeddedVNetConfig struct {
	Device                   TUNDevice
	ApplicationService       EmbeddedApplicationService
	ConfigureHost            EmbeddedConfigureHostFunc
	UpstreamNameserverSource dns.UpstreamNameserverSource
}
```

Those map onto Android almost one-to-one:

| `EmbeddedVNet` needs | Android provides |
| --- | --- |
| `Device TUNDevice` | descriptor from `VpnService.Builder.establish()` |
| `ConfigureHost(cfg)` | `Builder.addAddress` / `addRoute` / `addDnsServer` |
| `UpstreamNameserverSource` | `ConnectivityManager` → `LinkProperties.getDnsServers()` |
| `ApplicationService` | Go-side, built on `lib/client` |

`EmbeddedVNetHostConfig` — the struct handed to `ConfigureHost` — is already
almost a description of a `VpnService.Builder`:

```go
type EmbeddedVNetHostConfig struct {
	DeviceIPv4 string
	DeviceIPv6 string
	CIDRRanges []string   // -> addRoute
	DNSAddrs   []string   // -> addDnsServer
	DNSZones   []string   // -> addSearchDomain
}
```

The reference implementation to copy is
[`lib/tbot/services/beams/vnet_service.go`](../lib/tbot/services/beams/vnet_service.go),
which runs `EmbeddedVNet` against a single bot identity, derives DNS zones from
`Ping` plus the cluster's `vnet_config`, and resolves FQDNs with a server-side
predicate on `spec.public_addr`. An Android app doing single-cluster app access
is the same shape with a user profile in place of the bot identity.

### `gomobile` is already wired up

`go.mod` declares `tool golang.org/x/mobile/cmd/gomobile`, and
[`mobile/Verify`](Verify/README.md) already builds `lib/mobile/verify/enroll`
into an XCFramework from an Xcode run-script phase. The Android equivalent is
`go tool gomobile bind -target=android -o app/libs/vnet.aar ./lib/mobile/vnet`
from a Gradle task.

`lib/mobile/verify/enroll` also documents the two `gomobile` constraints worth
knowing up front: only a narrow set of types crosses the JNI boundary (no
`[]string`, no `context.Context`), and field names must not start with an
acronym, to dodge [golang/go#32008](https://github.com/golang/go/issues/32008).

## Answering the question as asked

### Do not port `tsh`

`tsh` is a Kingpin CLI. Its VNet integration is
[`vnet_client_application.go`](../tool/tsh/common/vnet_client_application.go),
323 lines implementing `vnet.ClientApplication` on top of `client.Store` and
`client.TeleportClient`. That file is a very good *template* — most of it is
portable as-is — but the thing to reuse is `lib/client`, not `tool/tsh`. Pulling
in `tool/tsh/common` drags in the CLI framework, terminal handling, and
`session/shell`, for no benefit.

### Do not port Teleport Connect

Connect is an Electron app: `web/packages/teleterm` is ~83k lines of
TypeScript/TSX against `electron` 42, driving a Go daemon over gRPC. Electron
does not run on Android, so "porting Connect" means rewriting the entire UI
while keeping only the Go daemon — at which point it is not a port of Connect,
it is a new app that reuses the same Go libraries. The Go daemon
(`lib/teleterm`) is also more than an Android app needs: it exists to serve a
desktop UI with clusters, servers, kubes, databases and gateways.

### Do this instead

Follow the `mobile/Verify` precedent: a thin Go façade package bound with
`gomobile`, plus a native Kotlin UI.

```
Kotlin
  MainActivity / Compose UI ....... login, cluster status, zone list
  TeleportVpnService .............. VpnService.Builder, foreground service
    | JNI (gomobile AAR)
Go: lib/mobile/vnet
  Session ......................... lifecycle, owns the TUN descriptor
  Host bridge ..................... EmbeddedVNetHostConfig <-> Builder
  ApplicationService .............. FQDN resolution + cert issuance
    |
Go: lib/vnet (unmodified)
  EmbeddedVNet -> gVisor netstack -> ALPN tunnel to the proxy
Go: lib/client (unmodified)
  profile store, SSO ceremony, cert reissue
```

The app never implements VNet. It implements `VpnService` and a UI, and hands
the descriptor to Go.

### The one upstream change worth making

`EmbeddedVNet` requires the embedder to implement `ResolveFQDN` itself, which
means reimplementing multi-profile, leaf-cluster and custom-DNS-zone resolution
that `lib/vnet` already does behind the `ClientApplication` interface. Fine for
beams, which is deliberately single-cluster; a waste for a general client app.

The better long-term seam is an `android` implementation of
`runPlatformUserProcess` that runs the network stack in the same process instead
of forking. Mechanically that is:

- `//go:build !android` on the nine `*_linux.go` files listed above;
- a `user_process_android.go` that builds the network stack directly from
  `p.clientApplicationService`;
- a shim implementing `vnetv1.ClientApplicationServiceClient` by calling the
  server struct directly — 18 RPCs of mechanical delegation.
  [`embeddedApplicationServiceClient`](../lib/vnet/embedded.go) is the same
  pattern and can be copied.

That is perhaps 400 lines, and it makes the full `ClientApplication` surface —
multi-profile, leaf clusters, relogin, MFA — work on Android for free. Worth
doing on the second pass, once the first pass has proven the plumbing. It is
also the version worth proposing upstream, since it removes the "VNet compiles
for Android but cannot run" trap.

## Authentication

The minimal auth flow is not the hard part; `lib/client` already has the seams.

**Storage.** `client.NewFSClientStore(dir)` writes the usual `~/.tsh` layout to
any directory, so `context.getFilesDir()` works unchanged. The private key
should go in the Android Keystore rather than a file, but that is a follow-up —
`client.Store` takes a `WithHardwareKeyService` option that is the natural place
to hang it.

**SSO.** `sso.Ceremony.HandleRedirect` is `func(ctx, redirectURL) error`, and
`sso.Redirector` takes a configurable `BindAddr` for its loopback callback
listener. On Android that becomes: bind the listener on `127.0.0.1:0` in-process,
and open `redirectURL` in a Chrome Custom Tab from `HandleRedirect`. This is the
same seam Connect uses; the only unusable piece is `sso.OpenURLInBrowser`, which
shells out to `xdg-open`.

**Local login and MFA.** Username/password plus OTP works as-is. WebAuthn is the
interesting one: the desktop clients use `libfido2` through cgo, but the Android
build selects the non-cgo stubs, so passkeys would need to go through Android's
`CredentialManager` and be handed back to Go as an assertion. Scope it out of the
first version and require SSO or OTP.

## Risks

**DNS is the real one.** VNet's split-DNS story depends on the OS resolving only
specific suffixes through VNet — that is what `osconfig_darwin.go` configures on
macOS, and what `systemd-resolved` does on Linux. Android's `VpnService` has no
equivalent: `addDnsServer` is all-or-nothing for apps inside the tunnel, and
`addSearchDomain` sets search domains, not routing. So every DNS query on the
device would reach VNet's resolver, which forwards non-matching ones upstream.
Functionally that is fine — the forwarding path already exists and is what VNet
does for unmatched names on desktop — but it puts VNet on the critical path for
all device DNS, with an added latency hop and a new failure mode. Two things need
testing on a device before committing:

- whether Android's resolver honours a VPN's DNS servers when the VPN only
  installs split routes, which [has been inconsistent
  historically](https://issuetracker.google.com/issues/116257079);
- whether "Private DNS" (DNS-over-TLS, on by default since Android 9) bypasses
  the VPN resolver entirely, which would break name resolution for Teleport apps.

**Re-establishing the tunnel on config change.** VNet recomputes its desired host
configuration every 10 seconds and can add CIDR ranges as new clusters are logged
into. Android cannot add a route to a live interface: changing routes means
building a new `Builder` and calling `establish()` again, which returns a *new*
descriptor. So a config change is a session restart. The `Host.ConfigureNetwork`
callback in this branch is documented to be idempotent for exactly this reason —
the app must diff against what it last applied and only re-establish on a real
change. Pinning the IPv6 ULA prefix across restarts (it is randomly generated per
run) would avoid one class of churn.

**Socket protection.** With split routes only, VNet's own connections to the
proxy are not captured by the tunnel and `VpnService.protect()` is not strictly
required. But if the proxy address ever resolves into the VNet range, or if the
tunnel is widened, the result is a routing loop. Protecting the dialer is cheap
insurance and needs a `protect(fd)` callback across the JNI boundary; Go's
`net.Dialer.Control` is the hook.

**APK size.** A stripped `android/arm64` binary linking `lib/vnet` is 83 MB:

```
$ GOOS=android GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="-s -w" ...
83M  vnetonly
```

Adding `lib/client` takes it to 84 MB, which says the bulk is already pulled in
by `lib/vnet` itself — it depends on the full Teleport client, which depends on
`client-go`, the AWS SDK, `pgx` and so on. Compressed and split per-ABI this is
survivable, but it is far above a typical VPN client, and trimming it means
breaking `lib/vnet`'s dependency on the whole client library. Measure a real AAR
early rather than assuming.

**`gomobile` binding surface.** Every type crossing JNI must be one of the
handful `gomobile` supports. The façade in this branch already works within that
(newline-separated strings instead of `[]string`), but the login and cluster-list
APIs will need the same discipline.

## What is in this branch

[`lib/mobile/vnet`](../lib/mobile/vnet) — a compiling, tested proof of concept of
the Android-specific plumbing. It is not a working app; it is the parts that had
to be written to know whether the rest is worth doing.

- **`tun.go`** — adapts a raw TUN descriptor to `vnet.TUNDevice`. This exists
  because wireguard-go's `tun.CreateUnmonitoredTUNFromFD` *cannot* be used here,
  which was the one genuine surprise in this research: that constructor calls
  `Name()` (a `TUNGETIFF` ioctl) and `initFromFlags` (`TUNGETIFF`/`TUNSETIFF`
  plus a netlink socket), and an app does not own the interface `VpnService`
  created. This came up on the [WireGuard mailing
  list](https://lists.zx2c4.com/pipermail/wireguard/2021-March/006475.html) and
  is why Tailscale carries a wireguard-go fork. All VNet needs is packet I/O and
  a name for logging, so the adapter provides both with no ioctl at all.
- **`host.go`** — `Host`, the interface the Kotlin side implements, and the
  bridge from `EmbeddedVNetHostConfig` to it, plus the upstream-nameserver
  source.
- **`session.go`** — `Start`/`Stop`/`Wait` lifecycle over `EmbeddedVNet`.

Verification:

```
$ go test ./lib/mobile/vnet/                                   # ok
$ GOOS=android GOARCH=arm64 CGO_ENABLED=0 go build ./lib/mobile/...  # exit 0
```

The tests cover the packet path against a `SOCK_DGRAM` socketpair, which
preserves packet boundaries the same way an `IFF_NO_PI` TUN descriptor does:
read offsets, write offsets, close-unblocks-read, and idempotent close.

Deliberately not written: the `EmbeddedApplicationService` implementation and the
login façade. Both are substantial, both need a live cluster to validate, and
guessing at them without one would produce code that compiles and misleads. The
shape to follow for the first is `lib/tbot/services/beams/vnet_service.go`; for
the second it is `tool/tsh/common/vnet_client_application.go`.

## Suggested order of work

1. Stand up the Gradle + `gomobile bind` build and get an empty AAR loading in an
   app. Measure the APK.
2. Kotlin `VpnService` that establishes a tunnel with hardcoded routes and hands
   the descriptor to `lib/mobile/vnet`. Confirm packets arrive in Go.
3. Login façade: SSO via Custom Tabs into a `client.Store` under
   `getFilesDir()`. No VNet yet — just prove a profile can be written and used.
4. `EmbeddedApplicationService` over that profile, modelled on beams. End-to-end
   `curl` to a TCP app from a terminal app on the device.
5. Answer the DNS questions on real devices across Android 10–15.
6. Then decide whether to invest in the `runPlatformUserProcess` route for
   multi-profile and leaf-cluster support.

Steps 1–4 are the minimal auth-plus-suffix-matching VPN asked about. Step 5 is
what decides whether this is a product or a demo.

## Update: the prototype

The research above led to a working prototype, in this same branch. What changed
relative to the plan:

- **Login goes through the browser, both ways.** `LoginHeadless` uses Teleport's
  headless authentication: it opens `https://<proxy>/web/headless/<id>` in a
  Chrome Custom Tab, where the user approves with whatever credential the
  browser already has, including a hardware security key or a platform passkey.
  `client.SSHAgentHeadlessLogin` and `services.NewHeadlessAuthenticationID` are
  both exported, so this needs no upstream change and no WebAuthn support in the
  app. It also works whether the cluster uses local or SSO authentication, which
  makes it a better default on Android than SSO.
- **Username and password login is not implementable.** `TeleportClient.AskPassword`
  refuses to run unless stdin is a terminal, so there is no way in from an app.
- **SSO login needs one hack.** `lib/client` builds its SSO redirector inside
  `TeleportClient.Login` and reports the URL to open by printing it to a writer
  captured from `os.Stderr`. The prototype swaps `os.Stderr` for a pipe and
  scans it. A `HandleRedirect` hook on `client.Config` would remove this, and is
  the smallest upstream change worth making.
- **The tunnel is planned before it is established.** Android will not let an
  app change a live interface, so the desktop pattern - create the TUN, then
  configure routes as clusters are discovered - does not work. VNet's IPv4
  addresses turn out to be derived deterministically from the cluster's CIDR
  range, so `Client.PlanNetwork` asks the cluster for that range up front and
  the app gets `VpnService.Builder` right on the first `establish()`.
  `Host.ConfigureNetwork` is then a logging checkpoint, not an action.
- **IPv6 is left out.** VNet generates a fresh random ULA prefix per run, so
  routing it would require establish → read prefix → re-establish → restart
  VNet → new prefix, which never converges. Letting the embedder supply the
  prefix would fix it.
- **The TUN adapter was needed, as predicted, and is now tested against the real
  kernel driver.** `TestTUNDeviceAgainstKernelTUN` allocates a TUN interface
  with `TUNSETIFF`, hands the raw descriptor to the adapter the way
  `ParcelFileDescriptor.detachFd()` does, brings the interface up, and checks a
  UDP packet sent to it arrives intact through `Read` - with no ioctl issued by
  the adapter itself.
- **Size, measured for real.** The AAR is 52 MB for arm64 and x86_64 together
  with `-ldflags="-s -w"`, and 100 MB without. The arm64 APK is 98 MB, of which
  96 MB is `libgojni.so` stored uncompressed. That is close to the 83 MB
  predicted above and confirms that trimming means breaking `lib/vnet`'s
  dependency on the whole Teleport client.

What is still unanswered is what it always was: how Android's resolver behaves
with a split-route tunnel, and whether Private DNS bypasses it. Those need a
device.

See [mobile/android/README.md](android/README.md) for building, installing and
what to watch in logcat.
