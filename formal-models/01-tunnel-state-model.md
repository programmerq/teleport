# Teleport Agent Tunnel Mode — End-to-End State Model

**Source**: `gravitational/teleport` @ `master` commit `67276143` (2026-07-10), version `19.0.0-prealpha.2`.
All citations are `file:line` in that tree. Line numbers drift with development; symbol names are given so citations remain findable.

**Scope**: one Teleport Proxy replica, one agent replica, agent connected in *tunnel mode* (reverse tunnel).
Agent types considered: `ssh` (node), `db`, `app`, `kube`, `windows_desktop`. **Out of scope**: proxy peering, vnet, trusted/leaf clusters (the code paths exist in the same package — noted where relevant — but are not modeled).

**Naming note**: the package `lib/reversetunnel` was refactored; what older docs call `localsite.go`/`remotesite.go` are now `lib/reversetunnel/local_cluster.go` (`localCluster`) and `lib/reversetunnel/leaf_cluster.go` (`leafCluster`).

---

## 1. Layer map

A `tsh db connect` session crosses seven layers. Each box is a separately-failing component with its own detection timers:

```
 [L0] psql/mysql client            (user's machine)
   │  plaintext TCP to 127.0.0.1:<random>
 [L1] tsh LocalProxy               lib/srv/alpnproxy/local_proxy.go
   │  TLS + ALPN "teleport-postgres" etc. → proxy web port
 [L2] Proxy ALPN router            lib/srv/alpnproxy/proxy.go
   │  in-process handoff
 [L3] Proxy db.ProxyServer         lib/srv/db/proxyserver.go  (authorize, pick db_service, mint cert)
   │  reversetunnel dial
 [L4] Reverse tunnel               lib/reversetunnel/local_cluster.go (proxy end)
   │  SSH channel "teleport-transport" over the agent-dialed SSH conn
 [L5] Agent tunnel endpoint        lib/reversetunnel/agent.go, agentpool.go (agent end)
   │  in-process handoff: p.Server.HandleConnection(conn)
 [L6] db_service engine            lib/srv/db/server.go (TLS re-handshake, engine)
   │  TCP (+TLS) to the real database
 [L7] Database
```

For **ssh** the client layers differ (tsh dials the proxy SSHTunnel/web port directly, optional resumption wraps the stream end-to-end tsh↔node); for **app** the client is a browser hitting the proxy web UI (`lib/web/app/transport.go:451` dials the tunnel); for **kube** it's kubectl with SNI routing (`lib/kube/proxy/transport.go:251` dials). The tunnel layers L4–L5 are identical for all types.

### Type-divergent behaviors (the 4 parameters of the model)

| # | Behavior | ssh (node) | db | app/okta | kube/desktop |
|---|---|---|---|---|---|
| 1 | Direct-dial fallback when tunnel missing | yes (`local_cluster.go:566` `skipDirectDial` false for nodes with addr) | **never** (`:571`) | **never** (`:571`) | addr is `LocalKubernetes`/`LocalWindowsDesktop` sentinel → tunnel-only |
| 2 | Protocol-native error frames to client | SSH stderr/banner via forwarding server | postgres/mysql/sqlserver: yes (`postgres/proxy.go:69`, `mysql/proxy.go:88`); mongo/redis/etc.: **bare close** | HTTP 5xx from web handler | kubectl gets apiserver-style error or bare close |
| 3 | Agent-side handoff | `Server.HandleConnection` direct | direct | direct | via `ServerHandlerToListener` adapter (`agentpool.go:980-1018`) |
| 4 | Resumption layer | **yes** (`lib/resumption`, node side only) | no | no | no |

---

## 2. Tunnel establishment — the agent state machine

The agent is the **SSH client**; the proxy is the **SSH server** (`lib/reversetunnel/srv.go:326`). Each `agent` object is one SSH connection to the proxy.

### States (`lib/reversetunnel/agent.go:50-62`)

```
AgentInitial ("initial") → AgentConnecting ("connecting") → AgentConnected ("connected") → AgentClosed ("closed")
```

Transition validity is enforced by `updateState` (`agent.go:285-327`): no transition out of Closed, no self-transitions, nothing returns to Initial, Connecting only from Initial, Connected only from Connecting. There is **no explicit draining state** — draining is a phase inside the transition to Closed, implemented with a separate `drainCtx` (`agent.go:204-210`).

### Transitions

| From → To | Trigger | Code |
|---|---|---|
| Initial → Connecting | `agent.Start()` | `agent.go:344` |
| (within Connecting) | dial proxy (`sshDialer.DialContext`), claim proxy lease, register `teleport-discovery` + `teleport-transport` channel handlers, open `teleport-heartbeat` channel, send first ping | `agent.go:407-444`, `:455-472` |
| Connecting → Connected | 4 worker goroutines launched (global requests, drain channels, channels, keepalives) | `agent.go:358-398` |
| any → Closed | `Stop()`: mark Closed → cancel drainCtx (reject new transports) → release lease → wait in-flight transports (`drainWG`) → cancel main ctx → close SSH client | `agent.go:475-499` |

**Things that call `Stop()`** (i.e., every reason a healthy tunnel dies from the agent's own perspective):
- any worker goroutine exiting, which happens on any conn error (`agent.go:364,377,386,395`)
- keepalive send failure (`agent.go:667-676`)
- heartbeat ping send failure (`agent.go:576-578`)
- watchdog closing the conn after read-silence (see §3)
- proxy sends global request `reconnect@goteleport.com` — graceful drain advisory (`agent.go:525-536`; sent by proxy from `conn.go:264` `adviseReconnect`, e.g. on proxy shutdown)
- pool disconnecting an excess agent (proxy-peering only, `agentpool.go:500`)

While draining, new transport channels are rejected with `ssh.ConnectionFailed, "agent connection is draining"` (`agent.go:591-597`); existing ones are allowed to finish.

### The pool: reconnection and connection count

`AgentPool.run()` (`agentpool.go:279-307`) is an infinite loop: acquire a lease from the `track.Tracker` → dial → on agent close, loop again.

- **Backoff**: linear, step **1s**, max **8s**, jittered, auto-resets after 4 good intervals (`agentpool.go:200-205`, `maxBackoff` at `:61`). So after a tunnel drop, reconnect attempts start ~1s later — the tunnel layer itself recovers fast.
- **How many tunnels**: agent-mesh (default) = one connection to every known proxy (`track/tracker.go:178-216`); with a single proxy replica, exactly one tunnel. Proxy gossip (`teleport-discovery` channel) feeds the tracker.
- Failed dial logs `"Failed to establish reverse tunnel"` (`agentpool.go:287-295`).
- Registration on the proxy: cert role → tunnel type (`srv.go:819-883`, `RoleDatabase → DatabaseTunnel` etc.), keyed by `{hostUUID, tunnelType, scope}` and **appended** to a per-key list — multiple simultaneous tunnels per agent are normal during reconnects (`local_cluster.go:753`, `conn.go:45`).

---

## 3. Steady state — keepalive flows and timers

Three periodic mechanisms run on an established tunnel, **two independent directions plus a watchdog**:

```
 AGENT                                                   PROXY
   │  (A) SSH global req "keepalive@openssh.com"           │
   │      every ~KeepAliveInterval (jittered ×8/7),        │
   │      wantReply=true  ──────────────────────────────▶  │ replies (srv.go:429-430)
   │  ◀── reply (pets agent watchdog, updates SRTT)        │
   │                                                       │
   │  (B) "ping" on channel "teleport-heartbeat"           │
   │      every KeepAliveInterval, wantReply=false ─────▶  │ resets offlineThreshold timer,
   │                                                       │ markValid (local_cluster.go:837-861)
   │                                                       │
   │  ◀── (C) SSH global req "keepalive@openssh.com"       │
   │      every DefaultIdleConnectionDuration/3 = 5m       │
   │      HARDCODED (sshutils/server.go:583,702-707)       │
   │      any read pets the agent watchdog                 │
```

- **(A)** `agent.go:649-707`. Send failure → `Stop()`. First success **arms the watchdog** with `timeout = KeepAliveInterval × KeepAliveCountMax` (`agent.go:695-696`).
- **Watchdog** (`lib/utils/timeout.go:64-123`): closes the underlying `net.Conn` if **no bytes are read** from the proxy for the timeout. Petted by any read: keepalive replies (A), proxy keepalives (C), discovery gossip, transport traffic. Disable env: `TELEPORT_UNSTABLE_DISABLE_AGENT_STALE_CONN_TIMEOUT` (`agentpool.go:563-572`).
- **(B)** `agent.go:553,572-580`. Pings stop while draining. Proxy side resets a per-conn `offlineThreshold` timer on each ping.
- **(C)** the proxy's `sshutils.Server` ticker is **not** derived from cluster networking config — fixed 15m/3 = 5m (`lib/sshutils/server.go:583`, `lib/defaults/defaults.go:136`).

### Proxy-side liveness judgment (`localCluster.handleHeartbeat`, `local_cluster.go:784-881`)

Two-stage, much slower than the agent side:

1. **offlineThreshold** = `KeepAliveCountMax × KeepAliveInterval` (`srv.go:340`), default **3 × 5m = 15m**. Timer fires → `markInvalid("no heartbeats for 15m")`, logging `"Unhealthy reverse tunnel connection"` (`conn.go:188-194`). The conn is *not* closed.
2. **Hard close** only at `offlineThreshold × missedHeartBeatThreshold` (**3×**, `local_cluster.go:61`) = default **45m**, and **only if `activeSessions == 0`** (`conn.go:217-221`, `local_cluster.go:866-870`). With active sessions it logs `"Deferring closure of unhealthy connection due to active connections"` and keeps waiting.
3. Independent immediate path: if the heartbeat channel *closes* (TCP conn actually died and the SSH layer noticed), → `"Agent disconnected"`, `markInvalid`, conn removed at once (`local_cluster.go:838`, deferred cleanup `:801-809`).

### The `remoteConn` state machine (proxy's view of one tunnel; `lib/reversetunnel/conn.go`)

States are three mostly-orthogonal flags: `ready` (≥1 heartbeat received, `conn.go:238`), `invalid` (`conn.go:72,188-209`), `closed` (`conn.go:79`), plus counter `activeSessions` (`conn.go:85,176-186`).

```
        addConn (local_cluster.go:753)
              │
        [not-ready, valid] ──first ping──▶ [ready, valid]  ◀──ping── (markValid resets invalid)
                                              │
                       offlineThreshold 15m   │   transport channel-open failure
                       (no ping)              ▼   (local_cluster.go:952-959)
                                          [ready, INVALID] ──ping──▶ [ready, valid]
                                              │
             45m AND activeSessions==0  ──────┴──────▶  [closed, removed]
             OR heartbeat channel closed
```

**Critical selection rule** (`getRemoteConn`, `local_cluster.go:905-945`): a dial picks the newest *ready+valid* conn; if none, it **knowingly returns the newest ready-but-invalid conn as a last resort** (comment at `:934-938`) rather than failing with "offline". Only when no ready conn exists at all does the caller get `trace.NotFound("%v is offline: no active %v tunnels found")` (`:944`).

---

## 4. Dialing through the tunnel (proxy → agent)

Entry: `localCluster.Dial`/`DialTCP` → `getConn` (`local_cluster.go:279-346, 630-751`).

```
getConn(dreq)
 ├─ dialTunnel (local_cluster.go:689)
 │    ├─ getRemoteConn  ── none registered ──▶ NotFound "no <type> reverse tunnel for <id> found" (:917)
 │    │                 ── none ready ───────▶ NotFound "<id> is offline: no active <type> tunnels found" (:944)
 │    └─ chanTransportConn (:947) → sshutils.ConnectProxyTransport (api/utils/sshutils/conn.go:37)
 │         opens SSH channel "teleport-transport", sends "teleport-transport-dial" + JSON DialReq
 │         ├─ channel-open fails → markInvalid; if idle, conn removed+closed immediately (:952-959)
 │         └─ agent replies !ok → error text read from channel stderr, returned VERBATIM (conn.go:71)
 ├─ tunnelErr not NotFound ─▶ ConnectionProblem(tunnelErr, getTunnelErrorMessage) — NO direct dial (:726)
 ├─ skipDirectDial? db/app/okta: always; kube/desktop: sentinel addr → yes (:566-580)
 └─ else directDial (ssh nodes) (:537)
```

The user-facing wrapper `getTunnelErrorMessage` (`local_cluster.go:592-607`): `"Teleport proxy failed to connect to %q agent %q over %s: ... This usually means that the agent is offline or has disconnected..."`.

### Agent side of a dial (`AgentPool.handleLocalTransport`, `agentpool.go:695-746`)

1. Waits up to `DefaultIOTimeout` = **30s** (`api/defaults/defaults.go:33`) for the dial request; timeout logs `"Timed out waiting for transport dial request"` (`:705-707`).
2. Replies OK, wraps the channel as a `net.Conn`, sanity-checks the address (`LocalNode`/`LocalKubernetes`/... — unexpected addresses are logged but **routed to the local service anyway**, `:734-740`).
3. Hands off in-process: `p.Server.HandleConnection(conn)` (`:745`). From here the reverse tunnel is a dumb pipe; all further failure semantics belong to the service (L6).

### db_service handling (L6) and error translation back to the client

`lib/srv/db/server.go:1161-1297`: TLS re-handshake with the proxy-minted per-session cert, authorize, start **agent-side ConnectionMonitor**, dispatch to protocol engine. The central error translator is the deferred **`engine.SendError(err)`** (`server.go:1241-1249`) — any error in the chain becomes a *protocol-native* error frame (postgres `ErrorResponse`, mysql `ERR` packet) written back down the still-open tunnel stream, through the proxy relay, the local proxy, to the user's client.

Real-database connect errors pass through `common.ConvertConnectError` (`lib/srv/db/common/errors.go:124-162`): CA mismatches and cloud-IAM denials get curated guidance; a plain **`connection refused` (database down) is returned raw** — psql prints the literal Go dial error.

### Proxy-side connect loop for db (L3)

`connect.Connect` (`lib/srv/db/common/connect/connect.go:294-346`) iterates candidate `db_service`s healthy→unknown→unhealthy; a tunnel-down error (`isReverseTunnelDownError`: `ConnectionProblem` or contains `NoDatabaseTunnel`) moves to the next candidate (`:332-335`); when all fail: **`trace.BadParameter("failed to connect to any of the database servers")`** (`:345`) — this is the error postgres/mysql users actually see for "agent offline", not the tunnel-layer message, which survives only in proxy logs.

### The client layers (L0–L1)

`tsh db connect` → local listener on `localhost:0` (`tool/tsh/common/db.go:630,693`); per accepted conn (`lib/srv/alpnproxy/local_proxy.go:186-223`):
1. `Middleware.OnNewConnection` = `CertChecker.GetOrIssueCert` — re-issues the per-session db cert if expired/mismatched, may trigger relogin/MFA (`lib/client/local_proxy_middleware.go:115-171`). Failure → **this client conn is closed and the loop continues** (`local_proxy.go:206-210`); the cause is only in tsh's stderr.
2. Dial proxy with TLS+ALPN (`api/client/alpn.go:126-150`), then `utils.ProxyConn` bidirectional copy.
3. **On any upstream failure the only signal to the db client is `downstreamConn.Close()`** (`local_proxy.go:233`) — no protocol error is synthesized at L1. psql renders this as `server closed the connection unexpectedly`.

---

## 5. Resumption (ssh only)

Package `lib/resumption` (design: RFD 0150). A userland `net.Conn` (`managedConn`) sits **below SSH**, above the transport; both peers keep a replay buffer and can re-attach a fresh transport. Wired only into the **SSH node** (`lib/service/service.go:3745-3786`) and SSH-path clients (tsh `lib/client/cluster_client.go:157-179`, tbot). Detection is in-band via the SSH version string (`"SSH-2.0-Teleport resume-v1 <pubkey> <hostID>"`); token = 16 bytes of SHA-256(ECDH secret), never sent plaintext (masked with a fresh ECDH-derived OTP on each resume, `client.go:356-365`, `server_exchange.go:152-162`).

### Conn-level states (both peers; `managedconn.go:57-84`, `resumable.go:49-57`)

```
ATTACHED  (transport bound; requestDetachLocked != nil)
DETACHED  (no transport; buffers held; app reads BLOCK, writes buffer up to 2 MiB)
LOCAL_CLOSED / REMOTE_CLOSED  (terminal; reads drain→EOF, writes → EPIPE)
```

### Client driver (`runClientResumableUnlocking`, `client.go:179-272`)

- On transport loss → reconnect loop: backoff **50ms → ×2 → cap 10s** (`client.go:44-45,250`), deadline **1 minute** (`reconnectTimeout`, `client.go:42`). Reconnect = fresh `DialHost` **through the proxy addressing the node by host ID** — over a *fresh* reverse-tunnel transport (`cluster_client.go:167-173`).
- Independent of failures, a **proactive replacement every 3 minutes** re-dials and swaps transports (`replacementInterval`, `client.go:40,194-217`) — this is the main defense against silently-dead transports.
- Permanent give-ups: expired client cert, `notFound`/`badAddress` server response, non-resumable server reached (`client.go:315-317,346,381-389`).

### Server side (`server_detect.go:105-128`, `server_exchange.go`)

- Holds a detached conn for **1 minute** (`detachedTimeout`, `server_detect.go:46`), then closes it. The timer arms **only when the transport errors out** — a silently-dead transport keeps `running>0` indefinitely until its own I/O fails.
- Resume from a different source IP → rejected `badAddress` (`server_exchange.go:183-186`). Position desync outside the 2 MiB replay window → `"got incompatible resume position"` (`resumable.go:203`).
- Graceful restart handover between processes via Unix socket (`handover.go`).

### Interaction with keepalives — the masking property

Resumption has **no liveness probes of its own**. While DETACHED, SSH-layer keepalive *writes succeed into the buffer* and reads simply block — so the SSH layers above (including flows A/B/C of §3 for the node↔proxy leg, and the client's own SSH keepalives) observe *nothing wrong* until resumption gives up and the virtual conn returns EOF/EPIPE. Net effect: failure surfacing is delayed by up to the resumption windows, and the *cause* ("transport lost, resume failed: bad address") exists only in debug logs.

---

## 6. Presence layer (abstracted in the model)

Upstream of every dial, the proxy resolves the target from **backend heartbeat records** (`types.Server`/`types.DatabaseServer`… TTL ≈ 10m, `apidefaults.ServerAnnounceTTL`), maintained by the agent over its **separate** auth connection (inventory control stream). This layer can disagree with tunnel reality in both directions:

- record exists, tunnel gone → dial proceeds, fails at L4 (`"failed to connect to any of the database servers"`).
- record expired, tunnel alive → user gets `"database %q not found among registered databases in cluster %q"` (`connect.go:82`) or `"target host %s is offline or does not exist"` (`lib/proxy/router.go:610`) without any dial attempt.

Per the agreed scope, the model represents presence as a per-agent boolean (`registered`/`expired`) that the fault injector may flip independently of tunnel state. Note `TunnelConnection` backend records are written **only for leaf-cluster (proxy) tunnels** (`leaf_cluster.go:391-405`) — agent liveness for dials is purely the in-memory `remoteConns` map of §3.

---

## 7. Timing constants (defaults)

| Constant | Value | Owner | Source |
|---|---|---|---|
| `KeepAliveInterval` | 5m | cluster networking cfg | `api/defaults/defaults.go:98` |
| `KeepAliveCountMax` | 3 | cluster networking cfg | `api/defaults/defaults.go:41` |
| Agent keepalive period (A) | ~5m ×[1,8/7] jitter | agent | `agent.go:651,664` |
| Agent heartbeat ping period (B) | 5m | agent | `agent.go:553` |
| Agent watchdog (read silence → close) | 15m (`interval×count`) | agent | `agent.go:695` |
| Proxy keepalive period (C) | **5m fixed** (15m/3) | proxy sshutils | `sshutils/server.go:583`, `defaults.go:136` |
| Proxy `offlineThreshold` (mark invalid) | 15m | proxy | `srv.go:340`, `local_cluster.go:862` |
| Proxy hard close (idle+invalid) | 45m (3× threshold) | proxy | `local_cluster.go:61,866-870` |
| Agent reconnect backoff | linear 1s→8s, jitter, autoreset 4 | agent pool | `agentpool.go:61,200-205` |
| Dial / transport-request IO timeout | 30s | both | `api/defaults/defaults.go:33` |
| Resumption client retry window | 1m | tsh | `resumption/client.go:42` |
| Resumption client backoff | 50ms→10s ×2 | tsh | `client.go:44-45` |
| Resumption proactive replacement | 3m | tsh | `client.go:40` |
| Resumption server detached hold | 1m | node | `server_detect.go:46` |
| Resumption handshake timeout | 5s | both | `resumable.go:61` |
| Resumption replay window | 2 MiB | both | `managedconn.go:37` |
| Presence record TTL | ~10m | auth backend | `api/defaults` `ServerAnnounceTTL` |

---

## 8. Fault taxonomy → detection matrix (tunnel idle, defaults)

| Fault on the tunnel TCP conn | Agent detects | Proxy detects | Window where they disagree |
|---|---|---|---|
| **RST injected** (LB/firewall) | next read/write errors → `Stop()` → redial ≤ ~9s | SSH conn dies → heartbeat channel closes → `"Agent disconnected"`, conn removed immediately | seconds |
| **FIN / clean close** | same as RST | same | seconds |
| **Silent blackhole** (drop all, e.g. LB idle purge without RST) | watchdog at ≤15m after last read → close+redial | mark-invalid at 15m after last ping; **close only at 45m if idle** | **up to 15m fully undetected; 15m–45m proxy holds an invalid conn that dials may still select** |
| **One-way loss** (agent→proxy dropped) | agent's keepalive (A) gets no reply — but replies aren't awaited synchronously; watchdog still petted by proxy keepalives (C) → agent may **not** detect | proxy sees no pings → invalid at 15m | pathological: conn "half-healthy" indefinitely from agent's view |
| **Agent process killed** | n/a | TCP dies → immediate `"Agent disconnected"`; presence record lingers ≤10m | dials fail fast at L4 but presence still lists target |
| **Proxy restart (graceful)** | `reconnect@goteleport.com` → drain → redial | proxy drains | in-flight sessions die unless ssh+resumption |

During the blackhole window the proxy's dial path behavior is the worst case: `getRemoteConn` still returns the dead conn (valid <15m, or invalid-as-last-resort ≥15m), the `teleport-transport` channel open blocks on a dead TCP conn, and the client-facing result is a **hang until TCP gives up or a 30s timeout**, then a generic error — not "agent offline".

---

## 9. End-user outcome matrix (what actually reaches the human)

For `tsh db connect` (postgres unless noted):

| Root cause | Layer that knows | What the user sees | Faithful? |
|---|---|---|---|
| Database down (`connection refused`) | L6 engine | psql error frame with raw dial error (`errors.go:161` passthrough) | yes (verbatim, arguably too raw) |
| DB CA mismatch | L6 | curated guidance frame (`errors.go:131-140`) | yes |
| Agent offline, presence current | L3/L4 | `failed to connect to any of the database servers` (`connect.go:345`) | partial — the informative tunnel message (`local_cluster.go:592`) is only in proxy logs |
| Agent offline, presence expired | L3 | `database %q not found among registered databases...` (`connect.go:82`) | misleading if db exists but agent died |
| Tunnel silently dead (<15m window) | nobody yet | hang, then bare close / timeout | **no** |
| Cert re-issue/MFA failure at local proxy | L1 | bare TCP close; cause only in tsh stderr (`local_proxy.go:206-210`) | **no** (client-side) |
| Idle timeout / cert expiry mid-session | L3+L6 monitors | bare close — DB monitors have **no `MessageWriter`** (`lib/srv/monitor.go:155-208`), reason goes to audit log only | **no** |
| Mongo/redis/etc. any proxy-side error | L3 | bare close (no protocol handler at proxy, `proxyserver.go:289-347`) | **no** |
| ssh: transport drop, resume succeeds | L5' resumption | nothing (by design) | yes |
| ssh: resume gives up (>1m / bad address / desync) | resumption | SSH conn error after masking delay; cause in debug logs | **no** |

---

## 10. Mapping to the P model (`TeleportTunnel.p`)

| P machine | Models | Key code anchors |
|---|---|---|
| `TimeKeeper` | deadline-ordered logical clock; all timers | §7 table |
| `Network` | every TCP conn as `{ALIVE, BLACKHOLE, RESET, CLOSED}`; fault injection API | §8 taxonomy |
| `Agent` | agent+pool state machine, keepalive (A/B), watchdog, transport handler, local service handoff | §2, §3 |
| `Proxy` | remoteConn registry+flags, heartbeat loop, offlineThreshold/hard-close, `getRemoteConn` selection, per-protocol error frame vs bare close | §3, §4 |
| `LocalProxy` | tsh local tunnel per-conn lifecycle, cert middleware failure mode | §4 (L0–L1) |
| `Client` | end-user client; observes outcomes (`ProtocolError(cause)` vs `BareClose` vs `Hang`) | §9 |
| `Target` | database/host; can be down/up | L7 |
| `Presence` | boolean registered/expired, desync-able | §6 |
| `ResumptionLayer` | managedConn ATTACHED/DETACHED + windows (ssh instances only) | §5 |
| spec `ErrorAttribution` | flags `BareClose`/`Hang` observed while a deeper root cause was announced | §9 rows marked **no** |
| spec `RecoveryLiveness` | hot until tunnel re-established & dials succeed after fault clears | §2 backoff, §3 |
| spec `ResumptionSafety` | byte-sequence prefix integrity across detach/reattach | §5 |

Agent type is a model parameter `tAgentKind ∈ {SSH, DB_PG, DB_MONGO, APP, KUBE}` toggling the four behaviors of §1.
