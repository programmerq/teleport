# Teleport Agent Tunnel Mode — Model-Checking Results & Findings

Companions: `01-tunnel-state-model.md` (cited state machines), `TeleportTunnel.p` (the P model).
Checked with P 3.1.0 (`p compile && p check -tc <test> -s 300`), 300 schedules per test, on
`gravitational/teleport` @ `master` `67276143`.

**How to read this**: the model encodes the state machines and timers exactly as cited from the code.
Tests assert three specs: `ErrorAttribution` (a user-visible failure must carry a cause when some layer
knew one), `RecoveryLiveness` (a dropped tunnel must come back), `ResumptionSafety` (no byte
loss/dup/reorder across reattach). A failing test is a *reachable* bad-UX path, with a counterexample
trace in `out/<test>/BugFinding/`. Model checking proves reachability *in the model*; every finding
below is additionally anchored to the specific code that produces the behavior.

## 1. Test matrix

| Test | Scenario | Spec | Result |
|---|---|---|---|
| `tcRstIdle` | RST on idle tunnel | RecoveryLiveness | ✅ pass |
| `tcSilentDropIdle` | blackhole on idle tunnel | RecoveryLiveness | ✅ pass |
| `tcProxyDrain` | `reconnect@goteleport.com` advisory | RecoveryLiveness | ✅ pass |
| `tcTargetDownPg` | database down, postgres | ErrorAttribution | ✅ pass |
| `tcTargetDownMongo` | database down, mongo | ErrorAttribution | ✅ pass |
| `tcAgentGonePg` | agent stopped, postgres client dials | ErrorAttribution | ✅ pass |
| `tcAgentGoneKube` | agent stopped, kubectl dials | ErrorAttribution | ✅ pass |
| `tcAgentGoneSsh` | agent stopped, tsh ssh dials | ErrorAttribution | ✅ pass |
| `tcPresenceExpired` | heartbeat record expired, tunnel healthy | ErrorAttribution | ✅ pass (but see F6) |
| `tcDialDuringRst` | dial ≥2s after RST | ErrorAttribution | ✅ pass |
| `tcResumptionFaults` | 2 random faults (RST/blackhole) on resumable ssh stream | ResumptionSafety | ✅ pass |
| `tcOneWayProxyLossIdle` | one-way loss (proxy→agent), idle | RecoveryLiveness | ✅ pass (watchdog-driven, ~15m) |
| `tcFlapRst` | 3 RSTs within 60s (flapping) | RecoveryLiveness | ✅ pass (churn, but converges) |
| `tcDialDuringBlackhole` | dial while tunnel blackholed (<15m) | ErrorAttribution | ❌ **F1: user hangs, no layer knows why** |
| `tcAgentGoneMongo` | agent stopped, mongo client dials | ErrorAttribution | ❌ **F4: bare close, proxy knew cause** |
| `tcAgentGoneApp` | agent stopped, browser app request | ErrorAttribution | ❌ **F4b: generic 500, cause omitted** |
| `tcCertReissueFail` | local-proxy cert re-issue fails | ErrorAttribution | ❌ **F5: bare close, tsh knew cause** |
| `tcMidSessionRst` | RST while a session is active, next query | ErrorAttribution | ❌ **F3 (model-verified): bare close** |
| `tcMidSessionBlackhole` | blackhole while a session is active | ErrorAttribution | ❌ **F3/F1: mid-session hang** |
| `tcOneWayAgentLossDial` | dial during one-way agent→proxy loss | ErrorAttribution | ❌ **F10: hang ≈20m** |
| `tcOneWayProxyLossDial` | dial during one-way proxy→agent loss | ErrorAttribution | ❌ **F10: hang on a fully-VALID conn** |
| **wave 2 (tbot / dialers / leaks — workflow-proposed)** | | | |
| `tcLpDialHungBackend` | tsh/tbot local tunnel dials a wedged proxy backend | DialBounded | ❌ **F11: dial pending forever, wedge survives backend recovery** |
| `tcTbotLbOneBadBackend15m` | LB rotates one blackholed backend; per-conn dials | DialBounded | ❌ **F11: the reported tbot ~15m hang (kernel give-up at ~924s)** |
| `tcTbotLbOneBadBackendBounded` | same, with a 30s dial deadline added | DialBounded | ✅ pass — machine-checked fix argument |
| `tcAgentStuckDialAlpn` | agent redial hits wedged backend, ALPN path | RecoveryLiveness | ❌ **F12: serial pool wedges forever — flips §2.1** |
| `tcAgentStuckDialHttpProxy` | same, HTTPS_PROXY path (30s deadline kept) | RecoveryLiveness | ✅ pass — recovery depends on HTTPS_PROXY being set |
| `tcSessionLeakPinsConn` | immortal client session pins unhealthy conn | ErrorAttribution | ❌ **F13: 45m window becomes unbounded** |
| `tcSessionLeakControl` | same, client with 60s patience | ErrorAttribution | ✅ pass — flip caused by one parameter |
| `tcPresenceFlapWrongCause` | auth outage 5min, tunnel healthy, dial in window | CauseFidelity | ❌ **F14: confident misattribution, now checkable** |

Note on coverage semantics: each test is a *scenario family*, not one sequence — `p check -s 300`
explores 300 schedules per family (fault instants via `choose`, timer tie-breaks, message
interleavings). The families themselves are hand-picked, though; §5 lists what remains unexplored.

## 2. Verified-good properties (worth knowing when troubleshooting)

1. **RST recovery is fast and symmetric.** An injected RST is detected by both sides on their next
   read/write (kernel wakes blocked reads); the agent redials within backoff (1–8s,
   `agentpool.go:200-205`), the proxy removes the conn immediately (`"Agent disconnected"`,
   `local_cluster.go:838`). A dial 2s later succeeds. If a user reports a one-off "unexpected EOF"
   that immediately works on retry, an LB/firewall RST on the tunnel is a plausible cause — in-flight
   sessions on that tunnel *do* die with bare EOFs (see F3).
2. **The agent-side watchdog bounds silent-blackhole detection at ≤15m** (`keepAliveInterval ×
   keepAliveCountMax`, `agent.go:695`), even though the proxy side won't hard-close the dead conn
   until 45m (`local_cluster.go:61,866`). Recovery is always agent-driven: watchdog close → redial.
   The model confirms the timeline exactly: fault at t=100 → watchdog at t=1000 → new tunnel at t=1008.
3. **Graceful proxy drain works**: the advisory triggers agent drain + immediate redial; no liveness gap.
4. **Kube and SSH clients get attributed errors for proxy-side failures**: kubectl receives the
   error text as `metav1.Status` JSON (`lib/kube/proxy/forwarder.go:763-778`); tsh ssh receives it
   through the SSH handshake. The bare-close/generic problem (F4/F4b) is specific to generic-TLS db
   protocols and app access.
5. **Agent-side (engine) errors reach the user for *all* database protocols** — the deferred
   `engine.SendError` (`lib/srv/db/server.go:1241-1249`) writes protocol-native frames that the proxy
   relays as bytes. `psql` and `mongosh` both see "connection refused" when the database is down.
   The bare-close problem (F4) is specific to *proxy-originated* failures.
6. **Resumption stream integrity holds** across arbitrary detach/reattach with random RST/blackhole
   faults: no loss, duplication, or reorder (RFD 0150's core guarantee; replay-buffer + cumulative-ack
   design in `lib/resumption/resumable.go`, `managedconn.go`). 0 violations in 300 schedules.

## 3. Findings

### F11 (HIGH — reported incident) — tbot/tsh local tunnels: per-connection upstream dials have NO deadline at any step
**Model**: `tcTbotLbOneBadBackend15m` — trace shows the dial start, `eDialOverdue` at +60s, and the
kernel connect give-up at **+924s (~15.4 min, Linux `tcp_retries2`)** — the reported tbot incident
signature, interleaved with successful conns that drew the healthy LB backend. `tcLpDialHungBackend`
shows the worse variant: an accepted-but-hung backend (no RST, kernel ACKs) wedges the dial
**forever**, and the wedge survives the backend recovering, because per-conn dials are never retried.

**Mechanism (code)**: every downstream client connection triggers a fresh upstream
TCP+TLS(+websocket-upgrade) dial (`local_proxy.go:232-247`), and every step is unbounded:
`net.Dialer.Timeout=0` (`local_proxy.go:303-314` → `api/client/alpn.go:132`), TLS
`HandshakeContext` on a long-lived parent ctx (`alpn.go:145`), and the upgrade round-trip has no
deadline (`api/client/proxy/alpn_conn_upgrade.go:244-251`). The ALPN ping protocol is
**server→client only** (30s interval, `lib/defaults/defaults.go:304-307`) and the client never
checks pings arrive — there is no tbot analog of the agent watchdog. Related fail-open:
`IsALPNConnUpgradeRequired` probes with 5s but returns `false` on error (`alpn_conn_upgrade.go:86-91`)
and the result is effectively cached, so a transient probe failure latches the wrong dial mode.

**Fix argument, machine-checked**: `tcTbotLbOneBadBackendBounded` — the identical scenario with a
30s dial deadline passes `DialBounded`: the user gets a fast (if still unattributed, see F5) failure
and the next attempt re-rolls the LB. Suggested: set `DialTimeout`/handshake deadlines on the
LocalProxy dial path and a deadline on the upgrade RTT; consider client-side ping-liveness.

### F12 (HIGH) — Agent redial wedges forever on the ALPN path: recovery is NOT always convergent
**Model**: `tcAgentStuckDialAlpn` fails RecoveryLiveness — this **flips §2.1/§2.2** ("recovery always
converges"), which held only while dials were modeled as atomic. The agent pool dials serially
(`agentpool.go:279-307`, one attempt in flight); `agentDialer` passes a 30s `DialTimeout`
(`agent_dialer.go:68`) **but the alpnDialer path drops it** (`lib/utils/proxy/proxy.go:69-73`;
`alpnDialerConfig` sets no `DialTimeout`, `agentpool.go:849-857`). One accepted-but-hung backend
(unhealthy proxy still in the LB) therefore wedges the agent's reconnect loop indefinitely — the
agent never becomes reachable again without a restart. The asymmetry is the finding's sharpest edge:
with HTTPS_PROXY set, the whole dial is wrapped in a 30s timeout (`proxy.go:96-108`) and
`tcAgentStuckDialHttpProxy` passes — **agent recovery currently depends on whether an egress proxy
is configured**. The SSH handshake *after* TCP+TLS is bounded (30s, `agent_dialer.go:102-107`), so
only the accept-then-hang class triggers this.

### F13 (MED-HIGH) — One leaked/immortal client session makes the dead-conn window unbounded
**Model**: `tcSessionLeakPinsConn` vs `tcSessionLeakControl` — a single parameter flip (client
patience 0 vs 60s). The 45m hard close requires `activeSessions()==0` (`conn.go:217-221`,
`local_cluster.go:866-870`); a JDBC-pool-style client that never hangs up (its query vanished into a
blackholed tunnel; it waits forever) pins the dead conn indefinitely. A dial hours later still
selects it (F2's last-resort) and hangs with no cause anywhere. Log signature: repeating
`"Deferring closure of unhealthy connection due to active connections"` with non-decreasing
`active_conn_count` (`local_cluster.go:870`). Fix directions: cap deferred-closure iterations; make
session-tracking conns subject to their own idle/liveness bound; F1(a)'s bounded transport-open
prevents new dials from joining the pinned conn.

### F14 (MED) — Misattribution is now a checkable property (`CauseFidelity` spec)
**Model**: `tcPresenceFlapWrongCause` — during a 5-minute control-plane outage with a perfectly
healthy tunnel, a dial returns `database %q not found among registered databases...`
(`connect.go:82`): ErrorAttribution *passes* (a cause IS attached), proving the original spec was
blind to wrong-but-confident errors; the new `CauseFidelity` spec (fault-injector ground truth vs
rendered cause) fails deterministically. This upgrades F6 from prose to a regression-checkable
artifact: any future fix distinguishing "never registered" vs "expired Xm ago, agent still
connected" makes this test pass.

### F15 (MED, code-read — not model-checked) — tbot per-connection overhead catalog
From the workflow's tbot exploration (the "heavy use, unoptimized" report):
- **`application-proxy` builds a new `http.Transport`+`http.Client` per REQUEST**
  (`lib/tbot/services/application/proxy_service.go:323-341`); zero-value Transport ⇒
  `IdleConnTimeout=0` and no `CloseIdleConnections()` — each request strands a persistent upstream
  TLS conn plus its read/write goroutines. Acknowledged by in-code TODOs (`:217-220`, `:321-322`).
  This is almost certainly the remembered "go handles" complaint.
- **Accept-loop head-of-line blocking**: `OnNewConnection` cert-expiry check → reissue (2-4 auth
  RPCs + RSA-2048 keygen for db, `generator.go:297-302`) runs inline before the next `Accept`
  (`local_proxy.go:204-212`): one slow reissue at a renewal boundary stalls all other clients.
- Per-conn: 3 goroutines + 2×32KiB copy buffers (`proxyconn.go:62-96`); ssh-mux adds an OTel root
  span, two `context.AfterFunc`s, and 3 Prometheus ops per conn (`multiplexer.go:529-545,617-621,
  782-789`), plus a full new proxy client (TCP+TLS+websocket+HTTP/2) every 100 dials (`:851-894`).
- Combined with F11: hung upstream dials pin all of the above for the full kernel timeout with no
  cap on in-flight connections.

### F1 (HIGH) — The silent-blackhole dial window: user hangs and *no* layer knows anything
**Model**: `tcDialDuringBlackhole` — assertion `UX GAP: user hung until giving up; last known deeper
cause: NONE (layer 0)`. Note the cause: not "wrong error" — *no error anywhere in the system*.

**Mechanism (code)**: after a middlebox silently kills the tunnel TCP conn (idle purge without RST):
- For up to 15m the proxy's `remoteConn` is still `valid` (nothing has failed yet); `getRemoteConn`
  happily selects it (`local_cluster.go:905-945`).
- `chanTransportConn` → `sshutils.ConnectProxyTransport` → `OpenChannel` on a dead TCP conn
  (`local_cluster.go:947`, `api/utils/sshutils/conn.go:37`). **There is no proxy-side timeout on the
  transport channel open** — it blocks until kernel TCP retransmission gives up (~15m by default).
  The agent-side 30s guard (`agentpool.go:705`) never runs because the dial request never arrives.
- The client (psql via tsh local proxy) sees pure silence, then whatever its own timeout produces.
  Nothing is logged at dial time on any component; the first system-side evidence appears at ≥15m
  (`"Unhealthy reverse tunnel connection"`, `conn.go:194` / agent watchdog).

**Suggested improvements**:
(a) bound the transport channel open with a context/timeout at the proxy and `markInvalid` on expiry
    (today `markInvalid` fires only on channel-open *error*, `local_cluster.go:952-959`);
(b) on that timeout, retry the dial on the next-newest conn or fail fast with the offline message —
    turning a 15m hang into a bounded, attributed error;
(c) enable aggressive TCP keepalives on the tunnel conn itself so the kernel surfaces the dead peer in
    seconds-to-minutes instead of relying on 15m application timers.

### F2 (MED) — Invalid-conn-as-last-resort extends the window past 15m for hang-type faults
`getRemoteConn` deliberately returns the newest ready-but-**invalid** conn when no valid one exists
("the error might be more informative than the default offline message", `local_cluster.go:934-939`).
That trade-off is only correct when the conn fails *fast* (RST/closed). For a blackholed conn the
"more informative error" is another indefinite block — so even after the proxy has concluded the
agent is unhealthy, dials keep hanging instead of returning `"<id> is offline: no active tunnels"`
(`local_cluster.go:944`). Same fix as F1(a)/(b); alternatively only use invalid conns when their
`lastError` indicates a fast-fail class.

### F3 (MED) — In-flight sessions die as bare EOFs when the tunnel drops
**Model**: `tcMidSessionRst` — `UX GAP: user saw a bare connection close but layer 4 knew the cause:
TUNNEL_DOWN`; `tcMidSessionBlackhole` — the mid-session variant of the F1 hang (next query vanishes
into the dead tunnel; nothing times out server-side).
When a tunnel conn dies (RST or hard-close), every client session multiplexed over it gets a bare
connection close: the proxy just tears down the transport channels; nothing protocol-aware is sent.
The end user sees `server closed the connection unexpectedly` / `unexpected EOF` with no hint that the
*tunnel* (not the database, not their query) was the casualty — precisely the complaint that motivated
this analysis. Improvement: on tunnel-conn death, have the db proxy emit a protocol error frame
("teleport: connection to the database agent was lost") for the protocols that support it before
closing (postgres/mysql already have the machinery: `postgres/proxy.go:69`, `mysql/proxy.go:88` — but
it is only used for dial-time errors, not mid-session teardown; sessions after connect are a raw
`utils.ProxyConn` byte relay, `proxyserver.go:471-496`).

### F4 (MED) — Non-postgres/mysql protocols: proxy-originated failures are always bare closes
**Model**: `tcAgentGoneMongo` — `UX GAP: user saw a bare connection close but layer 4 knew the cause:
TUNNEL_DOWN`. Only postgres/mysql/sqlserver have protocol-aware proxies registered at the ALPN router
(`lib/service/service.go:6296-6306`); for mongo/redis/etc. `ProxyServer.handleConnection` returns the
error to nobody — the conn is closed (`proxyserver.go:289-347`). The excellent curated messages
("failed to connect to any of the database servers", `connect.go:345`; `NoDatabaseTunnel`,
`reversetunnelclient/api.go:193`) exist but die in proxy logs. Improvement: per-protocol error
codecs at the proxy (the agent engines already contain `SendError` implementations for each protocol
that could be reused), or minimally: mid-handshake TLS alert with a descriptive enterprise extension.

#### F4b (LOW-MED) — App access renders proxy-side failures as a cause-less generic 500
**Model**: `tcAgentGoneApp` — `UX GAP: user got a generic error without the cause layer 4 knew`.
On a tunnel `ConnectionProblem` the app handler retries once through a renewed session, then falls
back to a launcher redirect or a plain `500 Internal Server Error` body
(`lib/web/app/handler.go:317-336`); the `NoApplicationTunnel` guidance
(`lib/reversetunnelclient/api.go:187`) stays in proxy logs. Better than a bare close (the retry is
genuinely good fault tolerance) but the browser user still cannot distinguish "agent offline" from
any other 500.

### F5 (MED-LOW) — Local-proxy failures are invisible to the database client
**Model**: `tcCertReissueFail` — `UX GAP: bare close but layer 1 (tsh) knew the cause: CERT_FAIL`.
When `CertChecker.OnNewConnection` fails (expired session, MFA/relogin failure), tsh closes the
just-accepted loopback conn and `continue`s (`local_proxy.go:205-210`); on upstream dial failure the
only signal is `downstreamConn.Close()` (`local_proxy.go:233`). Interactive `tsh db connect` users at
least have tsh's stderr in the same terminal; `tsh proxy db --tunnel` users see their GUI client
report a generic disconnect. Improvement: tsh knows the client protocol — synthesize a protocol error
frame ("teleport: session certificate expired, run `tsh login`") before closing, at least for pg/mysql.

### F6 (MED) — Presence/tunnel desync produces confidently wrong errors
Presence (backend heartbeat records via the *separate* agent→auth control stream) gates the dial
before the tunnel is consulted. Two desync cases (modeled as `Presence` flag; both reachable in
production per RFD 0226):
- **Record expired, tunnel healthy** (auth-path failure, agent fine): user gets `database %q not found
  among registered databases in cluster %q` (`connect.go:82`) — reads as a configuration error,
  sending the operator to check spec files while the actual problem is the agent's auth connection.
- **Record present, tunnel gone**: user gets `failed to connect to any of the database servers`
  (`connect.go:345`); the informative variant naming the agent and suggesting it is offline
  (`getTunnelErrorMessage`, `local_cluster.go:592-607`) is only logged proxy-side.
Improvement: distinguish "never registered" vs "registered but expired Xm ago" in the not-found
message; propagate the tunnel-layer detail into the client-facing error.

### F7 (LOW-MED) — Mid-session policy disconnects (idle timeout, cert expiry) are unexplained closes
The connection monitor closes db sessions on idle timeout / cert expiry with
`CloseWithCause(AccessDenied)` — but for db connections **no `MessageWriter` is configured**
(`lib/srv/monitor.go:155-208`), so the reason (`"Client exceeded idle timeout of %v"`,
`"client certificate expired at %v"`, `monitor.go:377-391,437-449`) goes only to the audit log.
The user's client shows a bare disconnect after being idle — indistinguishable from F1/F3 without
cluster-admin access. Improvement: wire the engine's `SendError` as the monitor's message writer.

### F8 (LOW) — Keepalive asymmetries worth documenting
- The proxy→agent keepalive ticker is **hardcoded** at `DefaultIdleConnectionDuration/3` = 5m
  (`sshutils/server.go:583`, `defaults.go:136`) and does not scale with `keepalive_interval`, while
  the agent watchdog it feeds *does* (`interval × count`, `agent.go:695`). Operators tuning
  `keepalive_interval`/`keepalive_count_max` low (watchdog < 5m) leave the watchdog petted only by
  the agent's own keepalive round-trips; a one-way loss (agent→proxy delivered, proxy→agent lost)
  then closes the tunnel on a schedule the operator didn't configure.
- The agent's `keepalive@openssh.com` uses `wantReply=true` but only a *send* error is fatal
  (`agent.go:667-676`); a missing reply is not itself detected — liveness rests entirely on the
  read-watchdog. On a blackholed conn, keepalive writes "succeed" into kernel buffers indefinitely.
- Heartbeat pings are `wantReply=false` (`agent.go:449`) — same property proxy-side: only the
  15m timer, never a failed ping, marks a conn unhealthy.

### F10 (HIGH) — One-way packet loss: dials hang on a tunnel the proxy believes is healthy
**Model**: `tcOneWayAgentLossDial` / `tcOneWayProxyLossDial` — both hang with no attributed cause.
One-way loss (asymmetric routing changes, conntrack half-expiry, some middlebox failures) is nastier
than a full blackhole because the liveness signals are direction-specific:
- **proxy→agent direction lost**: the agent's heartbeat pings still arrive, so the proxy keeps the
  conn **fully `valid`** — it is preferred by `getRemoteConn`, not merely last-resort. Every dial's
  `TRANSPORT_DIAL` vanishes; clients hang. Nothing marks the conn unhealthy, ever. Recovery only
  comes from the *agent's* watchdog (no proxy→agent bytes) closing and redialing at ≤15m.
- **agent→proxy direction lost**: pings stop, so the proxy marks invalid at 15m (then F2's
  last-resort keeps selecting it). The agent, meanwhile, is kept alive by proxy→agent keepalives —
  until the proxy's keepalive *loop* blocks: `sconn.SendRequest(wantReply=true)` in
  `lib/sshutils/server.go:702-707` **blocks forever awaiting the reply** (which crosses the dead
  direction), silencing all further proxy→agent keepalives. Only then does the agent's watchdog
  starve and fire: recovery ≈ keepalive tick (≤5m) + watchdog (15m) ≈ **up to ~20m**.
The same blocking applies to the agent's keepalive goroutine (`agent.go:663`). Improvements: a
timeout around both blocking `SendRequest` calls (makes one-way detection deterministic and fast);
plus F1(a)'s bounded transport-open, which converts these hangs into attributed errors regardless
of direction.

### F9 (MED, ssh only) — Resumption masks failures by design, and its give-up cause is invisible
Verified in the model and code: resumption has **no liveness probes** (`lib/resumption/` contains no
ping machinery); while detached, SSH-layer keepalive writes buffer silently (up to 2 MiB,
`managedconn.go:37`) and reads block, so *nothing* above notices for up to the resumption windows
(client retry 1m + proactive replacement 3m; server hold 1m). The user experiences a frozen terminal
with no feedback; when resumption gives up (deadline, `notFound` after server's 1m hold expires,
`badAddress` on IP roaming — `client.go:381-389`, `server_exchange.go:183-186`), the SSH session dies
with a generic error and the actual cause exists only at debug log level. A silently-dead transport
on the *server* side is worse: the 1m detach hold never arms until the transport errors
(`server_detect.go:121-128`), so the node can hold state indefinitely. Improvements: user-visible
"connection lost, resuming…" feedback in tsh during detach (mosh-style); log give-up causes at
warning level; consider a lightweight transport-level probe server-side.

## 4. Non-UX error-handling review items (from the same analysis)

- `connect.Connect` returns `trace.BadParameter("failed to connect to any of the database
  servers")` (`connect.go:345`) for what is an *availability* failure — the wrong trace class for
  programmatic consumers (retry logic, `isReverseTunnelDownError`-style checks elsewhere key off
  `ConnectionProblem`), and it renders as if the user misconfigured something.
- The last-resort invalid-conn selection (`local_cluster.go:939`) is **silent** — no log line or
  metric distinguishes "dialed a healthy conn" from "dialed a conn we know is unhealthy". A counter
  + debug log there would make F1/F2/F10 diagnosable from proxy telemetry alone.
- Unbounded transport channel opens (F1) are also a resource issue: each hang pins a goroutine and
  an SSH channel slot on the proxy for up to the kernel timeout.
- The blocking keepalive loops (F10) mean a single lost reply permanently silences that side's
  keepalive stream — detection then depends on a *different* mechanism noticing. A bounded
  `SendRequest` (or wantReply=false + separate reply tracking) removes the fragility.
- The 45m deferred-close depends on `activeSessions()==0` (`conn.go:217`); any leaked session
  tracker pins an unhealthy conn forever. Log signature to watch for: repeating
  `"Deferring closure of unhealthy connection due to active connections"` with a non-decreasing
  `active_conn_count` (`local_cluster.go:870`).

## 5. Unexplored failure modes (roadmap for future model extensions)

Not yet modeled — candidates for the next iteration, roughly ordered by expected yield:
1. **Stall/latency** (conn alive but slow): needs delay support in the World machine; would probe
   client-side timeout stacking (psql `connect_timeout` vs 30s IO timeouts vs patience).
2. **Session-counter leak** (see §4): model a session that never closes → verify the conn is pinned
   past 45m and dials keep selecting it.
3. **Auth/inventory outage + presence flapping** (RFD 0226 territory): registered→expired→registered
   oscillation while the tunnel stays up; interacts with F6's misleading errors.
4. **Resumption replay-buffer overflow**: bounded-buffer model variant to reach the
   `"got incompatible resume position"` desync (`resumable.go:203`) legitimately.
5. **Resumption handover** across agent graceful restart (unix-socket path, `handover.go`) and
   **IP roaming** (`badAddress` rejection on NAT change, `server_exchange.go:183`).
6. **Thundering herd**: N clients dialing during/after tunnel recovery; interaction with backoff.
7. **Proxy hard crash** (state wipe + all conns RST) vs the modeled graceful drain.
8. **Kube HTTP/2 GOAWAY handling** (`forwarder.go:775` mentions 429+Retry-After) — different
   error-propagation channel than the ones modeled.

## 6. Client / resource type coverage

Tunnel types the proxy accepts (`lib/reversetunnel/srv.go:819-883`): node(ssh), app, kube, db,
windows_desktop, linux_desktop, okta, proxy(leaf). Additional dial paths: git servers
(`local_cluster.go:386`), EICE/AWS (`local_cluster.go:635`), integration-credential apps (in-proc
`net.Pipe`, `lib/web/app/transport.go:368-384`).

| Type | Tunnel layers (L4/L5) | Client kind in model | Proxy-side failure rendering |
|---|---|---|---|
| db postgres/mysql/sqlserver | modeled | `AK_DB_PG` | error frame w/ cause ✅ |
| db mongo/redis/other TLS | modeled (same) | `AK_DB_MONGO` | bare close ❌ (F4) |
| kube | modeled (same; listener adapter) | `AK_KUBE` | metav1.Status w/ cause ✅ |
| app / okta | modeled (same) | `AK_APP` | generic 500 ⚠️ (F4b) |
| ssh node | modeled (+ resumption pair) | `AK_SSH` | attributed via SSH ✅ |
| windows/linux desktop | same tunnel layers as kube (adapter, `agentpool.go:980`) | not modeled as client | TDP/web-UI rendering unverified |
| git, EICE, integration apps, leaf clusters, relay (RFD 0213) | not modeled | — | — |

## 7. Model fidelity caveats

**Wave-2 fidelity correction**: `eNetClose` originally marked blackholed conns `CLOSED`, letting the
peer's next write error — but a FIN dropped by a blackhole is invisible and the peer's writes keep
buffering silently. Fixed (close on a dead conn now changes nothing observable); this correction is
what exposed F13, and it makes the F9 note (server-side resumption never reaps silently-dead
transports) hold in the model as well.
- Message latency is 0 relative to timers (time advances only at quiescence); realistic for
  LAN/WAN latencies vs. multi-second timers, but sub-second races are out of scope.
- Backoff simplified to its 8s worst case; agent watchdog armed at connect (real: first KA success);
  the agent-side 30s dial-request timeout is not modeled (dial requests are consumed atomically).
- Kernel TCP give-up (~15m) is not modeled; hangs are bounded by a 60s "user patience" timer —
  the real hang in F1 can be *longer* than the model shows.
- Resumption models frames (not bytes) with an unbounded replay buffer, so the 2 MiB-overflow desync
  (`"got incompatible resume position"`, `resumable.go:203`) is intentionally unreachable; it would
  need a bounded-buffer variant to explore.
- Single proxy, single agent, one tunnel type at a time; proxy peering, leaf clusters, vnet excluded.

## 8. Reproducing
```
dotnet tool install --global P            # P 3.1.0
cd model/ && p compile
p check -tc tcDialDuringBlackhole -s 300  # counterexample trace in PCheckerOutput/
p check --list-tests                      # all 12 tests
```
`TeleportTunnel.pproj`:
```xml
<Project>
  <ProjectName>TeleportTunnel</ProjectName>
  <InputFiles><PFile>./TeleportTunnel.p</PFile></InputFiles>
  <OutputDir>./PGenerated</OutputDir>
</Project>
```
