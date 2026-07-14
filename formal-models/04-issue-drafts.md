# Issue Drafts — Generated from the Tunnel Model

**Provenance (keep this section when filing, or link to it)**: these drafts were synthesized from a
model-checked P model of the tunnel stack (`TeleportTunnel.p`, tests named per draft) plus direct code
reading at `master` `67276143`. They were **not** captured on a live cluster. Everything in quotes —
user-facing errors, log message strings — is the exact string from the cited source line. Timestamps,
hostnames, and slog field ordering in the "log excerpt" blocks are illustrative reconstructions of what
those lines render as; validate once on a live/test cluster before filing externally. Repro steps are
real and should reproduce as written.

---

## Draft 1 — model test `tcDialDuringBlackhole` (finding F1)

**Title**: `db access: client connections hang with no error (and nothing logged) when an agent's reverse tunnel dies silently, for up to 15 minutes`

**Labels**: `bug` `ux` `database-access` `reversetunnel`

### Environment
- Teleport v19 (also reproduces conceptually on v15+; timers unchanged)
- db agent joined via reverse tunnel, TLS routing (multiplex), behind a load balancer /
  stateful firewall that expires idle flows **without sending RST** (e.g. AWS NLB 350s idle,
  many corporate firewalls)
- defaults: `keepalive_interval` 5m, `keepalive_count_max` 3

### Steps to reproduce
1. Register a database via a tunnel-mode `db_service` agent whose tunnel TCP connection passes
   through a middlebox that silently drops idle flow state (or simulate: `iptables -A ... -j DROP`
   on the established tunnel conn — do **not** use `-j REJECT --reject-with tcp-reset`).
2. Leave the cluster idle so the flow is purged (with defaults the tunnel can be byte-idle for up
   to ~5m between keepalives — longer than most LB idle timeouts).
3. `tsh db connect mydb` (or connect any client through an existing `tsh proxy db --tunnel`).

### Expected
A prompt, attributed error — e.g. the message the proxy already has for this situation:
> `Teleport proxy failed to connect to "db" agent "<host-id>" over reverse tunnel: ... This usually means that the agent is offline or has disconnected` (`lib/reversetunnel/local_cluster.go:592`)

### Actual
The client hangs indefinitely (psql sits silently at startup; with `connect_timeout` set it
eventually prints `psql: error: connection to server at "127.0.0.1", port 55432 failed: timeout
expired`). Ctrl-C is the realistic outcome. **Nothing** is logged at dial time on tsh, proxy, or
agent above debug level; the first system-side evidence appears ~15 minutes after the fault:

```
# proxy (illustrative rendering; message strings exact)
17:20:00.101 DEBU [TUNNEL] Tunnel dialing to host …            reversetunnel/local_cluster.go:524
        … 15 minutes of nothing …
17:34:55.480 ERRO [TUNNEL] Unhealthy reverse tunnel connection cluster:example.com error:"no heartbeats for 15m0s"   reversetunnel/conn.go:194

# agent, at the same ~15m mark (watchdog closes the conn, agent reconnects in seconds)
17:34:58.012 WARN [DB:AGNT] Failed to send keepalive request error:"use of closed network connection"   reversetunnel/agent.go:667
17:34:58.013 DEBU [DB:AGNT] Agent state updated previous_state:connected current_state:closed           reversetunnel/agent.go:317
17:35:06.220 INFO [DB:AGNT] Keepalive successful, arming watchdog timeout:15m0s                          reversetunnel/agent.go:697
```

### Root cause (from model + code)
1. After a silent drop, the proxy's `remoteConn` remains **valid** until the 15m `offlineThreshold`
   (`srv.go:340`, `local_cluster.go:862`) — `getRemoteConn` selects it for new dials
   (`local_cluster.go:905-945`).
2. The transport channel open (`chanTransportConn` → `sshutils.ConnectProxyTransport`,
   `local_cluster.go:947`, `api/utils/sshutils/conn.go:37`) has **no timeout** — it blocks on the
   dead TCP conn until kernel retransmission gives up (~15m). The agent-side 30s guard
   (`agentpool.go:705`) never runs; the dial request never arrived.
3. Even after `markInvalid` at 15m, `getRemoteConn` returns the invalid conn as a *last resort*
   (`local_cluster.go:934-939`) — correct for fast-fail conns, but for blackholed conns it extends
   the hang window toward the 45m hard close (`local_cluster.go:61,866`).

Model-checked timeline (fault t=100s): proxy conn valid+selectable 100→1000s; dials at any point in
that window hang with **no cause known anywhere in the system**; agent watchdog closes at t=1000s,
new tunnel at t≈1008s.

### Suggested fix directions
- Bound the transport channel open with a deadline at the proxy; on expiry `markInvalid` and either
  retry the next-newest conn or fail fast with the existing offline message.
- Only use invalid conns as last resort when their `lastError` class is fast-fail.
- Enable aggressive TCP keepalives on tunnel conns so the kernel surfaces dead peers in seconds.

---

## Draft 2 — model tests `tcAgentGoneMongo`, `tcAgentGoneApp` (findings F4/F4b)

**Title**: `MongoDB/Redis/etc. clients get unexplained disconnects for every proxy-side failure; app access gets a cause-less 500 — while postgres/mysql/kubectl users get real error messages`

**Labels**: `ux` `database-access` `application-access`

### Steps to reproduce
1. Register a mongo database via a tunnel-mode `db_service`; stop the agent (or kill its tunnel).
2. `tsh db connect mongo-db` / connect `mongosh` through `tsh proxy db --tunnel`.
3. For contrast, repeat with a postgres database and with a kube cluster / web app.

### Expected
What postgres users get in psql for the same failure:
> `failed to connect to any of the database servers` (`lib/srv/db/common/connect/connect.go:345`)

and kubectl users get via `metav1.Status` (`lib/kube/proxy/forwarder.go:763-778`).

### Actual
- **mongosh**: `MongoNetworkError: connection 1 to 127.0.0.1:27017 closed` — nothing else.
  The proxy has no protocol handler for generic-TLS DB protocols; `ProxyServer.handleConnection`
  returns the error internally and the conn is just closed (`lib/srv/db/proxyserver.go:289-347`).
  Only postgres/mysql/sqlserver have error-frame-capable proxies registered
  (`lib/service/service.go:6296-6306`; frames sent at `postgres/proxy.go:69`, `mysql/proxy.go:88`).
- **browser (app access)**: on a tunnel `ConnectionProblem` the handler retries once through a
  renewed session, then renders a generic `500 Internal Server Error` or a redirect to the launcher
  (`lib/web/app/handler.go:317-336`) — the cause string (`NoApplicationTunnel`,
  `lib/reversetunnelclient/api.go:187`) is only in proxy logs.

The informative messages exist in both cases — they are logged proxy-side and discarded
client-side. Users file "flaky database" tickets; operators must correlate proxy debug logs by
timestamp to answer them.

### Suggested fix directions
- Reuse the per-protocol `SendError` codecs that the **agent engines already implement** for every
  supported protocol (`lib/srv/db/server.go:1241-1249` proves each engine can render errors) at the
  proxy layer, so proxy-originated failures get the same treatment as engine failures.
- App access: include a short cause ("application service agent is offline") in the 500 body /
  launcher redirect.

---

## Draft 3 — model test `tcCertReissueFail` (finding F5)

**Title**: `tsh proxy db --tunnel: database clients see a bare disconnect when per-session cert re-issue fails (expired session / MFA); cause only visible in tsh's stderr`

**Labels**: `ux` `tsh` `database-access`

### Steps to reproduce
1. `tsh proxy db --tunnel mydb --port 55432` in terminal A; connect a GUI client or psql from
   terminal B — works.
2. Let the Teleport session expire (or revoke it), then have the client reconnect.

### Expected
The database client receives an actionable error — e.g. a postgres `ErrorResponse` saying
`teleport: session expired, run "tsh login"` — since tsh knows the protocol and the cause.

### Actual
- Client: `psql: error: connection to server at "127.0.0.1", port 55432 failed: server closed the
  connection unexpectedly` (GUI clients show their generic equivalent).
- Terminal A (tsh) is the only place the cause exists:
  `"Middleware failed to handle client connection"` (`lib/srv/alpnproxy/local_proxy.go:206`) —
  the middleware is `CertChecker.OnNewConnection` → `GetOrIssueCert`
  (`lib/client/local_proxy_middleware.go:115-171`); on failure the accepted loopback conn is closed
  and the accept loop continues (`local_proxy.go:207-210`). No bytes are ever written to the client.

For `tsh db connect` the tsh output shares the user's terminal, which mitigates this; for
long-running `tsh proxy db --tunnel` (the documented GUI-client workflow) the client-side experience
is an unexplained refusal that tends to get blamed on the database or the GUI tool.

### Suggested fix directions
- tsh knows the negotiated protocol: synthesize a protocol-native error frame before closing
  (postgres/mysql at minimum), mirroring what the proxy does at `postgres/proxy.go:69`.
- Alternatively surface a desktop notification / clearer stderr line including the remediation
  (`tsh login`), and document the behavior.

---

*Generated from the Teleport tunnel P model (`p check -tc <test>` counterexamples) + source reading at
commit `67276143`. Quoted strings are exact per the inline citations; log excerpt formatting is
illustrative. Validate on a live cluster before external filing.*
