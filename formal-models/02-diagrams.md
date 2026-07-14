# Teleport Agent Tunnel — Diagram Sources (Mermaid)

Render locally (`mmdc -i 02-diagrams.md`, VS Code Mermaid preview, or paste into GitHub —
GitHub renders ```mermaid fences natively, so these drop straight into issues/PRs).
Citations match `01-tunnel-state-model.md`.

## 1. Layer map — `tsh db connect`

```mermaid
flowchart LR
    subgraph user["user's machine"]
        A[psql / mysql client] -->|plaintext TCP 127.0.0.1| B["tsh LocalProxy<br/>lib/srv/alpnproxy/local_proxy.go"]
    end
    B -->|"TLS + ALPN teleport-postgres"| C["ALPN router<br/>lib/srv/alpnproxy/proxy.go"]
    subgraph proxy["Teleport Proxy"]
        C --> D["db.ProxyServer<br/>lib/srv/db/proxyserver.go"]
        D --> E["reversetunnel localCluster<br/>lib/reversetunnel/local_cluster.go"]
    end
    E ==>|"SSH channel teleport-transport<br/>over agent-dialed tunnel"| F["AgentPool.handleLocalTransport<br/>lib/reversetunnel/agentpool.go:695"]
    subgraph agent["db agent"]
        F --> G["db Server + engine<br/>lib/srv/db/server.go:1161"]
    end
    G -->|TCP/TLS| H[(Database)]
    F -.->|"tunnel dialed agent→proxy<br/>lib/reversetunnel/agent.go"| E
```

## 2. Agent tunnel state machine (`lib/reversetunnel/agent.go:50-62`)

```mermaid
stateDiagram-v2
    [*] --> Initial
    Initial --> Connecting : Start() — agent.go#58;344
    Connecting --> Connected : dial + lease claim + first heartbeat + 4 workers up — agent.go#58;358‑398
    Connecting --> Closed : dial/handshake error — agentpool.go#58;287
    Connected --> Closed : Stop()
    Closed --> [*]

    note right of Connected
        Stop() triggers (any → Closed):
        • worker goroutine exits on conn error (agent.go#58;364‑395)
        • keepalive send fails (agent.go#58;667)
        • heartbeat ping send fails (agent.go#58;576)
        • watchdog: 15m read silence (agent.go#58;695, timeout.go)
        • reconnect advisory from proxy (agent.go#58;525)
    end note

    note right of Closed
        no explicit Draining state —
        drain phase inside Stop():
        new transports rejected
        "agent connection is draining"
        (agent.go#58;591‑597), in‑flight ones finish
    end note

    state "Pool backoff loop (agentpool.go#58;279‑307)" as pool
    Closed --> pool : pool removes agent
    pool --> Initial : new agent after linear backoff 1s→8s (agentpool.go#58;61,200)
```

## 3. Proxy-side `remoteConn` lifecycle (`lib/reversetunnel/conn.go`, `local_cluster.go`)

```mermaid
stateDiagram-v2
    [*] --> NotReady : addConn on new tunnel — local_cluster.go#58;753
    NotReady --> ReadyValid : first heartbeat ping
    ReadyValid --> ReadyValid : ping every 5m → reset 15m timer (local_cluster.go#58;837‑861)
    ReadyValid --> ReadyInvalid : offlineThreshold 15m, no ping →<br/>"Unhealthy reverse tunnel connection" (conn.go#58;194)
    ReadyInvalid --> ReadyValid : ping received → markValid
    ReadyInvalid --> ClosedRemoved : 45m AND activeSessions==0 →<br/>"Closing unhealthy and idle connection" (local_cluster.go#58;867)
    ReadyInvalid --> ReadyInvalid : 45m but sessions active →<br/>"Deferring closure…" (local_cluster.go#58;870)
    ReadyValid --> ClosedRemoved : heartbeat channel closes →<br/>"Agent disconnected" (local_cluster.go#58;838)
    ReadyInvalid --> ClosedRemoved : transport channel‑open error, idle →<br/>removed immediately (local_cluster.go#58;952‑959)
    ClosedRemoved --> [*]

    note right of ReadyInvalid
        DIAL SELECTION (getRemoteConn,
        local_cluster.go#58;905‑945):
        newest ReadyValid preferred, but if none,
        newest ReadyInvalid is returned as a
        LAST RESORT — dials can still be routed
        into a dead connection (finding F2)
    end note
```

## 4. Keepalive flows on an established tunnel

```mermaid
sequenceDiagram
    participant A as Agent
    participant P as Proxy
    Note over A,P: three independent mechanisms (defaults)
    loop every ~5m jittered (agent.go:664)
        A->>P: keepalive@openssh.com (wantReply) — agent.go:663
        P-->>A: reply (srv.go:429) — pets agent watchdog, updates SRTT
    end
    loop every 5m (agent.go:553)
        A->>P: "ping" on teleport-heartbeat (no reply) — agent.go:449
        Note right of P: resets per-conn offlineThreshold timer (15m)<br/>markValid (local_cluster.go:837-861)
    end
    loop every 5m HARDCODED = 15m/3 (sshutils/server.go:583)
        P->>A: keepalive@openssh.com — sshutils/server.go:702
        A-->>P: reply (agent.go:538)
        Note left of A: any read pets the 15m read-watchdog<br/>(interval×count, agent.go:695; timeout.go:115)
    end
```

## 5. Silent blackhole timeline (defaults; model-verified in `tcSilentDropIdle` / `tcDialDuringBlackhole`)

```mermaid
gantt
    title Tunnel TCP conn silently blackholed at t=100s
    dateFormat X
    axisFormat %s
    section Agent
    keepalives+pings vanish into kernel buffers  :active, 100, 1000
    watchdog fires (last read +900s), conn closed :milestone, 1000, 0
    backoff + redial + register                   :done, 1000, 1010
    section Proxy
    conn still VALID and selectable for dials     :crit, 100, 1000
    markInvalid "no heartbeats for 15m"           :milestone, 1000, 0
    invalid but still last-resort selectable      :active, 1000, 2800
    hard close at 45m if no active sessions       :milestone, 2800, 0
    section Client (dials in the window)
    dial hangs — transport open into dead TCP     :crit, 110, 1000
```

## 6. Resumption (ssh only) — client driver & server hold (`lib/resumption`)

```mermaid
stateDiagram-v2
    state "ResClient (tsh) — client.go:179-272" as C {
        [*] --> Attached_c : initial dial + ECDH token
        Attached_c --> Reconnecting : transport lost (detached chan closes)
        Attached_c --> Attached_c : proactive replacement every 3m (client.go#58;40,194)
        Reconnecting --> Attached_c : redial via proxy by hostID,<br/>position handshake + replay (resumable.go#58;175‑213)
        Reconnecting --> GaveUp : 1m deadline (client.go#58;42) /<br/>notFound / badAddress / expired cert (client.go#58;315‑389)
        GaveUp --> [*]
    }
    state "ResServer (node) — server_detect.go:105-128" as S {
        [*] --> Running : transport attached (running>0)
        Running --> DetachedHold : transport ERRORS →<br/>arm detachedTimeout 1m (server_detect.go#58;121)
        DetachedHold --> Running : new transport attaches (timer stopped)
        DetachedHold --> Dropped : 1m expires → conn closed (server_exchange.go#58;109)
        Running --> Running : transport silently dead —<br/>timer NEVER armed (running stays >0)
        Dropped --> [*]
    }
```

## 7. Error propagation by client protocol (proxy-originated failures; model tests `tcAgentGone*`)

```mermaid
flowchart TD
    X["proxy-side failure<br/>(agent offline / presence expired / authz)"] --> PG["postgres / mysql / sqlserver"]
    X --> KU[kubectl]
    X --> SSHC[tsh ssh]
    X --> AP["app (browser)"]
    X --> MG["mongo / redis / other generic-TLS DB"]
    PG -->|"protocol error frame WITH cause<br/>postgres/proxy.go:69, mysql/proxy.go:88"| PGok["✅ attributed"]
    KU -->|"metav1.Status JSON with message<br/>kube/proxy/forwarder.go:763-778"| KUok["✅ attributed"]
    SSHC -->|error via SSH handshake| SSHok["✅ attributed"]
    AP -->|"retry once, then generic 500 / launcher redirect<br/>web/app/handler.go:317-336"| APbad["⚠️ error, but cause omitted (finding F4b)"]
    MG -->|"conn closed, nothing sent<br/>db/proxyserver.go:289-347"| MGbad["❌ bare close (finding F4)"]
```
