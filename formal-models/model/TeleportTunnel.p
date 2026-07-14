// =============================================================================
// TeleportTunnel.p — P model of Teleport agent tunnel mode (reverse tunnel)
//
// Source of truth: gravitational/teleport @ master 67276143 (v19.0.0-prealpha.2)
// Companion document: 01-tunnel-state-model.md (same citations, prose form).
//
// Modeling approach:
//  * World = discrete-event simulator: logical clock (seconds) + network.
//    Time advances ONLY at quiescence (no undelivered messages), so message
//    latency is treated as 0 relative to timer scales (real latencies are
//    milliseconds vs. timers of seconds..minutes). Every World-delivered
//    event must be ACKed by its recipient exactly once.
//  * Each TCP connection is a World record with a fault state:
//      CS_ALIVE      normal
//      CS_BLACKHOLE  silent drop (LB idle purge without RST): sends vanish,
//                    NO ONE is notified  -> only timers can detect
//      CS_RESET      RST injected: BOTH endpoints get an immediate error
//                    (kernel wakes blocked reads with ECONNRESET)
//      CS_CLOSED     orderly FIN by one endpoint: peer gets EOF
//  * Timer constants mirror the defaults cited in 01-tunnel-state-model.md §7.
//
// Real-code anchors are cited as   // => file:line   throughout.
// =============================================================================

// ------------------------------- enums / types ------------------------------

enum tConnState {
  CS_ALIVE,      // normal
  CS_BLACKHOLE,  // silent drop, both directions
  CS_BH_A2B,     // one-way loss: dialer->accepter dropped (other dir works)
  CS_BH_B2A,     // one-way loss: accepter->dialer dropped
  CS_RESET,      // RST: both endpoints error on next op
  CS_HUNG_OPEN,  // TCP accept done, peer kernel ACKs, application never answers
                 // (wedged LB backend / unhealthy proxy still in rotation)
  CS_CLOSED
}

// health of a dial TARGET, applied at eNetOpen time
enum tEpState {
  EP_OK,
  EP_REFUSE,            // immediate connection refused
  EP_ACCEPT_HANG,       // accepts, ACKs everything, never completes handshake
  EP_ACCEPT_BLACKHOLE   // SYN/ClientHello vanish: dialer errors only when the
                        // kernel gives up retransmitting (~tcp_retries2)
}

enum tAgentKind { AK_SSH, AK_DB_PG, AK_DB_MONGO, AK_APP, AK_KUBE }

enum tMsgKind {
  MSG_REGISTER,        // agent->proxy: SSH handshake + heartbeat chan + first ping
                       // => lib/reversetunnel/agent.go:438,455-472 (sendFirstHeartbeat)
  MSG_PING,            // agent->proxy: "ping" on teleport-heartbeat, every 5m
                       // => agent.go:553,572-580
  MSG_KA_REQ,          // keepalive@openssh.com, both directions
                       // => agent.go:663 (agent), lib/sshutils/server.go:702 (proxy)
  MSG_KA_REPLY,        //
  MSG_RECONNECT,       // proxy->agent: reconnect@goteleport.com drain advisory
                       // => agent.go:525-536, conn.go:264
  MSG_TRANSPORT_DIAL,  // proxy->agent: chan teleport-transport + dial req
                       // => api/utils/sshutils/conn.go:37-59, agentpool.go:695
  MSG_TRANSPORT_OK,    // agent->proxy: dial req accepted -> service handoff
  MSG_TRANSPORT_ERR,   // agent->proxy: rejected (draining) => agent.go:591-597
  MSG_HELLO,           // client->proxy (via localproxy): new user session
  MSG_APP_DATA,        // user payload (echoed by agent if target up)
  MSG_APP_ERRFRAME     // protocol-native error frame (engine.SendError or
                       // proxy-side postgres/mysql error) => lib/srv/db/server.go:1241
}

enum tCause {
  RC_NONE,
  RC_TARGET_DOWN,        // real database refused => lib/srv/db/common/errors.go:161
  RC_TUNNEL_DOWN,        // no usable reverse tunnel => local_cluster.go:917,:944
  RC_PRESENCE_EXPIRED,   // backend record gone => connect/connect.go:82
  RC_CERT_FAIL,          // local proxy middleware failure => local_proxy.go:206-210
  RC_DRAINING,           // agent draining => agent.go:591-597
  RC_FAULT               // injected network fault (ground truth marker)
}

enum tObs {
  OBS_SUCCESS,      // end user's client completed its query
  OBS_PROTO_ERR,    // client got a protocol-native error frame w/ a cause
  OBS_GENERIC_ERR,  // client got *an* error but with no cause attached
                    // (e.g. app access generic 500 => lib/web/app/handler.go:334)
  OBS_BARE_CLOSE,   // connection closed with no explanation
  OBS_HANG          // nothing happened until the user's patience ran out
}

type tMsg = (k: tMsgKind, ch: int, kd: tAgentKind, cause: tCause);

type tTimerRec = (owner: machine, tid: int, gen: int, deadline: int);
type tConnRec  = (epA: machine, epB: machine, st: tConnState, tag: int);

// conn tags (which cable the fault injector grabs)
// TAG_TUNNEL: agent->proxy reverse tunnel TCP conn
// TAG_C2L: db client -> tsh local proxy loopback conn
// TAG_L2P: tsh local proxy -> teleport proxy TLS conn
// TAG_RES: resumption transport (ssh tests)

// ------------------------------- World events -------------------------------

event eSetTimer   : (owner: machine, tid: int, gen: int, delay: int);
event eTimerFired : (tid: int, gen: int, now: int);          // ACK required
event eNetOpen    : (src: machine, dst: machine, tag: int);
event eNetOpened  : (cid: int, tag: int, peer: machine);     // ACK required
event eNetAccept  : (cid: int, tag: int, peer: machine);     // ACK required
event eNetSend    : (cid: int, src: machine, msg: tMsg);
event eNetDeliver : (cid: int, msg: tMsg);                   // ACK required
event eNetError   : (cid: int);                              // ACK required
event eNetEof     : (cid: int);                              // ACK required
event eNetClose   : (cid: int, src: machine);
event eInjectTag  : (tag: int, st: tConnState);
event eSetEpHealth: (ep: machine, st: tEpState);
event eSetLb      : (ep: machine, backends: seq[tEpState]); // per-dial choose = LB rotation
event eEnvSend    : (target: machine, cmd: int, flag: bool);
event eEnvCmd     : (cmd: int, flag: bool);                  // ACK required
event eAck;
event eKick;

// env command codes (driver -> machines through World)
// 1=BOOT  2=SET_TARGET(flag)  3=SET_PRESENCE(flag)  4=STOP_AGENT
// 5=CLIENT_CONNECT  6=ADVISE_RECONNECT  7=PUMP_APP_DATA

// ---------------------------- spec (announce) events -------------------------

event eObs        : (obs: tObs, cause: tCause);
event eCause      : (cause: tCause, layer: int);
event eTunnelUp;
event eTunnelDownA;
event eFaultInjected;
event eResDelivered : (dir: int, sqn: int);   // resumption stream integrity
event eResClosed;
event eDialStart;     // a user-facing component began an upstream dial
event eDialEnd;       // ... and it resolved (opened or errored)
event eDialOverdue;   // ... still unresolved after 60s (observational)
event eGroundTruth : bool;   // fault-injector truth: auth/control-plane outage

// ------------------------------ timing constants ----------------------------
// (functions because P has no top-level consts)

fun KEEPALIVE_IVL(): int      { return 300;  }  // => api/defaults/defaults.go:98
fun WATCHDOG(): int           { return 900;  }  // interval*count => agent.go:695
fun PROXY_KA_IVL(): int       { return 300;  }  // 15m/3 HARDCODED => sshutils/server.go:583
fun OFFLINE_THRESHOLD(): int  { return 900;  }  // => srv.go:340
fun MISSED_HB_MAX(): int      { return 3;    }  // hard close at 3x => local_cluster.go:61
fun BACKOFF(): int            { return 8;    }  // linear 1..8s; worst case => agentpool.go:61
fun PATIENCE(): int           { return 60;   }  // human gives up / client tool timeout
fun RES_REPLACEMENT(): int    { return 180;  }  // => resumption/client.go:40
fun RES_RECONNECT_MAX(): int  { return 60;   }  // => resumption/client.go:42
fun RES_DETACHED_HOLD(): int  { return 60;   }  // => resumption/server_detect.go:46
fun RES_BACKOFF_STEP(): int   { return 10;   }  // capped max => client.go:45
fun KERNEL_RETRANS(): int     { return 924;  }  // Linux tcp_retries2 connect give-up
fun DIAL_TIMEOUT(): int       { return 30;   }  // DefaultIOTimeout => api/defaults/defaults.go:33

// =============================================================================
// World: logical clock + network + fault injection
// =============================================================================

machine World {
  var now: int;
  var horizon: int;
  var busyCount: int;
  var timers: seq[tTimerRec];
  var conns: map[int, tConnRec];
  var nextCid: int;
  var epHealth: map[machine, tEpState];
  var lb: map[machine, seq[tEpState]];
  var dialPending: map[int, bool];   // blackholed dials awaiting kernel give-up

  start state Run {
    entry (h: int) {
      now = 0; horizon = h; busyCount = 0; nextCid = 1;
    }

    on eSetTimer do (p: (owner: machine, tid: int, gen: int, delay: int)) {
      timers += (sizeof(timers), (owner = p.owner, tid = p.tid, gen = p.gen, deadline = now + p.delay));
    }

    on eNetOpen do (p: (src: machine, dst: machine, tag: int)) {
      var cid: int;
      var st: tEpState;
      cid = nextCid; nextCid = nextCid + 1;
      st = EP_OK;
      if (p.dst in lb && sizeof(lb[p.dst]) > 0) { st = choose(lb[p.dst]); }
      else if (p.dst in epHealth) { st = epHealth[p.dst]; }
      if (st == EP_OK) {
        conns[cid] = (epA = p.src, epB = p.dst, st = CS_ALIVE, tag = p.tag);
        busyCount = busyCount + 2;
        send p.src, eNetOpened, (cid = cid, tag = p.tag, peer = p.dst);
        send p.dst, eNetAccept, (cid = cid, tag = p.tag, peer = p.src);
        return;
      }
      if (st == EP_REFUSE) {
        conns[cid] = (epA = p.src, epB = p.dst, st = CS_CLOSED, tag = p.tag);
        busyCount = busyCount + 1;
        send p.src, eNetError, (cid = cid,);
        return;
      }
      if (st == EP_ACCEPT_HANG) {
        // wedged forever: nothing is ever delivered to either side, and the
        // peer kernel ACKs, so no error ever surfaces to the dialer
        conns[cid] = (epA = p.src, epB = p.dst, st = CS_HUNG_OPEN, tag = p.tag);
        return;
      }
      // EP_ACCEPT_BLACKHOLE: dialer errors only at kernel retransmit give-up
      conns[cid] = (epA = p.src, epB = p.dst, st = CS_BLACKHOLE, tag = p.tag);
      dialPending[cid] = true;
      timers += (sizeof(timers), (owner = this, tid = cid, gen = 0, deadline = now + KERNEL_RETRANS()));
    }

    on eSetEpHealth do (p: (ep: machine, st: tEpState)) {
      epHealth[p.ep] = p.st;
    }
    on eSetLb do (p: (ep: machine, backends: seq[tEpState])) {
      lb[p.ep] = p.backends;
    }

    on eNetSend do (p: (cid: int, src: machine, msg: tMsg)) {
      var c: tConnRec;
      var dropped: bool;
      if (!(p.cid in conns)) { return; }
      c = conns[p.cid];
      if (c.st == CS_RESET || c.st == CS_CLOSED) {
        // next op errors for the operator
        busyCount = busyCount + 1;
        send p.src, eNetError, (cid = p.cid,);
        return;
      }
      dropped = c.st == CS_BLACKHOLE || c.st == CS_HUNG_OPEN
        || (c.st == CS_BH_A2B && p.src == c.epA)
        || (c.st == CS_BH_B2A && p.src == c.epB);
      if (dropped) {
        // silent drop: the write "succeeds" into kernel buffers; nobody learns anything
        return;
      }
      busyCount = busyCount + 1;
      if (p.src == c.epA) { send c.epB, eNetDeliver, (cid = p.cid, msg = p.msg); }
      else                { send c.epA, eNetDeliver, (cid = p.cid, msg = p.msg); }
    }

    on eNetClose do (p: (cid: int, src: machine)) {
      var c: tConnRec;
      if (!(p.cid in conns)) { return; }
      c = conns[p.cid];
      if (c.st == CS_ALIVE
          || (c.st == CS_BH_A2B && p.src == c.epB)
          || (c.st == CS_BH_B2A && p.src == c.epA)) {
        busyCount = busyCount + 1;
        if (p.src == c.epA) { send c.epB, eNetEof, (cid = p.cid,); }
        else                { send c.epA, eNetEof, (cid = p.cid,); }
        conns[p.cid] = (epA = c.epA, epB = c.epB, st = CS_CLOSED, tag = c.tag);
        return;
      }
      if (c.st == CS_RESET || c.st == CS_CLOSED) {
        conns[p.cid] = (epA = c.epA, epB = c.epB, st = CS_CLOSED, tag = c.tag);
        return;
      }
      // FIN into a blackhole / hung conn / the dead direction of a one-way
      // loss is DROPPED: the peer cannot tell the closer is gone, and the
      // peer's own writes keep vanishing into buffers instead of erroring.
      // Do NOT change the conn state — the close is invisible on the wire.
    }

    on eInjectTag do (p: (tag: int, st: tConnState)) {
      var cid: int;
      var c: tConnRec;
      var ks: seq[int];
      var i: int;
      ks = keys(conns);
      i = 0;
      announce eFaultInjected;
      while (i < sizeof(ks)) {
        cid = ks[i];
        c = conns[cid];
        if (c.tag == p.tag && (c.st == CS_ALIVE || c.st == CS_BLACKHOLE)) {
          conns[cid] = (epA = c.epA, epB = c.epB, st = p.st, tag = c.tag);
          if (p.st == CS_RESET) {
            // RST wakes both kernels immediately
            busyCount = busyCount + 2;
            send c.epA, eNetError, (cid = cid,);
            send c.epB, eNetError, (cid = cid,);
          }
        }
        i = i + 1;
      }
    }

    on eEnvSend do (p: (target: machine, cmd: int, flag: bool)) {
      busyCount = busyCount + 1;
      send p.target, eEnvCmd, (cmd = p.cmd, flag = p.flag);
    }

    on eAck do {
      busyCount = busyCount - 1;
      if (busyCount == 0) { advanceTime(); }
    }

    on eKick do {
      if (busyCount == 0) { advanceTime(); }
    }
  }

  // fire the earliest pending timer (nondeterministic tie-break)
  fun advanceTime() {
    var i: int;
    var best: int;
    var cand: seq[int];
    var t: tTimerRec;
    var emptyCand: seq[int];
    while (true) {
      if (sizeof(timers) == 0) { return; }
      best = -1;
      i = 0;
      while (i < sizeof(timers)) {
        if (best == -1 || timers[i].deadline < timers[best].deadline) { best = i; }
        i = i + 1;
      }
      cand = emptyCand;
      i = 0;
      while (i < sizeof(timers)) {
        if (timers[i].deadline == timers[best].deadline) { cand += (sizeof(cand), i); }
        i = i + 1;
      }
      best = choose(cand);
      t = timers[best];
      timers -= (best);
      if (t.deadline > horizon) { return; }  // freeze the world at the horizon
      now = t.deadline;
      if (t.owner == this) {
        // kernel connect give-up on a blackholed dial (~tcp_retries2, 924s)
        if (t.tid in dialPending && dialPending[t.tid] && t.tid in conns && conns[t.tid].st == CS_BLACKHOLE) {
          dialPending[t.tid] = false;
          busyCount = busyCount + 1;
          send conns[t.tid].epA, eNetError, (cid = t.tid,);
          return;
        }
        continue;  // stale world timer; keep advancing
      }
      busyCount = busyCount + 1;
      send t.owner, eTimerFired, (tid = t.tid, gen = t.gen, now = now);
      return;
    }
  }
}

// =============================================================================
// Agent: reverse-tunnel agent (one agent, one proxy)
//   state machine => lib/reversetunnel/agent.go:50-62 (initial/connecting/
//   connected/closed), pool reconnect loop => agentpool.go:279-307
// =============================================================================

// timer ids
fun T_KA(): int       { return 1; }
fun T_PING(): int     { return 2; }
fun T_WD(): int       { return 3; }
fun T_BACKOFF(): int  { return 4; }
fun T_DIAL(): int     { return 5; }

machine Agent {
  var w: machine;
  var proxy: machine;
  var kind: tAgentKind;
  var targetUp: bool;
  var dialBounded: bool;   // true: dial has a 30s deadline (HTTPS_PROXY path,
                           // agent_dialer.go:68); false: ALPN-routing path where
                           // the timeout is dropped (lib/utils/proxy/proxy.go:69-73)
  var tunnelCid: int;
  var draining: bool;
  var stopped: bool;
  var gens: map[int, int];

  start state Init {
    entry (cfg: (w: machine, proxy: machine, kind: tAgentKind, targetUp: bool, dialBounded: bool)) {
      w = cfg.w; proxy = cfg.proxy; kind = cfg.kind; targetUp = cfg.targetUp;
      dialBounded = cfg.dialBounded;
      tunnelCid = -1; draining = false; stopped = false;
      gens[T_KA()] = 0; gens[T_PING()] = 0; gens[T_WD()] = 0; gens[T_BACKOFF()] = 0;
      gens[T_DIAL()] = 0;
    }
    on eEnvCmd do (p: (cmd: int, flag: bool)) {
      if (p.cmd == 1) {            // BOOT -> AgentConnecting  => agent.go:344
        goto Connecting;           // quiescence ack is sent by Connecting's entry
      }
      handleEnv(p.cmd, p.flag);
      send w, eAck;
    }
  }

  state Connecting {
    entry {
      // dial the proxy  => agent_dialer.go:65-127 (dial timeout 30s not modeled:
      // proxy endpoint always accepts; refusals modeled as immediate error)
      send w, eNetOpen, (src = this, dst = proxy, tag = 1);
      if (dialBounded) { armTimer(T_DIAL(), DIAL_TIMEOUT()); }
      send w, eAck;   // completes the causal step that brought us here
    }
    on eNetOpened do (p: (cid: int, tag: int, peer: machine)) {
      tunnelCid = p.cid;
      draining = false;
      gens[T_DIAL()] = gens[T_DIAL()] + 1;   // dial resolved
      if (stopped) {
        send w, eNetClose, (cid = tunnelCid, src = this);
        goto Stopped;
      }
      // SSH handshake + heartbeat channel + first ping  => agent.go:424-472
      send w, eNetSend, (cid = tunnelCid, src = this, msg = mkMsg(MSG_REGISTER, 0, RC_NONE));
      goto Connected;
    }
    on eNetError do (p: (cid: int)) {
      // dial/handshake failed => agentpool.go:287 "Failed to establish reverse tunnel"
      if (stopped) { goto Stopped; }
      goto Backoff;
    }
    on eEnvCmd do (p: (cmd: int, flag: bool)) { handleEnv(p.cmd, p.flag); send w, eAck; }
    on eTimerFired do (p: (tid: int, gen: int, now: int)) {
      if (p.tid == T_DIAL() && gens[T_DIAL()] == p.gen) {
        // dial deadline expired (30s) -> give up this attempt, backoff, retry
        // => agent_dialer.go:68 (only on the DialerFromEnvironment/HTTPS_PROXY path)
        if (stopped) { goto Stopped; }
        goto Backoff;
      }
      send w, eAck;
    }
    on eNetEof do (p: (cid: int)) { send w, eAck; }
    on eNetDeliver do (p: (cid: int, msg: tMsg)) { send w, eAck; }
  }

  state Connected {
    entry {
      // 4 worker goroutines up -> AgentConnected  => agent.go:358-398
      armTimer(T_KA(), KEEPALIVE_IVL());
      armTimer(T_PING(), KEEPALIVE_IVL());
      // watchdog armed after first successful keepalive; we arm at connect
      // (first KA fires immediately in the real code: timer starts at 0, agent.go:651)
      armTimer(T_WD(), WATCHDOG());       // => agent.go:695-696
      send w, eAck;
    }

    on eTimerFired do (p: (tid: int, gen: int, now: int)) {
      if (!(p.tid in gens) || gens[p.tid] != p.gen) { send w, eAck; return; } // stale
      if (p.tid == T_KA()) {
        // keepalive@openssh.com wantReply  => agent.go:663
        send w, eNetSend, (cid = tunnelCid, src = this, msg = mkMsg(MSG_KA_REQ, 0, RC_NONE));
        armTimer(T_KA(), KEEPALIVE_IVL());
        send w, eAck; return;
      }
      if (p.tid == T_PING()) {
        // "ping" on teleport-heartbeat  => agent.go:572-580 (stops while draining)
        if (!draining) {
          send w, eNetSend, (cid = tunnelCid, src = this, msg = mkMsg(MSG_PING, 0, RC_NONE));
        }
        armTimer(T_PING(), KEEPALIVE_IVL());
        send w, eAck; return;
      }
      if (p.tid == T_WD()) {
        // watchdog: no bytes read from proxy for WATCHDOG seconds -> close conn
        // => lib/utils/timeout.go:74-83; goroutines die -> Stop() -> redial
        send w, eNetClose, (cid = tunnelCid, src = this);
        goto Backoff;
      }
      send w, eAck;
    }

    on eNetDeliver do (p: (cid: int, msg: tMsg)) {
      // ANY read pets the watchdog  => timeout.go:115-123
      armTimer(T_WD(), WATCHDOG());
      if (p.msg.k == MSG_KA_REQ) {
        // reply to proxy keepalive  => agent.go:538-543
        send w, eNetSend, (cid = tunnelCid, src = this, msg = mkMsg(MSG_KA_REPLY, 0, RC_NONE));
        send w, eAck; return;
      }
      if (p.msg.k == MSG_KA_REPLY) { send w, eAck; return; }
      if (p.msg.k == MSG_RECONNECT) {
        // drain advisory  => agent.go:525-536: Stop() -> drain -> close -> redial
        draining = true;
        send w, eNetClose, (cid = tunnelCid, src = this);
        goto Backoff;
      }
      if (p.msg.k == MSG_TRANSPORT_DIAL) {
        if (draining) {
          // => agent.go:591-597 "agent connection is draining"
          announce eCause, (cause = RC_DRAINING, layer = 5);
          send w, eNetSend, (cid = tunnelCid, src = this, msg = mkMsg(MSG_TRANSPORT_ERR, p.msg.ch, RC_DRAINING));
          send w, eAck; return;
        }
        // handleLocalTransport replies true then hands the conn to the local
        // service => agentpool.go:726-745. Engine failures are APP_ERRFRAMEs.
        send w, eNetSend, (cid = tunnelCid, src = this, msg = mkMsg(MSG_TRANSPORT_OK, p.msg.ch, RC_NONE));
        if (!targetUp) {
          // engine dials the real database and fails; deferred engine.SendError
          // writes a protocol-native frame  => lib/srv/db/server.go:1241-1249
          announce eCause, (cause = RC_TARGET_DOWN, layer = 6);
          send w, eNetSend, (cid = tunnelCid, src = this, msg = mkMsg(MSG_APP_ERRFRAME, p.msg.ch, RC_TARGET_DOWN));
        }
        send w, eAck; return;
      }
      if (p.msg.k == MSG_APP_DATA) {
        if (targetUp) {
          send w, eNetSend, (cid = tunnelCid, src = this, msg = mkMsg(MSG_APP_DATA, p.msg.ch, RC_NONE));
        }
        send w, eAck; return;
      }
      send w, eAck;
    }

    on eNetError do (p: (cid: int)) {
      // conn died (RST etc.): goroutine errors -> Stop()  => agent.go:364-395
      goto Backoff;
    }
    on eNetEof do (p: (cid: int)) {
      goto Backoff;
    }
    on eEnvCmd do (p: (cmd: int, flag: bool)) {
      if (p.cmd == 4) {  // STOP_AGENT (clean shutdown)
        stopped = true;
        send w, eNetClose, (cid = tunnelCid, src = this);
        goto Stopped;
      }
      handleEnv(p.cmd, p.flag);
      send w, eAck;
    }
    on eNetOpened do (p: (cid: int, tag: int, peer: machine)) { send w, eAck; }
    on eNetAccept do (p: (cid: int, tag: int, peer: machine)) { send w, eAck; }
  }

  state Backoff {
    entry {
      // pool loop: waitForBackoff, linear 1..8s  => agentpool.go:508-520,:61
      bumpAllGens();
      if (stopped) { goto Stopped; }
      armTimer(T_BACKOFF(), BACKOFF());
      send w, eAck;
    }
    on eTimerFired do (p: (tid: int, gen: int, now: int)) {
      if (p.tid == T_BACKOFF() && gens[p.tid] == p.gen) {
        if (stopped) { goto Stopped; }
        goto Connecting;
      }
      send w, eAck;
    }
    on eNetDeliver do (p: (cid: int, msg: tMsg)) { send w, eAck; }
    on eNetError do (p: (cid: int)) { send w, eAck; }
    on eNetEof do (p: (cid: int)) { send w, eAck; }
    on eEnvCmd do (p: (cmd: int, flag: bool)) {
      if (p.cmd == 4) { stopped = true; goto Stopped; }
      handleEnv(p.cmd, p.flag);
      send w, eAck;
    }
  }

  state Stopped {
    entry { send w, eAck; }
    on eTimerFired do (p: (tid: int, gen: int, now: int)) { send w, eAck; }
    on eNetDeliver do (p: (cid: int, msg: tMsg)) { send w, eAck; }
    on eNetError do (p: (cid: int)) { send w, eAck; }
    on eNetEof do (p: (cid: int)) { send w, eAck; }
    on eEnvCmd do (p: (cmd: int, flag: bool)) { send w, eAck; }
  }

  fun handleEnv(cmd: int, flag: bool) {
    if (cmd == 2) { targetUp = flag; }
    if (cmd == 4) { stopped = true; }
  }

  fun armTimer(tid: int, d: int) {
    gens[tid] = gens[tid] + 1;
    send w, eSetTimer, (owner = this, tid = tid, gen = gens[tid], delay = d);
  }

  fun bumpAllGens() {
    gens[T_KA()] = gens[T_KA()] + 1;
    gens[T_PING()] = gens[T_PING()] + 1;
    gens[T_WD()] = gens[T_WD()] + 1;
    gens[T_BACKOFF()] = gens[T_BACKOFF()] + 1;
    gens[T_DIAL()] = gens[T_DIAL()] + 1;
  }
}

fun mkMsg(k: tMsgKind, ch: int, c: tCause): tMsg {
  return (k = k, ch = ch, kd = AK_DB_PG, cause = c);
}

fun mkMsgKd(k: tMsgKind, ch: int, kd: tAgentKind, c: tCause): tMsg {
  return (k = k, ch = ch, kd = kd, cause = c);
}

// =============================================================================
// Proxy: reverse-tunnel server + per-protocol front door
//   remoteConn registry => lib/reversetunnel/local_cluster.go, conn.go
// =============================================================================

type tRconn = (cid: int, ready: bool, invalid: bool, missed: int, sessions: int);
type tSess  = (clientCid: int, rconnCid: int, kd: tAgentKind, gotFrame: bool);

// proxy timer ids: offline threshold = 1000+cid, proxy keepalive = 2000+cid

machine Proxy {
  var w: machine;
  var rconns: map[int, tRconn];   // keyed by tunnel cid
  var order: seq[int];            // tunnel cids, oldest -> newest
  var sess: map[int, tSess];      // keyed by transport ch
  var chByClient: map[int, int];  // client cid -> ch
  var nextCh: int;
  var presenceOK: bool;
  var gens: map[int, int];
  var readyCount: int;
  var kaAwaiting: map[int, bool];   // per-conn: keepalive sent, reply not yet
                                    // received; the real SendRequest(wantReply)
                                    // BLOCKS the keepalive loop until the reply
                                    // arrives => sshutils/server.go:704

  start state Serving {
    entry (wm: machine) {
      w = wm; nextCh = 1; presenceOK = true; readyCount = 0;
    }

    on eNetAccept do (p: (cid: int, tag: int, peer: machine)) {
      if (p.tag == 1) {
        // new tunnel conn: registered but NOT ready until first heartbeat
        // => srv.go:819 "New tunnel established", local_cluster.go:753 addConn
        rconns[p.cid] = (cid = p.cid, ready = false, invalid = false, missed = 0, sessions = 0);
        order += (sizeof(order), p.cid);
        armTimer(1000 + p.cid, OFFLINE_THRESHOLD());   // => local_cluster.go:876-879
        armTimer(2000 + p.cid, PROXY_KA_IVL());        // => sshutils/server.go:583
      }
      send w, eAck;
    }

    on eNetDeliver do (p: (cid: int, msg: tMsg)) {
      var rc: tRconn;
      var s: tSess;
      if (p.cid in rconns) {
        rc = rconns[p.cid];
        if (p.msg.k == MSG_REGISTER || p.msg.k == MSG_PING) {
          // heartbeat: markValid + reset offline timer  => local_cluster.go:837-861
          if (!rc.ready) { readyCount = readyCount + 1; announce eTunnelUp; }
          rconns[p.cid] = (cid = rc.cid, ready = true, invalid = false, missed = 0, sessions = rc.sessions);
          armTimer(1000 + p.cid, OFFLINE_THRESHOLD());
          send w, eAck; return;
        }
        if (p.msg.k == MSG_KA_REQ) {
          // reply to agent keepalive  => srv.go:429-430
          send w, eNetSend, (cid = p.cid, src = this, msg = mkMsg(MSG_KA_REPLY, 0, RC_NONE));
          send w, eAck; return;
        }
        if (p.msg.k == MSG_KA_REPLY) {
          kaAwaiting[p.cid] = false;   // loop unblocks
          send w, eAck; return;
        }
        if (p.msg.k == MSG_TRANSPORT_OK) {
          // dial accepted; nothing to tell the client yet (it just starts talking)
          send w, eAck; return;
        }
        if (p.msg.k == MSG_TRANSPORT_ERR) {
          failSession(p.msg.ch, p.msg.cause, 4);
          send w, eAck; return;
        }
        if (p.msg.k == MSG_APP_DATA || p.msg.k == MSG_APP_ERRFRAME) {
          // after connect the proxy is a byte relay: engine frames pass through
          // for ALL protocols  => proxyserver.go Proxy/utils.ProxyConn
          if (p.msg.ch in sess) {
            s = sess[p.msg.ch];
            if (p.msg.k == MSG_APP_ERRFRAME) {
              sess[p.msg.ch] = (clientCid = s.clientCid, rconnCid = s.rconnCid, kd = s.kd, gotFrame = true);
            }
            send w, eNetSend, (cid = s.clientCid, src = this, msg = p.msg);
          }
          send w, eAck; return;
        }
        send w, eAck; return;
      }
      // ---- client-facing conns ----
      if (p.msg.k == MSG_HELLO) {
        clientDial(p.cid, p.msg.kd);
        send w, eAck; return;
      }
      if (p.msg.k == MSG_APP_DATA) {
        if (p.cid in chByClient) {
          s = sess[chByClient[p.cid]];
          send w, eNetSend, (cid = s.rconnCid, src = this, msg = mkMsgKd(MSG_APP_DATA, chByClient[p.cid], s.kd, RC_NONE));
        }
        send w, eAck; return;
      }
      send w, eAck;
    }

    on eTimerFired do (p: (tid: int, gen: int, now: int)) {
      var cid: int;
      var rc: tRconn;
      if (!(p.tid in gens) || gens[p.tid] != p.gen) { send w, eAck; return; }
      if (p.tid >= 2000) {
        cid = p.tid - 2000;
        if (cid in rconns) {
          // proxy->agent keepalive  => sshutils/server.go:702-707
          // if the previous request never got its reply, the loop is still
          // blocked in SendRequest: no further keepalives are sent
          if (!(cid in kaAwaiting) || !kaAwaiting[cid]) {
            send w, eNetSend, (cid = cid, src = this, msg = mkMsg(MSG_KA_REQ, 0, RC_NONE));
            kaAwaiting[cid] = true;
          }
          armTimer(2000 + cid, PROXY_KA_IVL());
        }
        send w, eAck; return;
      }
      if (p.tid >= 1000) {
        cid = p.tid - 1000;
        if (cid in rconns) {
          rc = rconns[cid];
          // offline threshold: markInvalid  => local_cluster.go:862-865
          // "Unhealthy reverse tunnel connection" => conn.go:194
          rc = (cid = rc.cid, ready = rc.ready, invalid = true, missed = rc.missed + 1, sessions = rc.sessions);
          rconns[cid] = rc;
          if (rc.missed >= MISSED_HB_MAX() && rc.sessions == 0) {
            // "Closing unhealthy and idle connection" => local_cluster.go:867
            send w, eNetClose, (cid = cid, src = this);
            dropRconn(cid);
          } else {
            // "Deferring closure of unhealthy connection..." => local_cluster.go:870
            armTimer(1000 + cid, OFFLINE_THRESHOLD());
          }
        }
        send w, eAck; return;
      }
      send w, eAck;
    }

    on eNetError do (p: (cid: int)) {
      handleConnDeath(p.cid);
      send w, eAck;
    }
    on eNetEof do (p: (cid: int)) {
      // heartbeat channel closed -> "Agent disconnected" => local_cluster.go:838
      handleConnDeath(p.cid);
      send w, eAck;
    }

    on eEnvCmd do (p: (cmd: int, flag: bool)) {
      var i: int;
      var ks: seq[int];
      if (p.cmd == 3) { presenceOK = p.flag; }
      if (p.cmd == 6) {
        // graceful proxy drain: adviseReconnect to all agents => conn.go:264
        ks = keys(rconns);
        i = 0;
        while (i < sizeof(ks)) {
          send w, eNetSend, (cid = ks[i], src = this, msg = mkMsg(MSG_RECONNECT, 0, RC_NONE));
          i = i + 1;
        }
      }
      send w, eAck;
    }
    on eNetOpened do (p: (cid: int, tag: int, peer: machine)) { send w, eAck; }
  }

  // ---- the dial path: getRemoteConn + connect loop --------------------------
  fun clientDial(clientCid: int, kd: tAgentKind) {
    var pick: int;
    var ch: int;
    var rc: tRconn;
    // presence check happens BEFORE any tunnel dial
    // => lib/srv/db/common/connect/connect.go:65-85
    if (!presenceOK) {
      announce eCause, (cause = RC_PRESENCE_EXPIRED, layer = 3);
      failClient(clientCid, kd, RC_PRESENCE_EXPIRED);
      return;
    }
    pick = getRemoteConn();
    if (pick == -1) {
      // NotFound -> connect loop exhausts -> "failed to connect to any of the
      // database servers"  => local_cluster.go:917,:944; connect.go:345
      announce eCause, (cause = RC_TUNNEL_DOWN, layer = 4);
      failClient(clientCid, kd, RC_TUNNEL_DOWN);
      return;
    }
    ch = nextCh; nextCh = nextCh + 1;
    sess[ch] = (clientCid = clientCid, rconnCid = pick, kd = kd, gotFrame = false);
    chByClient[clientCid] = ch;
    rc = rconns[pick];
    rconns[pick] = (cid = rc.cid, ready = rc.ready, invalid = rc.invalid, missed = rc.missed, sessions = rc.sessions + 1);
    // open teleport-transport channel + dial req  => local_cluster.go:947
    // NOTE: if the tunnel conn is blackholed this send vanishes and NOTHING
    // times out proxy-side (the code blocks on channel open) -> client hang.
    send w, eNetSend, (cid = pick, src = this, msg = mkMsgKd(MSG_TRANSPORT_DIAL, ch, kd, RC_NONE));
  }

  // newest ready+valid; else newest ready+invalid (LAST RESORT);
  // else none  => local_cluster.go:905-945
  fun getRemoteConn(): int {
    var i: int;
    var cid: int;
    var rc: tRconn;
    var newestInvalid: int;
    newestInvalid = -1;
    i = sizeof(order) - 1;
    while (i >= 0) {
      cid = order[i];
      if (cid in rconns) {
        rc = rconns[cid];
        if (rc.ready && !rc.invalid) { return cid; }
        if (rc.ready && rc.invalid && newestInvalid == -1) { newestInvalid = cid; }
      }
      i = i - 1;
    }
    return newestInvalid;
  }

  // proxy-originated failure rendering, by client protocol:
  //  - postgres/mysql: protocol error frame WITH the cause text
  //    => lib/srv/db/postgres/proxy.go:69, lib/srv/db/mysql/proxy.go:88
  //  - kubectl: metav1.Status JSON carrying the error message
  //    => lib/kube/proxy/forwarder.go:763-778 (formatStatusResponseError)
  //  - ssh: error string reaches the client via the SSH handshake/banner
  //  - app (browser): retry-once then generic 500 / launcher redirect,
  //    cause not included => lib/web/app/handler.go:317-336
  //  - mongo/redis/other generic-TLS db protocols: bare close
  //    => lib/srv/db/proxyserver.go:289-347 (no protocol handler at proxy)
  fun failClient(clientCid: int, kd: tAgentKind, cause: tCause) {
    if (kd == AK_DB_PG || kd == AK_KUBE || kd == AK_SSH) {
      send w, eNetSend, (cid = clientCid, src = this, msg = mkMsgKd(MSG_APP_ERRFRAME, 0, kd, cause));
    }
    if (kd == AK_APP) {
      send w, eNetSend, (cid = clientCid, src = this, msg = mkMsgKd(MSG_APP_ERRFRAME, 0, kd, RC_NONE));
    }
    send w, eNetClose, (cid = clientCid, src = this);
  }

  fun failSession(ch: int, cause: tCause, layer: int) {
    var s: tSess;
    var rc: tRconn;
    if (!(ch in sess)) { return; }
    s = sess[ch];
    if (s.rconnCid in rconns) {
      rc = rconns[s.rconnCid];
      rconns[s.rconnCid] = (cid = rc.cid, ready = rc.ready, invalid = rc.invalid, missed = rc.missed, sessions = rc.sessions - 1);
    }
    failClient(s.clientCid, s.kd, cause);
    sess -= (ch);
    chByClient -= (s.clientCid);
  }

  fun handleConnDeath(cid: int) {
    var ks: seq[int];
    var i: int;
    var s: tSess;
    if (cid in rconns) {
      dropRconn(cid);
      // "Agent disconnected" => local_cluster.go:838 — the proxy KNOWS
      announce eCause, (cause = RC_TUNNEL_DOWN, layer = 4);
      // in-flight sessions riding this tunnel die with bare closes
      ks = keys(sess);
      i = 0;
      while (i < sizeof(ks)) {
        s = sess[ks[i]];
        if (s.rconnCid == cid) {
          send w, eNetClose, (cid = s.clientCid, src = this);
          chByClient -= (s.clientCid);
          sess -= (ks[i]);
        }
        i = i + 1;
      }
      return;
    }
    // client conn died: tear down its session
    if (cid in chByClient) {
      failSessionQuiet(chByClient[cid]);
    }
  }

  fun failSessionQuiet(ch: int) {
    var s: tSess;
    var rc: tRconn;
    if (!(ch in sess)) { return; }
    s = sess[ch];
    if (s.rconnCid in rconns) {
      rc = rconns[s.rconnCid];
      rconns[s.rconnCid] = (cid = rc.cid, ready = rc.ready, invalid = rc.invalid, missed = rc.missed, sessions = rc.sessions - 1);
    }
    sess -= (ch);
    chByClient -= (s.clientCid);
  }

  fun dropRconn(cid: int) {
    var i: int;
    var rc: tRconn;
    if (!(cid in rconns)) { return; }
    rc = rconns[cid];
    if (rc.ready) {
      readyCount = readyCount - 1;
      if (readyCount == 0) { announce eTunnelDownA; }
    }
    rconns -= (cid);
    i = 0;
    while (i < sizeof(order)) {
      if (order[i] == cid) { order -= (i); }
      else { i = i + 1; }
    }
    gens[1000 + cid] = gens[1000 + cid] + 1;
    gens[2000 + cid] = gens[2000 + cid] + 1;
  }

  fun armTimer(tid: int, d: int) {
    if (!(tid in gens)) { gens[tid] = 0; }
    gens[tid] = gens[tid] + 1;
    send w, eSetTimer, (owner = this, tid = tid, gen = gens[tid], delay = d);
  }
}

// =============================================================================
// LocalProxy: tsh local tunnel (db paths)  => lib/srv/alpnproxy/local_proxy.go
// =============================================================================

machine LocalProxy {
  var w: machine;
  var proxy: machine;
  var canReissue: bool;
  var upDialTimeout: int;   // 0 = today's code: NO deadline on the per-conn
                            // upstream dial+handshake+upgrade (local_proxy.go:240,
                            // alpn.go:126-150); >0 models adding one
  var pendingDial: bool;
  var g9: int;              // observational 60s overdue timer
  var g10: int;             // behavioral dial-timeout timer
  var downCid: int;      // client -> local proxy
  var upCid: int;        // local proxy -> teleport proxy
  var pendingMsgs: seq[tMsg];  // client bytes buffered until upstream is open
                               // (kernel socket buffers in the real code)
  var kd: tAgentKind;

  start state Run {
    entry (cfg: (w: machine, proxy: machine, canReissue: bool, upDialTimeout: int)) {
      w = cfg.w; proxy = cfg.proxy; canReissue = cfg.canReissue;
      upDialTimeout = cfg.upDialTimeout;
      downCid = -1; upCid = -1; pendingDial = false; g9 = 0; g10 = 0;
    }
    on eNetAccept do (p: (cid: int, tag: int, peer: machine)) {
      var empty: seq[tMsg];
      downCid = p.cid;
      upCid = -1;
      pendingMsgs = empty;
      send w, eAck;
    }
    on eNetDeliver do (p: (cid: int, msg: tMsg)) {
      if (p.cid == downCid) {
        if (p.msg.k == MSG_HELLO) {
          // Middleware.OnNewConnection = cert (re)issue; on failure the client
          // conn is closed and the cause exists only in tsh logs
          // => local_proxy.go:205-210
          if (!canReissue) {
            announce eCause, (cause = RC_CERT_FAIL, layer = 1);
            send w, eNetClose, (cid = downCid, src = this);
            send w, eAck; return;
          }
          kd = p.msg.kd;
          // EVERY downstream conn triggers a fresh upstream dial (websocket /
          // upgrade mode dials per connection) => local_proxy.go:232-247
          announce eDialStart;
          pendingDial = true;
          g9 = g9 + 1;
          send w, eSetTimer, (owner = this, tid = 9, gen = g9, delay = 60);
          if (upDialTimeout > 0) {
            g10 = g10 + 1;
            send w, eSetTimer, (owner = this, tid = 10, gen = g10, delay = upDialTimeout);
          }
          send w, eNetOpen, (src = this, dst = proxy, tag = 3);
        }
        // relay downstream->upstream, buffering until upstream is open
        // => local_proxy.go:240-246 (dial then utils.ProxyConn)
        if (upCid != -1) {
          send w, eNetSend, (cid = upCid, src = this, msg = p.msg);
        } else {
          pendingMsgs += (sizeof(pendingMsgs), p.msg);
        }
        send w, eAck; return;
      }
      if (p.cid == upCid && downCid != -1) {
        send w, eNetSend, (cid = downCid, src = this, msg = p.msg);
      }
      send w, eAck;
    }
    on eNetOpened do (p: (cid: int, tag: int, peer: machine)) {
      var i: int;
      upCid = p.cid;
      if (pendingDial) { pendingDial = false; g9 = g9 + 1; g10 = g10 + 1; announce eDialEnd; }
      i = 0;
      while (i < sizeof(pendingMsgs)) {
        send w, eNetSend, (cid = upCid, src = this, msg = pendingMsgs[i]);
        i = i + 1;
      }
      send w, eAck;
    }
    on eNetError do (p: (cid: int)) {
      // upstream dial/relay failure: ONLY signal to the db client is Close()
      // => local_proxy.go:233
      if (pendingDial) { pendingDial = false; g9 = g9 + 1; g10 = g10 + 1; announce eDialEnd; }
      if (downCid != -1) { send w, eNetClose, (cid = downCid, src = this); }
      send w, eAck;
    }
    on eTimerFired do (p: (tid: int, gen: int, now: int)) {
      if (p.tid == 9 && p.gen == g9 && pendingDial) {
        announce eDialOverdue;   // observational: user has been waiting >60s
      }
      if (p.tid == 10 && p.gen == g10 && pendingDial) {
        // modeled fix: bounded dial => treat like an upstream error
        pendingDial = false; g9 = g9 + 1;
        announce eDialEnd;
        if (downCid != -1) { send w, eNetClose, (cid = downCid, src = this); }
      }
      send w, eAck;
    }
    on eNetEof do (p: (cid: int)) {
      if (p.cid == upCid && downCid != -1) { send w, eNetClose, (cid = downCid, src = this); }
      if (p.cid == downCid && upCid != -1) { send w, eNetClose, (cid = upCid, src = this); }
      send w, eAck;
    }
    on eEnvCmd do (p: (cmd: int, flag: bool)) { send w, eAck; }
  }
}

// =============================================================================
// Client: the end user's database client + the human's patience
// =============================================================================

machine Client {
  var w: machine;
  var entrypoint: machine;   // LocalProxy for db kinds, Proxy for others
  var kd: tAgentKind;
  var cid: int;
  var gen: int;              // patience-timer generation (tid 7)
  var qgen: int;             // next-query-timer generation (tid 8)
  var done: bool;
  var queries: int;          // total queries per session (long sessions > 1)
  var gap: int;              // think time between queries
  var patience: int;         // 0 = immortal client (JDBC-pool style, never hangs up)
  var quiet: bool;           // suppress failure observations (background actor)
  var queriesLeft: int;

  start state Idle {
    entry (cfg: (w: machine, entrypoint: machine, kd: tAgentKind, queries: int, gap: int, patience: int, quiet: bool)) {
      w = cfg.w; entrypoint = cfg.entrypoint; kd = cfg.kd;
      queries = cfg.queries; gap = cfg.gap; patience = cfg.patience; quiet = cfg.quiet;
      cid = -1; gen = 0; qgen = 0; done = false; queriesLeft = 0;
    }
    on eEnvCmd do (p: (cmd: int, flag: bool)) {
      if (p.cmd == 5) {   // CLIENT_CONNECT
        done = false;
        send w, eNetOpen, (src = this, dst = entrypoint, tag = 2);
      }
      send w, eAck;
    }
    on eNetOpened do (p: (cid: int, tag: int, peer: machine)) {
      cid = p.cid;
      queriesLeft = queries - 1;
      qgen = qgen + 1;
      send w, eNetSend, (cid = cid, src = this, msg = mkMsgKd(MSG_HELLO, 0, kd, RC_NONE));
      // the first query; a real client pipelines after connect
      send w, eNetSend, (cid = cid, src = this, msg = mkMsgKd(MSG_APP_DATA, 0, kd, RC_NONE));
      gen = gen + 1;
      if (patience > 0) {
        send w, eSetTimer, (owner = this, tid = 7, gen = gen, delay = patience);
      }
      send w, eAck;
    }
    on eNetDeliver do (p: (cid: int, msg: tMsg)) {
      if (done) { send w, eAck; return; }
      if (p.msg.k == MSG_APP_DATA) {
        if (queriesLeft > 0) {
          // long-lived session: think, then run the next query
          queriesLeft = queriesLeft - 1;
          gen = gen + 1;   // pause patience while thinking
          qgen = qgen + 1;
          send w, eSetTimer, (owner = this, tid = 8, gen = qgen, delay = gap);
          send w, eAck; return;
        }
        done = true; gen = gen + 1;
        announce eObs, (obs = OBS_SUCCESS, cause = RC_NONE);
        send w, eNetClose, (cid = cid, src = this);
      }
      if (p.msg.k == MSG_APP_ERRFRAME) {
        done = true; gen = gen + 1;
        if (p.msg.cause == RC_NONE) {
          announce eObs, (obs = OBS_GENERIC_ERR, cause = RC_NONE);
        } else {
          announce eObs, (obs = OBS_PROTO_ERR, cause = p.msg.cause);
        }
      }
      send w, eAck;
    }
    on eNetEof do (p: (cid: int)) {
      if (!done && p.cid == cid) {
        done = true; gen = gen + 1;
        if (!quiet) { announce eObs, (obs = OBS_BARE_CLOSE, cause = RC_NONE); }
      }
      send w, eAck;
    }
    on eNetError do (p: (cid: int)) {
      if (!done && p.cid == cid) {
        done = true; gen = gen + 1;
        if (!quiet) { announce eObs, (obs = OBS_BARE_CLOSE, cause = RC_NONE); }
      }
      send w, eAck;
    }
    on eTimerFired do (p: (tid: int, gen: int, now: int)) {
      if (p.tid == 7 && p.gen == gen && !done) {
        done = true;
        if (!quiet) { announce eObs, (obs = OBS_HANG, cause = RC_NONE); }
        send w, eNetClose, (cid = cid, src = this);
      }
      if (p.tid == 8 && p.gen == qgen && !done) {
        // send the next query mid-session, patience restarts
        send w, eNetSend, (cid = cid, src = this, msg = mkMsgKd(MSG_APP_DATA, 0, kd, RC_NONE));
        gen = gen + 1;
        if (patience > 0) {
          send w, eSetTimer, (owner = this, tid = 7, gen = gen, delay = patience);
        }
      }
      send w, eAck;
    }
  }
}

// =============================================================================
// Resumption pair (ssh only)  => lib/resumption (RFD 0150)
// Coarse model: frame-level stream with replay buffer; transports are World
// conns with tag 4 that the driver can fault. Positions are frame counts.
// =============================================================================

event eResAppSend;   // driver pumps one app frame into the client side

machine ResClient {
  var w: machine;
  var server: machine;
  var cid: int;             // current transport (-1 = detached)
  var sendSeq: int;         // next frame seq to originate
  var buf: seq[int];        // sent, unacked frames (replay buffer) => managedconn.go:37
  var rcvPos: int;          // frames received  => resumable.go:175-213 handshake pos
  var deadlineLeft: int;    // reconnect budget => client.go:42 (60s)
  var gens: map[int, int];
  var given_up: bool;
  var attached: bool;

  start state Detached {
    entry (cfg: (w: machine, server: machine)) {
      w = cfg.w; server = cfg.server;
      cid = -1; sendSeq = 0; rcvPos = 0; deadlineLeft = RES_RECONNECT_MAX();
      given_up = false; attached = false;
      gens[1] = 0; gens[2] = 0;
      send w, eNetOpen, (src = this, dst = server, tag = 4);
    }
    on eNetOpened do (p: (cid: int, tag: int, peer: machine)) {
      cid = p.cid;
      attached = true;
      // attach handshake: send my receive position; server rewinds+replays
      // => resumable.go:175-213
      send w, eNetSend, (cid = cid, src = this, msg = mkMsg(MSG_REGISTER, rcvPos, RC_NONE));
      replayFrom();
      armTimer(2, RES_REPLACEMENT());    // proactive replacement => client.go:40,194
      send w, eAck;
      goto Attached;
    }
    on eNetError do (p: (cid: int)) { retryOrGiveUp(); send w, eAck; }
    on eNetEof do (p: (cid: int)) { retryOrGiveUp(); send w, eAck; }
    on eTimerFired do (p: (tid: int, gen: int, now: int)) {
      if (p.tid == 1 && gens[1] == p.gen && !given_up) {
        send w, eNetOpen, (src = this, dst = server, tag = 4);
      }
      send w, eAck;
    }
    on eResAppSend do { bufferFrame(); }
    on eNetDeliver do (p: (cid: int, msg: tMsg)) { send w, eAck; }
    on eEnvCmd do (p: (cmd: int, flag: bool)) {
      if (p.cmd == 7) { bufferFrame(); }
      send w, eAck;
    }
  }

  state Attached {
    on eNetDeliver do (p: (cid: int, msg: tMsg)) {
      if (p.cid != cid) { send w, eAck; return; }
      if (p.msg.k == MSG_APP_DATA) {
        // in-order delivery check: ch carries the frame seq
        announce eResDelivered, (dir = 1, sqn = p.msg.ch);
        rcvPos = rcvPos + 1;
        // cumulative ack rides back  => resumable.go:352
        send w, eNetSend, (cid = cid, src = this, msg = mkMsg(MSG_KA_REPLY, rcvPos, RC_NONE));
        send w, eAck; return;
      }
      if (p.msg.k == MSG_KA_REPLY) {
        ackTo(p.msg.ch);
        send w, eAck; return;
      }
      send w, eAck;
    }
    on eNetError do (p: (cid: int)) {
      if (p.cid == cid) { detach(); goto Detached2; }
      send w, eAck;
    }
    on eNetEof do (p: (cid: int)) {
      if (p.cid == cid) { detach(); goto Detached2; }
      send w, eAck;
    }
    on eTimerFired do (p: (tid: int, gen: int, now: int)) {
      if (p.tid == 2 && gens[2] == p.gen) {
        // proactive replacement: drop transport, immediately re-dial
        // => client.go:194-217
        send w, eNetClose, (cid = cid, src = this);
        detach();
        goto Detached2;
      }
      send w, eAck;
    }
    on eEnvCmd do (p: (cmd: int, flag: bool)) {
      if (p.cmd == 7) {
        bufferFrame();
        send w, eNetSend, (cid = cid, src = this, msg = mkMsg(MSG_APP_DATA, sendSeq - 1, RC_NONE));
      }
      send w, eAck;
    }
    on eNetOpened do (p: (cid: int, tag: int, peer: machine)) { send w, eAck; }
  }

  // reconnection loop state (fresh transport dial after loss)
  state Detached2 {
    entry {
      deadlineLeft = RES_RECONNECT_MAX();
      redial();
      send w, eAck;
    }
    on eNetOpened do (p: (cid: int, tag: int, peer: machine)) {
      cid = p.cid;
      attached = true;
      send w, eNetSend, (cid = cid, src = this, msg = mkMsg(MSG_REGISTER, rcvPos, RC_NONE));
      replayFrom();
      armTimer(2, RES_REPLACEMENT());
      send w, eAck;
      goto Attached;
    }
    on eNetError do (p: (cid: int)) { retryOrGiveUp(); send w, eAck; }
    on eNetEof do (p: (cid: int)) { retryOrGiveUp(); send w, eAck; }
    on eTimerFired do (p: (tid: int, gen: int, now: int)) {
      if (p.tid == 1 && gens[1] == p.gen && !given_up) { redial(); }
      send w, eAck;
    }
    on eNetDeliver do (p: (cid: int, msg: tMsg)) {
      if (p.msg.k == MSG_TRANSPORT_ERR) {
        // server said notFound (held conn expired) -> permanent give-up
        // => client.go:381-389
        given_up = true;
        announce eResClosed;
      }
      send w, eAck;
    }
    on eEnvCmd do (p: (cmd: int, flag: bool)) {
      if (p.cmd == 7) { bufferFrame(); }
      send w, eAck;
    }
  }

  fun bufferFrame() {
    buf += (sizeof(buf), sendSeq);
    sendSeq = sendSeq + 1;
  }

  fun replayFrom() {
    var i: int;
    i = 0;
    while (i < sizeof(buf)) {
      send w, eNetSend, (cid = cid, src = this, msg = mkMsg(MSG_APP_DATA, buf[i], RC_NONE));
      i = i + 1;
    }
  }

  fun ackTo(pos: int) {
    // peer confirmed receipt of frames < pos: drop them from replay buffer
    while (sizeof(buf) > 0 && buf[0] < pos) { buf -= (0); }
  }

  fun detach() {
    attached = false; cid = -1;
    gens[2] = gens[2] + 1;  // cancel replacement timer
  }

  fun redial() {
    if (deadlineLeft <= 0) {
      // "failed to reconnect to server after timeout" => client.go:240
      given_up = true;
      announce eResClosed;
      return;
    }
    deadlineLeft = deadlineLeft - RES_BACKOFF_STEP();
    send w, eNetOpen, (src = this, dst = server, tag = 4);
  }

  fun retryOrGiveUp() {
    if (given_up) { return; }
    gens[1] = gens[1] + 1;
    send w, eSetTimer, (owner = this, tid = 1, gen = gens[1], delay = RES_BACKOFF_STEP());
  }

  fun armTimer(tid: int, d: int) {
    gens[tid] = gens[tid] + 1;
    send w, eSetTimer, (owner = this, tid = tid, gen = gens[tid], delay = d);
  }
}

machine ResServer {
  var w: machine;
  var cid: int;
  var sendSeq: int;
  var buf: seq[int];
  var rcvPos: int;
  var gens: map[int, int];
  var closedForGood: bool;
  var echo: bool;

  start state Run {
    entry (wm: machine) {
      w = wm; cid = -1; sendSeq = 0; rcvPos = 0; closedForGood = false;
      echo = true;
      gens[1] = 0;
    }
    on eNetAccept do (p: (cid: int, tag: int, peer: machine)) {
      var old: int;
      if (closedForGood) {
        // resumable conn already dropped: notFound => handover.go:64-65
        send w, eNetSend, (cid = p.cid, src = this, msg = mkMsg(MSG_TRANSPORT_ERR, 0, RC_NONE));
        send w, eNetClose, (cid = p.cid, src = this);
        send w, eAck; return;
      }
      // server disconnects an existing transport if a new one attaches (RFD 0150)
      if (cid != -1) { old = cid; send w, eNetClose, (cid = old, src = this); }
      cid = p.cid;
      gens[1] = gens[1] + 1;   // disarm detachedTimeout => server_detect.go:114-119
      send w, eAck;
    }
    on eNetDeliver do (p: (cid: int, msg: tMsg)) {
      if (p.cid != cid) { send w, eAck; return; }
      if (p.msg.k == MSG_REGISTER) {
        // client's receive position: rewind + replay  => resumable.go:206-209
        while (sizeof(buf) > 0 && buf[0] < p.msg.ch) { buf -= (0); }
        replayFrom();
        send w, eAck; return;
      }
      if (p.msg.k == MSG_APP_DATA) {
        announce eResDelivered, (dir = 0, sqn = p.msg.ch);
        rcvPos = rcvPos + 1;
        send w, eNetSend, (cid = cid, src = this, msg = mkMsg(MSG_KA_REPLY, rcvPos, RC_NONE));
        if (echo) {
          buf += (sizeof(buf), sendSeq);
          send w, eNetSend, (cid = cid, src = this, msg = mkMsg(MSG_APP_DATA, sendSeq, RC_NONE));
          sendSeq = sendSeq + 1;
        }
        send w, eAck; return;
      }
      if (p.msg.k == MSG_KA_REPLY) {
        while (sizeof(buf) > 0 && buf[0] < p.msg.ch) { buf -= (0); }
        send w, eAck; return;
      }
      send w, eAck;
    }
    on eNetError do (p: (cid: int)) {
      if (p.cid == cid) {
        cid = -1;
        // transport error arms detachedTimeout (1m) => server_detect.go:121-128
        // NOTE: a silently-dead transport never arms this (running>0 forever)
        armTimer(1, RES_DETACHED_HOLD());
      }
      send w, eAck;
    }
    on eNetEof do (p: (cid: int)) {
      if (p.cid == cid) {
        cid = -1;
        armTimer(1, RES_DETACHED_HOLD());
      }
      send w, eAck;
    }
    on eTimerFired do (p: (tid: int, gen: int, now: int)) {
      if (p.tid == 1 && gens[1] == p.gen && cid == -1) {
        // detachedTimeout: drop the resumable conn => server_exchange.go:109
        closedForGood = true;
        announce eResClosed;
      }
      send w, eAck;
    }
    on eEnvCmd do (p: (cmd: int, flag: bool)) { send w, eAck; }
  }

  fun replayFrom() {
    var i: int;
    i = 0;
    while (i < sizeof(buf)) {
      send w, eNetSend, (cid = cid, src = this, msg = mkMsg(MSG_APP_DATA, buf[i], RC_NONE));
      i = i + 1;
    }
  }

  fun armTimer(tid: int, d: int) {
    gens[tid] = gens[tid] + 1;
    send w, eSetTimer, (owner = this, tid = tid, gen = gens[tid], delay = d);
  }
}

// =============================================================================
// Specs
// =============================================================================

// Every user-visible failure should carry a cause from the layer that failed.
// A BARE_CLOSE or HANG observed while a deeper root cause was announced is a
// UX gap: the system knew, the user wasn't told. Tests including this spec
// and reaching such a state produce a counterexample trace == a finding.
spec ErrorAttribution observes eObs, eCause {
  var lastCause: tCause;
  var lastLayer: int;
  start state Watching {
    entry { lastCause = RC_NONE; lastLayer = 0; }
    on eCause do (p: (cause: tCause, layer: int)) {
      lastCause = p.cause; lastLayer = p.layer;
    }
    on eObs do (p: (obs: tObs, cause: tCause)) {
      if (p.obs == OBS_BARE_CLOSE) {
        assert lastCause == RC_NONE,
          format("UX GAP: user saw a bare connection close but layer {0} knew the cause: {1}", lastLayer, lastCause);
      }
      if (p.obs == OBS_GENERIC_ERR) {
        assert lastCause == RC_NONE,
          format("UX GAP: user got a generic error without the cause layer {0} knew: {1}", lastLayer, lastCause);
      }
      if (p.obs == OBS_HANG) {
        assert false,
          format("UX GAP: user hung until giving up; last known deeper cause: {0} (layer {1})", lastCause, lastLayer);
      }
    }
  }
}

// Every user-facing upstream dial must resolve (success or error) within 60s.
// A dial still pending at 60s is the tbot/tsh "hangs for minutes" incident class.
spec DialBounded observes eDialStart, eDialEnd, eDialOverdue {
  var outstanding: int;
  start cold state Quiet {
    entry { }
    on eDialStart do { outstanding = outstanding + 1; goto Dialing; }
    on eDialEnd do { if (outstanding > 0) { outstanding = outstanding - 1; } }
    ignore eDialOverdue;
  }
  hot state Dialing {
    on eDialStart do { outstanding = outstanding + 1; }
    on eDialEnd do {
      outstanding = outstanding - 1;
      if (outstanding == 0) { goto Quiet; }
    }
    on eDialOverdue do {
      assert false, "UX GAP: upstream dial pending >60s with no error surfaced to the user";
    }
  }
}

// Attribution CORRECTNESS (not just presence): during a control-plane outage
// with a healthy tunnel, rendering "not found among registered databases"
// (connect.go:82) sends the operator to debug configuration instead of the
// auth path. The existing ErrorAttribution spec is blind to this: a cause IS
// attached -- it is just the wrong story.
spec CauseFidelity observes eGroundTruth, eObs, eTunnelUp, eTunnelDownA {
  var gtOutage: bool;
  var ready: int;
  start state Watching {
    entry { gtOutage = false; ready = 0; }
    on eGroundTruth do (b: bool) { gtOutage = b; }
    on eTunnelUp do { ready = ready + 1; }
    on eTunnelDownA do { ready = 0; }
    on eObs do (p: (obs: tObs, cause: tCause)) {
      if (gtOutage && ready > 0 && p.obs == OBS_PROTO_ERR && p.cause == RC_PRESENCE_EXPIRED) {
        assert false, "MISATTRIBUTION: control-plane outage rendered as config-style not-found while the tunnel is healthy";
      }
    }
  }
}

// After the tunnel drops it must come back (agent redial loop must converge).
spec RecoveryLiveness observes eTunnelUp, eTunnelDownA {
  start state NoTunnel {
    on eTunnelUp goto Up;
    on eTunnelDownA goto Down;
  }
  cold state Up {
    on eTunnelDownA goto Down;
    ignore eTunnelUp;
  }
  hot state Down {
    on eTunnelUp goto Up;
    ignore eTunnelDownA;
  }
}

// Resumption must deliver each direction's frames exactly once, in order,
// across any number of detach/reattach cycles (RFD 0150 core guarantee).
spec ResumptionSafety observes eResDelivered, eResClosed {
  var expect: map[int, int];
  var closed: bool;
  start state Checking {
    entry { expect[0] = 0; expect[1] = 0; closed = false; }
    on eResDelivered do (p: (dir: int, sqn: int)) {
      if (closed) { return; }
      // duplicates from replay-after-partial-delivery MUST be discarded by
      // the receiver; the model's receiver counts every delivery, so any
      // out-of-order/duplicate delivery trips this assert.
      assert p.sqn == expect[p.dir],
        format("stream integrity violated: dir {0} expected seq {1} got {2}", p.dir, expect[p.dir], p.sqn);
      expect[p.dir] = expect[p.dir] + 1;
    }
    on eResClosed do { closed = true; }
  }
}

// =============================================================================
// Test drivers
// =============================================================================

// driver timer ids double as scripts: 100+n = script step n

machine DriverTunnelFault {
  var w: machine;
  var agent: machine;
  var proxy: machine;
  var lp: machine;
  var client: machine;
  var kd: tAgentKind;
  var faultKind: int;      // 0=blackhole 1=reset 2=one-way agent->proxy lost
                           // 3=one-way proxy->agent lost
  var dialDuringFault: bool;

  start state Boot {
    entry (cfg: (kd: tAgentKind, faultKind: int, dialDuringFault: bool, canReissue: bool, targetUp: bool, midSession: bool, flap: bool)) {
      var nq: int;
      kd = cfg.kd; faultKind = cfg.faultKind; dialDuringFault = cfg.dialDuringFault;
      w = new World(14400);
      proxy = new Proxy(w);
      agent = new Agent((w = w, proxy = proxy, kind = kd, targetUp = cfg.targetUp, dialBounded = false));
      lp = new LocalProxy((w = w, proxy = proxy, canReissue = cfg.canReissue, upDialTimeout = 0));
      nq = 1;
      if (cfg.midSession) { nq = 2; }   // long session: 2 queries, 300s apart
      if (kd == AK_DB_PG || kd == AK_DB_MONGO) {
        client = new Client((w = w, entrypoint = lp, kd = kd, queries = nq, gap = 300, patience = PATIENCE(), quiet = false));
      } else {
        client = new Client((w = w, entrypoint = proxy, kd = kd, queries = nq, gap = 300, patience = PATIENCE(), quiet = false));
      }
      // script:
      send w, eEnvSend, (target = agent, cmd = 1, flag = true);        // boot agent at t=0
      send w, eSetTimer, (owner = this, tid = 101, gen = 0, delay = 100);   // fault at t=100
      if (cfg.flap) {
        // two more resets shortly after recovery (connection flapping)
        send w, eSetTimer, (owner = this, tid = 105, gen = 0, delay = 130);
        send w, eSetTimer, (owner = this, tid = 106, gen = 0, delay = 160);
      }
      if (cfg.midSession) {
        // connect BEFORE the fault; the 2nd query lands after it
        send w, eSetTimer, (owner = this, tid = 102, gen = 0, delay = 40);
      } else if (dialDuringFault) {
        if (faultKind >= 2) {
          // one-way loss detection is slower; sample the whole zombie window
          send w, eSetTimer, (owner = this, tid = 102, gen = 0, delay = 110 + choose(7) * 300);
        } else {
          // dial while the fault is undetected (before watchdog/threshold)
          send w, eSetTimer, (owner = this, tid = 102, gen = 0, delay = 100 + choose(5) * 150 + 10);
        }
      }
      // dial after full recovery should always work
      send w, eSetTimer, (owner = this, tid = 103, gen = 0, delay = 3000);
      send w, eKick;
    }
    on eTimerFired do (p: (tid: int, gen: int, now: int)) {
      if (p.tid == 101 || p.tid == 105 || p.tid == 106) {
        if (faultKind == 0)      { send w, eInjectTag, (tag = 1, st = CS_BLACKHOLE); }
        else if (faultKind == 1) { send w, eInjectTag, (tag = 1, st = CS_RESET); }
        else if (faultKind == 2) { send w, eInjectTag, (tag = 1, st = CS_BH_A2B); }
        else                     { send w, eInjectTag, (tag = 1, st = CS_BH_B2A); }
      }
      if (p.tid == 102 || p.tid == 103) {
        send w, eEnvSend, (target = client, cmd = 5, flag = true);
      }
      send w, eAck;
    }
    on eNetDeliver do (p: (cid: int, msg: tMsg)) { send w, eAck; }
  }
}

machine DriverProxyPathErrors {
  var w: machine;
  var agent: machine;
  var proxy: machine;
  var lp: machine;
  var client: machine;

  start state Boot {
    entry (cfg: (kd: tAgentKind, scenario: int, targetUp: bool, canReissue: bool)) {
      // scenario: 0 = agent cleanly stopped (tunnel gone, presence stale)
      //           1 = presence expired (tunnel healthy)
      //           2 = plain dial (target up/down decides outcome)
      //           3 = proxy drain advisory mid-idle, then dial
      w = new World(7200);
      proxy = new Proxy(w);
      agent = new Agent((w = w, proxy = proxy, kind = cfg.kd, targetUp = cfg.targetUp, dialBounded = false));
      lp = new LocalProxy((w = w, proxy = proxy, canReissue = cfg.canReissue, upDialTimeout = 0));
      if (cfg.kd == AK_DB_PG || cfg.kd == AK_DB_MONGO) {
        client = new Client((w = w, entrypoint = lp, kd = cfg.kd, queries = 1, gap = 0, patience = PATIENCE(), quiet = false));
      } else {
        client = new Client((w = w, entrypoint = proxy, kd = cfg.kd, queries = 1, gap = 0, patience = PATIENCE(), quiet = false));
      }
      send w, eEnvSend, (target = agent, cmd = 1, flag = true);
      if (cfg.scenario == 0) {
        send w, eSetTimer, (owner = this, tid = 110, gen = 0, delay = 50);   // stop agent
      }
      if (cfg.scenario == 1) {
        send w, eSetTimer, (owner = this, tid = 111, gen = 0, delay = 50);   // expire presence
      }
      if (cfg.scenario == 3) {
        send w, eSetTimer, (owner = this, tid = 113, gen = 0, delay = 50);   // drain advisory
      }
      if (cfg.scenario == 4) {
        // presence flap: auth outage 50..350 while the tunnel stays healthy
        send w, eSetTimer, (owner = this, tid = 114, gen = 0, delay = 50);
        send w, eSetTimer, (owner = this, tid = 115, gen = 0, delay = 350);
        send w, eSetTimer, (owner = this, tid = 116, gen = 0, delay = 60 + choose(2) * 300);
      } else {
        send w, eSetTimer, (owner = this, tid = 112, gen = 0, delay = 200);  // client dial
      }
      send w, eKick;
    }
    on eTimerFired do (p: (tid: int, gen: int, now: int)) {
      if (p.tid == 110) { send w, eEnvSend, (target = agent, cmd = 4, flag = true); }
      if (p.tid == 111) { send w, eEnvSend, (target = proxy, cmd = 3, flag = false); }
      if (p.tid == 113) { send w, eEnvSend, (target = proxy, cmd = 6, flag = true); }
      if (p.tid == 114) {
        announce eGroundTruth, true;
        send w, eEnvSend, (target = proxy, cmd = 3, flag = false);
      }
      if (p.tid == 115) {
        send w, eEnvSend, (target = proxy, cmd = 3, flag = true);
        announce eGroundTruth, false;
      }
      if (p.tid == 112 || p.tid == 116) { send w, eEnvSend, (target = client, cmd = 5, flag = true); }
      send w, eAck;
    }
    on eNetDeliver do (p: (cid: int, msg: tMsg)) { send w, eAck; }
  }
}

machine DriverResumption {
  var w: machine;
  var rc: machine;
  var rs: machine;
  var pumps: int;

  start state Boot {
    entry (nfaults: int) {
      var i: int;
      w = new World(1800);
      rs = new ResServer(w);
      rc = new ResClient((w = w, server = rs));
      pumps = 6;
      // pump app frames at t=10,20,...; inject transport faults in between
      i = 0;
      while (i < pumps) {
        send w, eSetTimer, (owner = this, tid = 120 + i, gen = 0, delay = 10 + i * 40);
        i = i + 1;
      }
      i = 0;
      while (i < nfaults) {
        send w, eSetTimer, (owner = this, tid = 140 + i, gen = 0, delay = 30 + i * 80 + choose(4) * 10);
        i = i + 1;
      }
    }
    on eTimerFired do (p: (tid: int, gen: int, now: int)) {
      if (p.tid >= 140) {
        if ($) { send w, eInjectTag, (tag = 4, st = CS_RESET); }
        else   { send w, eInjectTag, (tag = 4, st = CS_BLACKHOLE); }
      } else if (p.tid >= 120) {
        send w, eEnvSend, (target = rc, cmd = 7, flag = true);
      }
      send w, eAck;
    }
    on eNetDeliver do (p: (cid: int, msg: tMsg)) { send w, eAck; }
  }
}

// tbot/tsh local-tunnel dial faults: an unhealthy proxy endpoint that the LB
// has not (yet) ejected. mode 0: single backend wedges (EP_ACCEPT_HANG);
// mode 1: LB with one healthy + one blackholed backend, chosen per dial.
machine DriverLpDialFault {
  var w: machine;
  var agent: machine;
  var proxy: machine;
  var lps: seq[machine];
  var clients: seq[machine];
  var mode: int;

  start state Boot {
    entry (cfg: (mode: int, upDialTimeout: int)) {
      var i: int;
      var lp: machine;
      var c: machine;
      mode = cfg.mode;
      w = new World(3600);
      proxy = new Proxy(w);
      agent = new Agent((w = w, proxy = proxy, kind = AK_DB_PG, targetUp = true, dialBounded = false));
      i = 0;
      while (i < 3) {
        lp = new LocalProxy((w = w, proxy = proxy, canReissue = true, upDialTimeout = cfg.upDialTimeout));
        c = new Client((w = w, entrypoint = lp, kd = AK_DB_PG, queries = 1, gap = 0, patience = PATIENCE(), quiet = false));
        lps += (i, lp);
        clients += (i, c);
        i = i + 1;
      }
      send w, eEnvSend, (target = agent, cmd = 1, flag = true);
      if (mode == 0) {
        send w, eSetTimer, (owner = this, tid = 121, gen = 0, delay = 50);    // wedge
        send w, eSetTimer, (owner = this, tid = 122, gen = 0, delay = 600);   // heal
        send w, eSetTimer, (owner = this, tid = 131, gen = 0, delay = 60);
        send w, eSetTimer, (owner = this, tid = 132, gen = 0, delay = 200);
        send w, eSetTimer, (owner = this, tid = 133, gen = 0, delay = 400);
      } else {
        send w, eSetTimer, (owner = this, tid = 123, gen = 0, delay = 20);    // LB config
        send w, eSetTimer, (owner = this, tid = 131, gen = 0, delay = 100);
        send w, eSetTimer, (owner = this, tid = 132, gen = 0, delay = 400);
        send w, eSetTimer, (owner = this, tid = 133, gen = 0, delay = 1200);
      }
      send w, eKick;
    }
    on eTimerFired do (p: (tid: int, gen: int, now: int)) {
      var backends: seq[tEpState];
      if (p.tid == 121) { send w, eSetEpHealth, (ep = proxy, st = EP_ACCEPT_HANG); }
      if (p.tid == 122) { send w, eSetEpHealth, (ep = proxy, st = EP_OK); }
      if (p.tid == 123) {
        backends += (0, EP_OK);
        backends += (1, EP_ACCEPT_BLACKHOLE);
        send w, eSetLb, (ep = proxy, backends = backends);
      }
      if (p.tid >= 131 && p.tid <= 133) {
        send w, eEnvSend, (target = clients[p.tid - 131], cmd = 5, flag = true);
      }
      send w, eAck;
    }
    on eNetDeliver do (p: (cid: int, msg: tMsg)) { send w, eAck; }
  }
}

// agent redial hits a wedged proxy backend: the serial pool loop
// (agentpool.go:279-307) has ONE dial in flight; on the ALPN-routing path the
// 30s dial timeout is dropped (lib/utils/proxy/proxy.go:69-73), so a single
// accepted-but-hung dial wedges the agent forever.
machine DriverAgentRedial {
  var w: machine;
  var agent: machine;
  var proxy: machine;

  start state Boot {
    entry (bounded: bool) {
      w = new World(7200);
      proxy = new Proxy(w);
      agent = new Agent((w = w, proxy = proxy, kind = AK_DB_PG, targetUp = true, dialBounded = bounded));
      send w, eEnvSend, (target = agent, cmd = 1, flag = true);
      send w, eSetTimer, (owner = this, tid = 141, gen = 0, delay = 90);   // wedge endpoint
      send w, eSetTimer, (owner = this, tid = 142, gen = 0, delay = 100);  // RST the tunnel
      send w, eSetTimer, (owner = this, tid = 143, gen = 0, delay = 600);  // heal endpoint
      send w, eKick;
    }
    on eTimerFired do (p: (tid: int, gen: int, now: int)) {
      if (p.tid == 141) { send w, eSetEpHealth, (ep = proxy, st = EP_ACCEPT_HANG); }
      if (p.tid == 142) { send w, eInjectTag, (tag = 1, st = CS_RESET); }
      if (p.tid == 143) { send w, eSetEpHealth, (ep = proxy, st = EP_OK); }
      send w, eAck;
    }
    on eNetDeliver do (p: (cid: int, msg: tMsg)) { send w, eAck; }
  }
}

// a leaked/immortal client session pins an unhealthy conn past the 45m hard
// close (isOffline requires activeSessions==0, conn.go:217); a later dial then
// hangs on the pinned dead conn with no bound at all.
machine DriverSessionLeak {
  var w: machine;
  var agent: machine;
  var proxy: machine;
  var clientA: machine;
  var clientB: machine;

  start state Boot {
    entry (immortal: bool) {
      var lpA: machine;
      var lpB: machine;
      var pat: int;
      w = new World(6000);
      proxy = new Proxy(w);
      agent = new Agent((w = w, proxy = proxy, kind = AK_DB_PG, targetUp = true, dialBounded = false));
      lpA = new LocalProxy((w = w, proxy = proxy, canReissue = true, upDialTimeout = 0));
      lpB = new LocalProxy((w = w, proxy = proxy, canReissue = true, upDialTimeout = 0));
      pat = PATIENCE();
      if (immortal) { pat = 0; }
      clientA = new Client((w = w, entrypoint = lpA, kd = AK_DB_PG, queries = 2, gap = 300, patience = pat, quiet = true));
      clientB = new Client((w = w, entrypoint = lpB, kd = AK_DB_PG, queries = 1, gap = 0, patience = PATIENCE(), quiet = false));
      send w, eEnvSend, (target = agent, cmd = 1, flag = true);
      send w, eSetTimer, (owner = this, tid = 151, gen = 0, delay = 40);    // A connects
      send w, eSetTimer, (owner = this, tid = 152, gen = 0, delay = 100);   // blackhole
      send w, eSetTimer, (owner = this, tid = 153, gen = 0, delay = 150);   // agent stops for good
      send w, eSetTimer, (owner = this, tid = 154, gen = 0, delay = 4000);  // B dials (past 45m mark)
      send w, eKick;
    }
    on eTimerFired do (p: (tid: int, gen: int, now: int)) {
      if (p.tid == 151) { send w, eEnvSend, (target = clientA, cmd = 5, flag = true); }
      if (p.tid == 152) { send w, eInjectTag, (tag = 1, st = CS_BLACKHOLE); }
      if (p.tid == 153) { send w, eEnvSend, (target = agent, cmd = 4, flag = true); }
      if (p.tid == 154) { send w, eEnvSend, (target = clientB, cmd = 5, flag = true); }
      send w, eAck;
    }
    on eNetDeliver do (p: (cid: int, msg: tMsg)) { send w, eAck; }
  }
}

// =============================================================================
// Test harnesses (concrete parameterizations)
// =============================================================================

machine TcRstIdle {
  start state I { entry {
    new DriverTunnelFault((kd = AK_DB_PG, faultKind = 1, dialDuringFault = false, canReissue = true, targetUp = true, midSession = false, flap = false));
  } }
}
machine TcSilentDropIdle {
  start state I { entry {
    new DriverTunnelFault((kd = AK_DB_PG, faultKind = 0, dialDuringFault = false, canReissue = true, targetUp = true, midSession = false, flap = false));
  } }
}
machine TcDialDuringBlackhole {
  start state I { entry {
    new DriverTunnelFault((kd = AK_DB_PG, faultKind = 0, dialDuringFault = true, canReissue = true, targetUp = true, midSession = false, flap = false));
  } }
}
machine TcDialDuringRst {
  start state I { entry {
    new DriverTunnelFault((kd = AK_DB_PG, faultKind = 1, dialDuringFault = true, canReissue = true, targetUp = true, midSession = false, flap = false));
  } }
}
machine TcAgentGonePg {
  start state I { entry {
    new DriverProxyPathErrors((kd = AK_DB_PG, scenario = 0, targetUp = true, canReissue = true));
  } }
}
machine TcAgentGoneMongo {
  start state I { entry {
    new DriverProxyPathErrors((kd = AK_DB_MONGO, scenario = 0, targetUp = true, canReissue = true));
  } }
}
machine TcPresenceExpired {
  start state I { entry {
    new DriverProxyPathErrors((kd = AK_DB_PG, scenario = 1, targetUp = true, canReissue = true));
  } }
}
machine TcTargetDownPg {
  start state I { entry {
    new DriverProxyPathErrors((kd = AK_DB_PG, scenario = 2, targetUp = false, canReissue = true));
  } }
}
machine TcTargetDownMongo {
  start state I { entry {
    new DriverProxyPathErrors((kd = AK_DB_MONGO, scenario = 2, targetUp = false, canReissue = true));
  } }
}
machine TcCertReissueFail {
  start state I { entry {
    new DriverProxyPathErrors((kd = AK_DB_PG, scenario = 2, targetUp = true, canReissue = false));
  } }
}
machine TcProxyDrain {
  start state I { entry {
    new DriverProxyPathErrors((kd = AK_DB_PG, scenario = 3, targetUp = true, canReissue = true));
  } }
}
machine TcAgentGoneKube {
  start state I { entry {
    new DriverProxyPathErrors((kd = AK_KUBE, scenario = 0, targetUp = true, canReissue = true));
  } }
}
machine TcAgentGoneApp {
  start state I { entry {
    new DriverProxyPathErrors((kd = AK_APP, scenario = 0, targetUp = true, canReissue = true));
  } }
}
machine TcAgentGoneSsh {
  start state I { entry {
    new DriverProxyPathErrors((kd = AK_SSH, scenario = 0, targetUp = true, canReissue = true));
  } }
}
machine TcMidSessionRst {
  start state I { entry {
    new DriverTunnelFault((kd = AK_DB_PG, faultKind = 1, dialDuringFault = false, canReissue = true, targetUp = true, midSession = true, flap = false));
  } }
}
machine TcMidSessionBlackhole {
  start state I { entry {
    new DriverTunnelFault((kd = AK_DB_PG, faultKind = 0, dialDuringFault = false, canReissue = true, targetUp = true, midSession = true, flap = false));
  } }
}
machine TcOneWayAgentLossDial {
  start state I { entry {
    new DriverTunnelFault((kd = AK_DB_PG, faultKind = 2, dialDuringFault = true, canReissue = true, targetUp = true, midSession = false, flap = false));
  } }
}
machine TcOneWayProxyLossDial {
  start state I { entry {
    new DriverTunnelFault((kd = AK_DB_PG, faultKind = 3, dialDuringFault = true, canReissue = true, targetUp = true, midSession = false, flap = false));
  } }
}
machine TcOneWayProxyLossIdle {
  start state I { entry {
    new DriverTunnelFault((kd = AK_DB_PG, faultKind = 3, dialDuringFault = false, canReissue = true, targetUp = true, midSession = false, flap = false));
  } }
}
machine TcFlapRst {
  start state I { entry {
    new DriverTunnelFault((kd = AK_DB_PG, faultKind = 1, dialDuringFault = false, canReissue = true, targetUp = true, midSession = false, flap = true));
  } }
}
machine TcLpDialHungBackend {
  start state I { entry { new DriverLpDialFault((mode = 0, upDialTimeout = 0)); } }
}
machine TcTbotLbOneBadBackend {
  start state I { entry { new DriverLpDialFault((mode = 1, upDialTimeout = 0)); } }
}
machine TcTbotLbOneBadBackendBounded {
  start state I { entry { new DriverLpDialFault((mode = 1, upDialTimeout = 30)); } }
}
machine TcAgentStuckDialAlpn {
  start state I { entry { new DriverAgentRedial(false); } }
}
machine TcAgentStuckDialHttpProxy {
  start state I { entry { new DriverAgentRedial(true); } }
}
machine TcSessionLeakPinsConn {
  start state I { entry { new DriverSessionLeak(true); } }
}
machine TcSessionLeakControl {
  start state I { entry { new DriverSessionLeak(false); } }
}
machine TcPresenceFlapWrongCause {
  start state I { entry {
    new DriverProxyPathErrors((kd = AK_DB_PG, scenario = 4, targetUp = true, canReissue = true));
  } }
}
machine TcResumptionFaults {
  start state I { entry {
    new DriverResumption(2);
  } }
}

// =============================================================================
// Modules + tests
// =============================================================================

module Tunnel = { World, Agent, Proxy, LocalProxy, Client, ResClient, ResServer,
                  DriverTunnelFault, DriverProxyPathErrors, DriverResumption,
                  DriverLpDialFault, DriverAgentRedial, DriverSessionLeak };

// --- expected to PASS: recovery liveness across fault types -----------------
test tcRstIdle [main=TcRstIdle]:
  assert RecoveryLiveness in (union Tunnel, { TcRstIdle });
test tcSilentDropIdle [main=TcSilentDropIdle]:
  assert RecoveryLiveness in (union Tunnel, { TcSilentDropIdle });
test tcProxyDrain [main=TcProxyDrain]:
  assert RecoveryLiveness in (union Tunnel, { TcProxyDrain });

// --- expected to PASS: faithful error attribution when layers do their job --
test tcTargetDownPg [main=TcTargetDownPg]:
  assert ErrorAttribution in (union Tunnel, { TcTargetDownPg });
test tcTargetDownMongo [main=TcTargetDownMongo]:
  assert ErrorAttribution in (union Tunnel, { TcTargetDownMongo });
test tcAgentGonePg [main=TcAgentGonePg]:
  assert ErrorAttribution in (union Tunnel, { TcAgentGonePg });
test tcAgentGoneKube [main=TcAgentGoneKube]:
  assert ErrorAttribution in (union Tunnel, { TcAgentGoneKube });
test tcAgentGoneSsh [main=TcAgentGoneSsh]:
  assert ErrorAttribution in (union Tunnel, { TcAgentGoneSsh });
test tcPresenceExpired [main=TcPresenceExpired]:
  assert ErrorAttribution in (union Tunnel, { TcPresenceExpired });

test tcOneWayProxyLossIdle [main=TcOneWayProxyLossIdle]:
  assert RecoveryLiveness in (union Tunnel, { TcOneWayProxyLossIdle });
test tcFlapRst [main=TcFlapRst]:
  assert RecoveryLiveness in (union Tunnel, { TcFlapRst });

// --- expected to FAIL: each counterexample trace is a documented UX gap -----
test tcMidSessionRst [main=TcMidSessionRst]:
  assert ErrorAttribution in (union Tunnel, { TcMidSessionRst });
test tcMidSessionBlackhole [main=TcMidSessionBlackhole]:
  assert ErrorAttribution in (union Tunnel, { TcMidSessionBlackhole });
test tcOneWayAgentLossDial [main=TcOneWayAgentLossDial]:
  assert ErrorAttribution in (union Tunnel, { TcOneWayAgentLossDial });
test tcOneWayProxyLossDial [main=TcOneWayProxyLossDial]:
  assert ErrorAttribution in (union Tunnel, { TcOneWayProxyLossDial });
test tcDialDuringBlackhole [main=TcDialDuringBlackhole]:
  assert ErrorAttribution in (union Tunnel, { TcDialDuringBlackhole });
test tcDialDuringRst [main=TcDialDuringRst]:
  assert ErrorAttribution in (union Tunnel, { TcDialDuringRst });
test tcAgentGoneMongo [main=TcAgentGoneMongo]:
  assert ErrorAttribution in (union Tunnel, { TcAgentGoneMongo });
test tcAgentGoneApp [main=TcAgentGoneApp]:
  assert ErrorAttribution in (union Tunnel, { TcAgentGoneApp });
test tcCertReissueFail [main=TcCertReissueFail]:
  assert ErrorAttribution in (union Tunnel, { TcCertReissueFail });

// --- wave 2: unhealthy endpoints, wedged dials, leaks, misattribution -------
test tcLpDialHungBackend [main=TcLpDialHungBackend]:
  assert ErrorAttribution, DialBounded in (union Tunnel, { TcLpDialHungBackend });
test tcTbotLbOneBadBackend15m [main=TcTbotLbOneBadBackend]:
  assert ErrorAttribution, DialBounded in (union Tunnel, { TcTbotLbOneBadBackend });
test tcTbotLbOneBadBackendBounded [main=TcTbotLbOneBadBackendBounded]:
  assert DialBounded in (union Tunnel, { TcTbotLbOneBadBackendBounded });
test tcAgentStuckDialAlpn [main=TcAgentStuckDialAlpn]:
  assert RecoveryLiveness in (union Tunnel, { TcAgentStuckDialAlpn });
test tcAgentStuckDialHttpProxy [main=TcAgentStuckDialHttpProxy]:
  assert RecoveryLiveness in (union Tunnel, { TcAgentStuckDialHttpProxy });
test tcSessionLeakPinsConn [main=TcSessionLeakPinsConn]:
  assert ErrorAttribution in (union Tunnel, { TcSessionLeakPinsConn });
test tcSessionLeakControl [main=TcSessionLeakControl]:
  assert ErrorAttribution in (union Tunnel, { TcSessionLeakControl });
test tcPresenceFlapWrongCause [main=TcPresenceFlapWrongCause]:
  assert ErrorAttribution, CauseFidelity in (union Tunnel, { TcPresenceFlapWrongCause });

// --- resumption stream integrity across detach/reattach ---------------------
test tcResumptionFaults [main=TcResumptionFaults]:
  assert ResumptionSafety in (union Tunnel, { TcResumptionFaults });
