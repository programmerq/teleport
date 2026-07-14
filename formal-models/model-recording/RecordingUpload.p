// =============================================================================
// RecordingUpload.p — P model of Teleport's session-recording upload pipeline
//
// Source of truth: gravitational/teleport @ master 67276143 (v19), S3 backend.
// Companion: 05-recording-findings.md (cited state machines + findings).
//
// Scope: the multipart-commit protocol that turns a session's event stream into
// a finalized storage object. Focus = LOST / INCOMPLETE / CORRUPT recordings.
//
// Modeling approach (message-driven, NO numeric clock): the corruption bugs are
// about the ORDER of upload / list / complete / crash operations, not about
// specific timer values, so we let P's scheduler explore interleavings directly.
// The grace-period / session-tracker guard is modeled as a boolean the driver
// sets, so a scenario can exercise both "guard holds" and "guard bypassed".
//
// Integrity oracle: the full recording is a stream of chunks 0..N-1 (a "chunk"
// = one flushed part's worth of events). The finalized object's coverage must
// equal exactly {0..N-1}, in order, once each. Truncation = missing tail;
// hole = missing middle; interleave/overwrite = a chunk from the wrong writer.
//
// Code anchors cited inline as  // => file:line
// =============================================================================

// a stored multipart part: part number, the chunk of the stream it carries,
// and which writer generation produced it (to catch resume/interleave)
type tPart = (pn: int, chunk: int, wgen: int);

// ---- reasons a recording is lost (terminal, no complete object) ----
// RL_ZERO_PARTS   : abandoned upload had 0 parts -> AbortMultipartUpload,
//                   no object, no synthesized session.end => complete.go:296-298,
//                   s3stream.go:165-167
// RL_DECOMMISSION : agent host removed before its on-disk parts were combined /
//                   before the completer's 24h grace elapsed (async node mode)
// RL_ABORT_DATA   : an upload carrying real events was aborted
enum tLostReason { RL_ZERO_PARTS, RL_DECOMMISSION, RL_ABORT_DATA }

// ---- S3 request/response events ----
event eS3Create      : machine;
event eS3UploadPart  : (pn: int, chunk: int, wgen: int);
event eS3ListParts   : machine;
event eS3Parts       : seq[int];
event eS3Complete    : (replyTo: machine, pns: seq[int]);
event eCompleteResult: (ok: bool, reason: int);   // reason 0=ok 1=notfound 2=aborted
event eS3Abort       : tLostReason;

// ---- driver -> actor control ----
event eGo;
event eRunCompleter  : (s3: machine, abandoned: bool);
event eDecommission  : machine;
event eAck;

// ---- spec announcements ----
event eStreamSize      : int;                       // N chunks in the full recording
event eObjectFinalized : seq[int];      // object completed w/ this coverage
event eRecordingLost   : tLostReason;
event eSessionHadData  : int;                       // >=1 chunk was actually produced

// =============================================================================
// S3: one multipart upload for one session
//   CreateMultipartUpload / UploadPart / ListParts / CompleteMultipartUpload /
//   AbortMultipartUpload  => lib/events/s3sessions/s3stream.go
// =============================================================================
machine S3 {
  var parts: map[int, tPart];   // pn -> part; LAST-WRITER-WINS  => s3stream.go:80-135
  var open: bool;
  var finalized: bool;
  var aborted: bool;
  var hadData: bool;            // any UploadPart ever accepted

  start state Idle {
    on eS3Create do (owner: machine) {
      open = true;
      // s3stream.go:46-77 (Initiated not even set here)
    }

    on eS3UploadPart do (p: (pn: int, chunk: int, wgen: int)) {
      if (!open || finalized || aborted) { return; }
      // last-writer-wins per part number; no ETag provenance check
      // => s3stream.go:118 (CompleteUpload later trusts whatever is stored)
      parts[p.pn] = (pn = p.pn, chunk = p.chunk, wgen = p.wgen);
      hadData = true;
    }

    on eS3ListParts do (replyTo: machine) {
      var ks: seq[int];
      // snapshot of CURRENTLY-committed parts, ascending by number
      // => s3stream.go:212-248 (paginated, NOT a consistent snapshot vs
      //    an UploadPart that P may schedule after this handler)
      ks = sortedKeys();
      send replyTo, eS3Parts, ks;
    }

    on eS3Complete do (p: (replyTo: machine, pns: seq[int])) {
      var cov: seq[int];
      var ordered: seq[int];
      var i: int;
      if (aborted) { send p.replyTo, eCompleteResult, (ok = false, reason = 2); return; }
      if (finalized) {
        // already completed by someone else => NoSuchUpload/NotFound
        // => complete.go:286-288 "Upload not found, moving on"
        send p.replyTo, eCompleteResult, (ok = false, reason = 1); return;
      }
      if (sizeof(p.pns) == 0) {
        // CompleteUpload([]) delegates to AbortMultipartUpload
        // => s3stream.go:165-167
        aborted = true;
        if (hadData) { announce eRecordingLost, RL_ABORT_DATA; }
        else         { announce eRecordingLost, RL_ZERO_PARTS; }
        send p.replyTo, eCompleteResult, (ok = false, reason = 2); return;
      }
      // S3 assembles the object from the STORED bodies of the listed part
      // numbers (in ascending order) -- reading current parts[pn], so a part
      // overwritten by a later writer contributes the later content.
      ordered = sortSeq(p.pns);
      i = 0;
      while (i < sizeof(ordered)) {
        if (ordered[i] in parts) { cov += (sizeof(cov), parts[ordered[i]].chunk); }
        i = i + 1;
      }
      finalized = true;
      announce eObjectFinalized, cov;
      send p.replyTo, eCompleteResult, (ok = true, reason = 0);
    }

    on eS3Abort do (reason: tLostReason) {
      if (finalized || aborted) { return; }
      aborted = true;
      if (hadData) { announce eRecordingLost, reason; }
    }

    on eDecommission do (s3req: machine) {
      // host removed before the object was ever finalized (async node mode:
      // on-disk parts never combined / never streamed to auth)
      if (!finalized && !aborted && hadData) {
        aborted = true;
        announce eRecordingLost, RL_DECOMMISSION;
      }
    }
  }

  fun sortedKeys(): seq[int] { return sortSeq(keys(parts)); }
}

// insertion sort on a seq[int] (P has no builtin sort over seq we can call here)
fun sortSeq(xs: seq[int]): seq[int] {
  var out: seq[int];
  var i: int; var j: int; var v: int; var placed: bool;
  i = 0;
  while (i < sizeof(xs)) {
    v = xs[i];
    j = 0; placed = false;
    while (j < sizeof(out) && !placed) {
      if (v < out[j]) { out += (j, v); placed = true; }
      j = j + 1;
    }
    if (!placed) { out += (sizeof(out), v); }
    i = i + 1;
  }
  return out;
}

// =============================================================================
// Writer: the recording producer (SessionWriter -> ProtoStream)
//   Uploads chunks as parts, tracks completedParts, and on session end calls
//   CompleteUpload with its TRACKED list  => stream.go:864-892
//
// cfg:
//   wgen        - writer generation (distinguishes resume writers)
//   nChunks     - full stream size
//   failFrom    - inclusive chunk index at/after which uploads are DROPPED:
//                 models both "SessionWriter backoff drops events" (session_
//                 writer.go:293-296,347-352, RecordEvent returns nil so strict
//                 mode never kills the session) AND "part upload retries
//                 exhausted -> getPart error -> dropped, complete proceeds"
//                 (stream.go:872-876). -1 = drop nothing.
//   dropMiddle  - a single middle chunk to drop (hole), -1 = none
//   uploadLimit - stop after uploading this many chunks then DO NOT complete
//                 (crash/abandon mid-stream). -1 = upload all.
//   startPn     - first part number to use (resume writers start past the last
//                 committed part, with the documented +2 skip => stream.go:382-398)
//   doComplete  - whether this writer calls CompleteUpload at end
// =============================================================================
machine Writer {
  var s3: machine;
  var driver: machine;
  var wgen: int;
  var nChunks: int;
  var failFrom: int;
  var dropMiddle: int;
  var uploadLimit: int;
  var startPn: int;
  var doComplete: bool;
  var fromChunk: int;         // first chunk index to upload (resume: skip claimed)
  var tracked: seq[int];      // part numbers this writer will pass to CompleteUpload

  start state Init {
    entry (cfg: (s3: machine, driver: machine, wgen: int, nChunks: int, failFrom: int, dropMiddle: int, uploadLimit: int, startPn: int, doComplete: bool, fromChunk: int, seedPns: seq[int])) {
      s3 = cfg.s3; driver = cfg.driver; wgen = cfg.wgen; nChunks = cfg.nChunks;
      failFrom = cfg.failFrom; dropMiddle = cfg.dropMiddle; uploadLimit = cfg.uploadLimit;
      startPn = cfg.startPn; doComplete = cfg.doComplete; fromChunk = cfg.fromChunk;
      // resume: seed tracked parts from a prior writer's committed parts
      // (ProtoStreamer.ResumeAuditStream ListParts-seeds CompletedParts => stream.go:222-243)
      tracked = cfg.seedPns;
    }
    on eGo do {
      var c: int;
      var pn: int;
      var uploaded: int;
      c = fromChunk; uploaded = 0;
      while (c < nChunks) {
        if (uploadLimit >= 0 && uploaded >= uploadLimit) { c = nChunks; }   // crash: stop
        else {
          if ((failFrom >= 0 && c >= failFrom) || c == dropMiddle) {
            // dropped: this chunk never becomes a committed part, but the
            // writer keeps going and will complete with the parts it DID upload
          } else {
            pn = startPn + c;
            send s3, eS3UploadPart, (pn = pn, chunk = c, wgen = wgen);
            tracked += (sizeof(tracked), pn);
            uploaded = uploaded + 1;
          }
          c = c + 1;
        }
      }
      if (doComplete && uploadLimit < 0) {
        // normal end-of-session completion with the TRACKED parts list
        send s3, eS3Complete, (replyTo = this, pns = tracked);
      } else {
        // crashed / abandoned: never completes -> left to the UploadCompleter
        send driver, eAck;
      }
    }
    on eCompleteResult do (p: (ok: bool, reason: int)) {
      send driver, eAck;
    }
    on eS3Parts do (pns: seq[int]) { }   // unused by writer
  }
}

// =============================================================================
// Completer: finishes an ABANDONED upload
//   ListParts (fresh, server snapshot) then CompleteUpload(listed parts)
//   => complete.go:224-351 (auth: real storage, 24h grace, EnsureSessionEndEvent;
//      agent: local disk). Gated by session-tracker presence + grace period.
// =============================================================================
machine Completer {
  var driver: machine;
  var s3: machine;

  start state Ready {
    entry (d: machine) { driver = d; }
    on eRunCompleter do (p: (s3: machine, abandoned: bool)) {
      s3 = p.s3;
      if (!p.abandoned) {
        // session tracker still present OR within grace period -> skip
        // => complete.go:243-260 "session has active tracker...", early break
        send driver, eAck;
      } else {
        // tracker NotFound and past grace -> proceed to complete it
        send s3, eS3ListParts, this;
      }
    }
    on eS3Parts do (pns: seq[int]) {
      // completes with WHATEVER ListParts returned -- a truncated snapshot
      // (in-flight/uncommitted parts absent) is completed as-is.
      send s3, eS3Complete, (replyTo = this, pns = pns);
    }
    on eCompleteResult do (p: (ok: bool, reason: int)) { send driver, eAck; }
  }
}

// =============================================================================
// Specs
// =============================================================================

// SAFETY: if the object is FINALIZED (marked complete / durable / summarized),
// it must contain the ENTIRE event stream. A finalized object missing any chunk
// is a silently-truncated-or-holed recording presented as a good one.
spec CompletedImpliesComplete observes eStreamSize, eObjectFinalized {
  var n: int;
  start state NeedSize {
    on eStreamSize do (sz: int) { n = sz; goto Watching; }
    ignore eObjectFinalized;
  }
  state Watching {
    on eStreamSize do (sz: int) { n = sz; }
    on eObjectFinalized do (coverage: seq[int]) {
      assert isFullCoverage(coverage, n),
        format("INCOMPLETE UPLOAD MARKED COMPLETE: object covers {0} of {1} chunks (missing/holed/interleaved)", sizeof(coverage), n);
    }
  }
}

// SAFETY: a session that produced data must never reach a terminal LOST state
// (aborted-with-data / zero-part-abort / decommission-before-combine). Tests
// that reach it produce a counterexample = a data-loss finding.
spec NoSilentLoss observes eSessionHadData, eRecordingLost {
  var hadData: bool;
  start state Watching {
    on eSessionHadData do (k: int) { hadData = true; }
    on eRecordingLost do (reason: tLostReason) {
      assert !hadData,
        format("RECORDING LOST after data was produced (reason={0})", reason);
    }
  }
}

fun isFullCoverage(cov: seq[int], n: int): bool {
  var seen: map[int, bool];
  var i: int;
  if (sizeof(cov) != n) { return false; }
  i = 0;
  while (i < sizeof(cov)) {
    if (cov[i] < 0 || cov[i] >= n) { return false; }
    if (cov[i] in seen) { return false; }   // duplicate/interleave
    seen[cov[i]] = true;
    i = i + 1;
  }
  return sizeof(seen) == n;
}

// =============================================================================
// Drivers (one per scenario)
// =============================================================================

// Happy path + single-writer fault scenarios (drop / hole / part-fail).
machine DriverSingleWriter {
  var s3: machine;
  var w: machine;

  start state Boot {
    entry (cfg: (nChunks: int, failFrom: int, dropMiddle: int)) {
      s3 = new S3();
      announce eStreamSize, cfg.nChunks;
      if (cfg.nChunks > 0) { announce eSessionHadData, cfg.nChunks; }
      send s3, eS3Create, this;
      w = new Writer((s3 = s3, driver = this, wgen = 1, nChunks = cfg.nChunks,
                      failFrom = cfg.failFrom, dropMiddle = cfg.dropMiddle,
                      uploadLimit = -1, startPn = 1, doComplete = true,
                      fromChunk = 0, seedPns = default(seq[int])));
      send w, eGo;
    }
    on eAck do { }
    on eS3Parts do (pns: seq[int]) { }
  }
}

// Crash mid-stream, then the completer runs. `abandoned` toggles whether the
// session-tracker/grace guard has released (true = premature/bypassed).
machine DriverCrashCompleter {
  var s3: machine;
  var w: machine;
  var comp: machine;
  var nChunks: int;
  var uploadLimit: int;
  var abandoned: bool;
  var phase: int;

  start state Boot {
    entry (cfg: (nChunks: int, uploadLimit: int, abandoned: bool)) {
      nChunks = cfg.nChunks; uploadLimit = cfg.uploadLimit; abandoned = cfg.abandoned;
      phase = 0;
      s3 = new S3();
      comp = new Completer(this);
      announce eStreamSize, nChunks;
      if (nChunks > 0) { announce eSessionHadData, nChunks; }
      send s3, eS3Create, this;
      w = new Writer((s3 = s3, driver = this, wgen = 1, nChunks = nChunks,
                      failFrom = -1, dropMiddle = -1, uploadLimit = uploadLimit,
                      startPn = 1, doComplete = false,
                      fromChunk = 0, seedPns = default(seq[int])));
      send w, eGo;
    }
    on eAck do {
      if (phase == 0) {
        // writer has crashed (sent its parts, no complete). Fire the completer.
        // P will interleave the completer's ListParts with any still-in-flight
        // UploadPart, exploring the truncation race as well as the clean case.
        phase = 1;
        send comp, eRunCompleter, (s3 = s3, abandoned = abandoned);
      } else if (phase == 1) {
        phase = 2;
        if (!abandoned) {
          // guard held: nobody ever completes -> the recording is stranded.
          // model host teardown before the 24h completer grace to make the
          // loss terminal & checkable.
          send s3, eDecommission, s3;
        }
      }
    }
    on eS3Parts do (pns: seq[int]) { }
  }
}

// Resume with OPTIMISTIC-CHECKPOINT loss: writer 1 commits `w1Commit` chunks but
// the on-disk checkpoint claims `w1Claim` are done (LastEventIndex is written
// before/independently of part commit => fileasync.go monitorStreamStatus,
// writeStatus dropped-on-error, no fsync). Writer 2 resumes: seeds CompletedParts
// from ListParts (only the committed parts) and starts uploading from chunk
// `w1Claim` (trusting the checkpoint), so chunks in [w1Commit, w1Claim) are
// never uploaded by anyone -> a HOLE, then Complete succeeds. Cites the resume
// data-loss trade-off documented at stream.go:382-398.
machine DriverResumeCkpt {
  var s3: machine;
  var w1: machine;
  var w2: machine;
  var nChunks: int;
  var w1Commit: int;
  var w1Claim: int;
  var phase: int;

  start state Boot {
    entry (cfg: (nChunks: int, w1Commit: int, w1Claim: int)) {
      nChunks = cfg.nChunks; w1Commit = cfg.w1Commit; w1Claim = cfg.w1Claim; phase = 0;
      s3 = new S3();
      announce eStreamSize, nChunks;
      if (nChunks > 0) { announce eSessionHadData, nChunks; }
      send s3, eS3Create, this;
      w1 = new Writer((s3 = s3, driver = this, wgen = 1, nChunks = nChunks,
                       failFrom = -1, dropMiddle = -1, uploadLimit = w1Commit,
                       startPn = 1, doComplete = false,
                       fromChunk = 0, seedPns = default(seq[int])));
      send w1, eGo;
    }
    on eAck do {
      if (phase == 0) { phase = 1; send s3, eS3ListParts, this; }
    }
    on eS3Parts do (pns: seq[int]) {
      // seed from committed parts, resume uploading from the CLAIMED index
      w2 = new Writer((s3 = s3, driver = this, wgen = 2, nChunks = nChunks,
                       failFrom = -1, dropMiddle = -1, uploadLimit = -1,
                       startPn = 100, doComplete = true,
                       fromChunk = w1Claim, seedPns = pns));
      send w2, eGo;
    }
  }
}

// =============================================================================
// Test harnesses
// =============================================================================
machine TcHappy            { start state I { entry { new DriverSingleWriter((nChunks = 3, failFrom = -1, dropMiddle = -1)); } } }
machine TcBackoffDropsTail { start state I { entry { new DriverSingleWriter((nChunks = 3, failFrom = 2,  dropMiddle = -1)); } } }
machine TcPartFailHole     { start state I { entry { new DriverSingleWriter((nChunks = 3, failFrom = -1, dropMiddle = 1)); } } }
machine TcCompleterClean   { start state I { entry { new DriverCrashCompleter((nChunks = 3, uploadLimit = 3, abandoned = true)); } } }
machine TcCompleterTruncates { start state I { entry { new DriverCrashCompleter((nChunks = 3, uploadLimit = 2, abandoned = true)); } } }
machine TcZeroPartAbort    { start state I { entry { new DriverCrashCompleter((nChunks = 3, uploadLimit = 0, abandoned = true)); } } }
machine TcGraceStrands     { start state I { entry { new DriverCrashCompleter((nChunks = 3, uploadLimit = 2, abandoned = false)); } } }
machine TcResumeCkptLoss   { start state I { entry { new DriverResumeCkpt((nChunks = 3, w1Commit = 1, w1Claim = 2)); } } }
machine TcResumeCkptClean  { start state I { entry { new DriverResumeCkpt((nChunks = 3, w1Commit = 2, w1Claim = 2)); } } }

// =============================================================================
// Modules + tests
// =============================================================================
module Rec = { S3, Writer, Completer, DriverSingleWriter, DriverCrashCompleter, DriverResumeCkpt };

// expected PASS: clean paths
test tcHappy [main=TcHappy]:
  assert CompletedImpliesComplete, NoSilentLoss in (union Rec, { TcHappy });
test tcCompleterClean [main=TcCompleterClean]:
  assert CompletedImpliesComplete, NoSilentLoss in (union Rec, { TcCompleterClean });

// expected FAIL: incomplete-marked-complete
test tcBackoffDropsTail [main=TcBackoffDropsTail]:
  assert CompletedImpliesComplete in (union Rec, { TcBackoffDropsTail });
test tcPartFailHole [main=TcPartFailHole]:
  assert CompletedImpliesComplete in (union Rec, { TcPartFailHole });
test tcCompleterTruncates [main=TcCompleterTruncates]:
  assert CompletedImpliesComplete in (union Rec, { TcCompleterTruncates });
test tcResumeCkptLoss [main=TcResumeCkptLoss]:
  assert CompletedImpliesComplete in (union Rec, { TcResumeCkptLoss });
test tcResumeCkptClean [main=TcResumeCkptClean]:
  assert CompletedImpliesComplete in (union Rec, { TcResumeCkptClean });

// expected FAIL: silent loss
test tcZeroPartAbort [main=TcZeroPartAbort]:
  assert NoSilentLoss in (union Rec, { TcZeroPartAbort });
test tcGraceStrands [main=TcGraceStrands]:
  assert NoSilentLoss in (union Rec, { TcGraceStrands });
