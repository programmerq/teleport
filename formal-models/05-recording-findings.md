# Session Recording Upload — State Model & Findings

Companion model: `model-recording/RecordingUpload.p` (P 3.1.0, compiles, 10 tests).
Code: `gravitational/teleport` @ `master` `67276143` (v19), **S3 backend** unless noted.
All `file:line` are in that tree.

**What this models**: the multipart-commit protocol that turns a session's event stream into a
finalized storage object, focused on **lost / incomplete / corrupt recordings**. The model is
message-driven (no numeric clock): the corruption bugs are about the *order* of upload / list /
complete / crash operations, not timer values, so P's scheduler explores the interleavings. The
grace-period / session-tracker guard is a boolean the driver sets, so each scenario can exercise
both "guard holds" and "guard bypassed".

**Integrity oracle**: the full recording is chunks `0..N-1` (a chunk = one flushed part's events).
A finalized object's coverage must equal exactly `{0..N-1}`, once each, in order. Missing tail =
truncation; missing middle = hole; a chunk from the wrong writer = interleave. Spec
`CompletedImpliesComplete` asserts this on every finalize; `NoSilentLoss` asserts a session that
produced data never reaches a terminal aborted/lost state.

## 1. Pipeline (node mode, async, the common case)

```
 session events
   │  SessionWriter.RecordEvent  (buffers; DROPS on backoff, returns nil)   session_writer.go:271-368
   ▼
 ProtoStream (on the AGENT, writing to local disk)                          stream.go / filesessions
   │  slices → parts (128 KiB local / 5 MiB to S3); UploadPart = rename N.reservation→N.part
   │  session end → CompleteUpload(TRACKED parts) → combine into <sid>.tar   filestream.go:168-258
   ▼
 filesessions.Uploader  (scans <sid>.tar every 5s, re-streams over gRPC)    fileasync.go:204-856
   │  CreateAuditStream / ResumeAuditStream(checkpoint UploadID)
   ▼
 auth ProtoStream  →  S3 MultipartHandler                                    s3sessions/s3stream.go
   │  UploadPart(1,3,5,…)  →  CompleteMultipartUpload(TRACKED parts)
   ▼
 <bucket>/<path>/<sid>.tar   (bucket versioning on; reads take OLDEST version) s3handler.go:536-566
```

Two other actors gate correctness:
- **UploadCompleter** (auth *and* every agent): every ~5m, for uploads past a **24h grace** with
  **no live session tracker**, does a fresh `ListParts` → `CompleteUpload(listed)` — the pattern you
  recalled (`complete.go:224-351`). Auth also synthesizes `session.end` if missing.
- **SessionTracker** (30m TTL): the "is this session still alive?" signal the completer trusts.

**Sync modes** (`node-sync`/`proxy-sync`) skip the disk tier — events stream straight to auth's
ProtoStream. On audit failure the session's fate is set by role `record_session` mode, not the
node/proxy axis: `strict` → session killed (`sess.go:2443-2449`); `best_effort` → recording disabled,
session continues unrecorded (`sess.go:2438-2442`).

## 2. Test matrix

| Test | Scenario | Spec | Result |
|---|---|---|---|
| `tcHappy` | 3 chunks, no faults | integrity+loss | ✅ pass |
| `tcCompleterClean` | crash after all parts up, completer finishes | integrity+loss | ✅ pass |
| `tcResumeCkptClean` | resume, checkpoint == committed | integrity | ✅ pass |
| `tcBackoffDropsTail` | SessionWriter drops tail chunk, completes rest | integrity | ❌ **R1: 2/3 chunks, marked complete** |
| `tcPartFailHole` | a middle part's upload fails, complete proceeds | integrity | ❌ **R2: hole, marked complete** |
| `tcCompleterTruncates` | tracker "abandoned" while producer had more | integrity | ❌ **R3: completer finalizes a prefix** |
| `tcResumeCkptLoss` | optimistic checkpoint claims > committed | integrity | ❌ **R4: resume skips a never-committed chunk** |
| `tcZeroPartAbort` | abandoned upload, 0 parts | loss | ❌ **R5: aborted, no object, no session.end** |
| `tcGraceStrands` | guard holds; host removed before combine | loss | ❌ **R6: stranded parts lost on decommission** |

## 3. Findings

### R1 (HIGH) — A failed part upload becomes a hole, and the recording is finalized as complete
**Model**: `tcPartFailHole` — object covers 2/3, marked complete. **Code (verified by read)**:
`completeStream` (`stream.go:869-892`) drains `activeUploads`; on a part's `getPart()` error it logs
`"Failed to upload part"` and **`continue`s** (drops it from `completedParts`), then calls
`CompleteUpload` with the survivors and proceeds to synthesize session.end + metadata + summary. A
part that exhausts its 1000 retries (`stream.go:952-1048`) therefore yields a recording with a
**hole in the middle, finalized as fully successful**. (A `ReserveUploadPart` failure is different —
it cancels the whole stream via the `"uploader failed to reserve upload part"` sentinel — but a plain
part-body upload failure does not.) Fix direction: treat any dropped part in a `completeTypeComplete`
as fatal (abort + retain source) rather than completing a partial object.

### R2 (HIGH) — SessionWriter drops events on backoff without tripping strict mode
**Model**: `tcBackoffDropsTail`. **Code (verified)**: `RecordEvent` returns `nil` on both drop paths —
the fast "backoff active" drop (`session_writer.go:293-296`) and the "5s write timeout → set 30s
backoff" drop (`:347-352`). Returning `nil` means the recorder's caller sees success, so
`onWriteErrorCallback` never fires and **`strict` recording mode does not kill the session**
(`sess.go:2434-2453`). Events are silently lost (counted in `lostEvents`, surfaced only as a
`Close`-time log `"Session has lost audit events…"`, `:390`), and the eventual upload is finalized as
complete. A strict-mode operator who believes "no recording ⇒ no session" is wrong for this path.

### R3 (HIGH) — The completer can finalize a truncated/abandoned upload as the whole recording
**Model**: `tcCompleterTruncates`. **Code**: `CheckUploads` (`complete.go:224-351`) completes any
upload past the 24h grace with no live `SessionTracker`, via fresh `ListParts` → `CompleteUpload`.
Its guards (grace period, tracker presence, "recently uploaded part" skip at `:273-282`) are
*heuristics, not correctness guarantees*: a session whose tracker expired/was never created (local
fallback tracker, `sess.go:2382-2388`) while its upload is genuinely incomplete gets its **prefix
finalized as the full recording**, with a synthesized `session.end` making it look clean. This is the
`ListParts`-then-`Complete` pattern doing exactly what S3 warns against — completing with a
server-snapshot that may not be the intended whole.

### R4 (MED-HIGH) — Optimistic checkpoints let a resumed upload skip a never-committed chunk
**Model**: `tcResumeCkptLoss` (writer 1 commits 1 chunk but the checkpoint claims 2; writer 2 resumes
from the claimed index → the uncommitted chunk is never uploaded by anyone → hole). **Code**: the
disk uploader writes `StreamStatus.LastEventIndex` optimistically and unsynced (`monitorStreamStatus`,
`writeStatus` dropped-on-error, no fsync, `fileasync.go:860-874`), and resume seeds `CompletedParts`
from a fresh `ListParts` then advances past it (`stream.go:222-243, 382-398` — the code comment
itself documents "resume may replay uncommitted events → duplicate events" and a deliberate 2-part
skip). If the checkpoint's index ran ahead of what actually committed, resume produces a **hole**
rather than a benign duplicate. `tcResumeCkptClean` (checkpoint == committed) passes — the bug is
strictly the divergence.

### R5 (MED) — Zero-part abandoned uploads vanish with no recording and no session.end
**Model**: `tcZeroPartAbort` (`RECORDING LOST`, reason `RL_ZERO_PARTS`). **Code**: `CompleteUpload([])`
delegates to `AbortMultipartUpload` (`s3stream.go:165-167`), and the completer `continue`s at
`complete.go:296-298` **before** the `SessionUpload`/session.end-recovery block. A session that
created an upload but committed no parts (e.g. crash before first flush, or all parts dropped per
R1/R2) disappears with no object and **no synthesized end event** — the only trace is the earlier
`session.start`.

### R6 (MED) — Async parts are stranded for 24h; host teardown before then loses them
**Model**: `tcGraceStrands` (`RECORDING LOST`, reason `RL_DECOMMISSION`). **Code**: when a node
crashes after writing `multi/<uploadID>/*.part` but before combining into `<sid>.tar`, recovery
depends on the *agent's own* UploadCompleter, which won't act until the tracker is NotFound (≤30m)
**and** 24h grace elapses on both `Initiated` and last part (`complete.go:237-282`). In async node
mode auth never sees these parts. If the host is decommissioned (autoscaling, spot reclaim, disk
wipe) inside that window, the recording is permanently lost with no server-side trace.

### R7 (MED, code-read — not model-checked) — No fsync anywhere in the disk recorder
`PlainFileRecorder` does `ReservePart`/`WritePart`/`CombineParts` with **zero `Sync`/`fsync`/`O_SYNC`**
(`filesessionrecorder.go`; grep-confirmed across `lib/events` recording paths). Atomic `os.Rename`
gives ordering, not durability. On host **power loss** (not clean SIGKILL) any part, the combined
`.tar`, or the `.checkpoint` whose page-cache write wasn't yet persisted can be missing or truncated →
lost/corrupt recording. (Not in the P model — durability under power loss is outside a message-order
model; flagged for a separate crash-consistency check.)

### R8 (LOW-MED, code-read) — Recorder `Done()` → discard swap silently unrecords the tail
Once the stream dies, `session.recordEvent` swaps in a discard recorder and returns nil
(`sess.go:2422-2431`); all later session I/O is silently unrecorded while the session continues. Same
"looks fine, isn't" class as R2.

### R9 (LOW-MED, S3-specific, code-read) — Grace decisions key off node wall-clock and a non-snapshot ListParts
Live-stream parts carry `LastModified = time.Now()` on the *node*, not S3's part time (explicit TODO,
`s3stream.go:123-128`), and `ListParts` pagination is not a consistent snapshot (`s3stream.go:229-241`).
Clock skew or a part landing mid-pagination can make the completer's "recently uploaded part" guard
(R3's main defense) fire wrong, widening the R3 premature-completion window.

## 4. Verified-good (worth knowing)

- The happy path, a clean completer finish (all parts present), and an accurate-checkpoint resume all
  preserve integrity — the protocol is correct when no part is dropped and the guards hold.
- Bucket **versioning + read-oldest-version** (`s3handler.go:536-566`) genuinely defends the *final
  object* against a second completion overwriting it — but only if versioning is enabled (it is, on
  Teleport-created buckets; operator-managed buckets that skip `ensureBucket`'s version-enable are
  exposed).
- The completer **semaphore** (`MaxLeases=1`, `complete.go:164-215`) prevents two auth servers
  double-completing — unless `Semaphores==nil` (misconfig), where the guard is skipped.

## 5. Answering "rerun with another backend"

The corruption findings split cleanly by *where the bug lives*:

- **R1–R6 are producer/completer-logic bugs** (drop-and-complete, backoff drop, completer heuristics,
  checkpoint optimism, zero-part abort, 24h stranding). They live above the storage handler and
  **reproduce on every backend** — the same `ProtoStream`/`UploadCompleter`/`SessionWriter` code runs
  regardless of S3/GCS/Azure/file.
- **R9–R10 are S3-semantics bugs.** Only S3 has *mutable* parts (last-writer-wins per part number,
  no ETag provenance check) and a non-snapshot `ListParts`. GCS and Azure upload parts as
  **immutable, precondition-guarded** objects (`If(DoesNotExist)` / `CommitBlockList` with
  `blobDoesNotExist`), and complete via server-side compose/commit — so the part-overwrite and
  list-race classes **cannot occur** there; a re-upload fails `AlreadyExists` instead of silently
  overwriting (`gcssessions/gcsstream.go:96,108`; `azsessions/azsessions.go:557-564`). The filesystem
  backend uses rename-atomic parts + a flock on completion. So: to reproduce R1–R6 on GCS/Azure,
  swap the `S3` machine's `UploadPart` semantics for an idempotent-precondition variant and rerun the
  same tests (they should still fail — the producer logic is unchanged). R9/R10 should *not* reproduce.
  This is a ~1-machine swap in the model — the `S3` machine is the only backend-specific part.

## 6. Reproducing
```
cd model-recording/ && p compile
p check -tc tcPartFailHole -s 300      # R1 counterexample
p check --list-tests                   # all 10
```

## 7. Fidelity caveats
- Message-order model, no wall-clock: precise timings (5m flush, 24h grace, 30m tracker TTL) are
  abstracted to "before/after" orderings — enough to prove the corruption is *reachable*, not to
  predict its frequency. R7 (power-loss durability) and R9 (clock skew) are outside this abstraction
  and are code-read only.
- One session, one upload, chunk-granular (a "chunk" abstracts one flushed part's events); the
  two-tier disk-then-auth path is collapsed to one commit protocol — the tier that owns the final
  object. Sync vs async and strict vs best-effort are noted in prose, not enumerated as tests here.
- The `S3` machine is deliberately the only backend-specific component (see §5).
