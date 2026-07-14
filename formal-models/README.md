# Teleport connectivity & recording — P formal models

Formal models (in the [P language](https://p-org.github.io/P/)) of two Teleport
subsystems, built to find failure modes that don't surface cleanly to end users.
These are **analysis artifacts, not product code** — nothing here is imported by
Teleport, and the branch is not intended to merge.

Modeled against `gravitational/teleport` @ `master` `67276143` (v19). Checked with
P 3.1.0 (`dotnet tool install --global P`).

## Layout

| Path | What |
|---|---|
| `model/TeleportTunnel.p` | Agent reverse-tunnel + `tsh`/`tbot` client-to-target path (SSH/db/app/kube), resumption, dialers. 29 tests. |
| `model-recording/RecordingUpload.p` | Session-recording multipart upload pipeline (S3 backend): recorder → ProtoStream → uploader → completer. 10 tests. |
| `01-tunnel-state-model.md` | Cited state machines for the tunnel stack (the modeling source of record). |
| `02-diagrams.md` | Mermaid diagrams (render locally or on GitHub). |
| `03-findings.md` | Tunnel model-checking results + findings F1–F15. |
| `04-issue-drafts.md` | Issue-style writeups generated from tunnel counterexamples. |
| `05-recording-findings.md` | Recording-upload model + findings R1–R9. |

Every finding is anchored to a specific `file:line` in the Teleport source; the
model proves a bad state is *reachable*, and the citation shows the code that
produces it.

## Running

```sh
# tunnel model
cd model && p compile && p check --list-tests
p check -tc tcTbotLbOneBadBackend15m -s 300      # e.g. the reported tbot ~15m hang

# recording model
cd ../model-recording && p compile && p check --list-tests
p check -tc tcPartFailHole -s 300                # incomplete-upload-marked-complete
```

A failing test emits a counterexample trace under `<test>/BugFinding/` — that
trace *is* the finding. See the two findings docs for the full matrix and which
tests are expected to pass vs. fail (an expected failure is a documented gap).

## Scope

One proxy replica, one agent replica. Out of scope: proxy peering, vnet, trusted
(leaf) clusters. The tunnel model parameterizes agent type; the recording model's
S3 machine is the only backend-specific component (see `05-recording-findings.md`
§5 for rerunning against GCS/Azure/filesystem semantics).
