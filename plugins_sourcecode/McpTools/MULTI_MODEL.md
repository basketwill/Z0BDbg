# Multi-Model Agent

## Mach-O Static Open (Initial Support)

`Z0BDbg.exe -ida <file>` and the static file menu recognize thin Mach-O and
Universal/Fat Mach-O independently from the PE reader. Fat files prompt for an
architecture slice before the static view opens. The upper-left pane shows the
Fat architecture table, selected Mach-O header, load commands and segment/section
fields; the selected slice is also available as raw bytes. It does not yet decode
symbols or arm64 assembly. `static_macho_info` reports validated header fields and
all architecture slices to the model. Existing `static_pe_info` and other PE
specific static tools still require a PE file. Invalid Mach-O load-command or
Fat slice bounds are rejected before opening the static view.

PE static tools also work while a process is open in the debugger. Without an
active `-ida` view they read the current debug target's main executable from
disk; no extra UI action is required. Addresses in these results use the PE
preferred image base, which may differ from the loaded base under ASLR. The
tools are omitted from the catalog when neither a static view nor a debug target
is available.

Open Settings, then **Multi-model...** in the model panel. The existing model
configuration is the primary model. Three additional model slots are available.
Each slot has its own URL, model name, API key, reasoning effort and timeout.
Output limits and sampling settings are inherited from Advanced settings.

- **Auto route** chooses an enabled model whose keywords match the user message.
  Separate keywords with commas, semicolons, pipes or newlines. Matching ignores
  case; the longest matching keyword wins, with slot order breaking ties.
  Messages without a match use the primary model.
- **Failover** tries another enabled model when a model request or its response
  fails validation. The selected model is tried first, then the primary model,
  then slots 1-3. Each endpoint/model/account combination is tried once per
  round, using the existing HTTP retry policy. Completed MCP calls are retained
  in the conversation and are not replayed by the fallback mechanism.
- **Review** sends the primary answer and recent conversation/tool results to
  enabled slots marked **Reviewer**. Reviewers receive no executable tools.
  Their conclusions appear after the primary answer. A failed review leaves
  the primary answer available. Reviewers identical to the executing model's
  endpoint and model name are skipped.

All three options default to off. Model and routing events are shown in the
conversation. A model that does not support required tool calls is skipped.
Routing uses configured keyword rules, not a separate classifier model.

## CLI Commands

- `/models`: show primary/additional models and agent options, without keys.
- `/model auto`: use keyword routing (or primary when routing is disabled).
- `/model primary`: use the primary model first.
- `/model 1`, `/model 2`, `/model 3`: use that enabled slot first.
- `/model <model-name>`: select a unique configured model name (case insensitive).
  Use slot numbers when names are duplicated. `/model` lists available models.
- `/settings`: show current settings, accepted values and ranges (no API keys).
- `/set <setting> <value>`: change a setting for subsequent requests.
- `/effort high`: shortcut for `/set effort high`.
- `/save`: persist only settings changed in this CLI, and refresh the running GUI
  associated with the same executable. Failed saves can be retried.
- `/reload`: reload settings saved by the GUI or in `McpServer.ini`.

Settings commands:

| Setting | Values | Scope |
| --- | --- | --- |
| `effort` | `auto`, `low`, `medium`, `high` | Currently displayed model |
| `timeout` | 5-300 seconds | Currently displayed model |
| `tokens` | 0-65536 (0 uses provider default) | All models |
| `temperature` | 0-2 or `default` | All models |
| `top_p` | Above 0, up to 1, or `default` | All models |
| `tool_choice` | `auto`, `none`, `required` | All models |
| `tool_rounds` | 1-1000 (default 12) | Ordinary chat |
| `round_warning` | 1-20 (default 3) | Chat and managed tasks |
| `time_warning_seconds` | 10-600 (default 60) | Chat and managed tasks |
| `task_rounds` | 0 or 1-1000 (default 32) | Managed tasks; 0 disables the round limit |
| `task_timeout_seconds` | 0 or 10-86400 (default 3600) | Whole run; 0 disables the total timeout |
| `history` | 2-100 messages | All models |
| `stream` | `on`, `off` | All models |
| `auto_route`, `failover`, `review` | `on`, `off` | Agent |

For example, `/model 1`, `/effort high`, `/set timeout 120`, `/save` configures
slot 1. In automatic mode, effort and timeout target the model displayed in the
footer (the last routed model, or primary initially). Provider support still
determines which reasoning/sampling fields are sent. Model selection is session
only; `/save` saves parameter changes. `/reload` discards unsaved changes.

### Model Setup And MCP Settings

CLI setup is also available before a model is configured. Model fields are
`name` (alias `model_name`), `url` (alias `model_url`) and `api_key`.
Prefix a model field with `primary.`, `1.`, `2.` or `3.` to configure a specific
slot, including a disabled slot. Slot fields also include `enabled` (on/off),
`keywords` (comma-separated routing keywords) and `reviewer` (on/off).
Changing a model URL clears its old API key. Configure the name and URL before
enabling a slot. Disabling the selected slot returns selection to automatic.

```text
/set 1.name qwen-plus
/set 1.url https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions
/set 1.api_key
/set 1.enabled on
/set 1.keywords asm, crash
/set 1.reviewer on
/model 1
/save
```

`/set api_key`, `/set 1.api_key` and `/set mcp_token` prompt for hidden secret
entry. Secrets are omitted from settings output and conversation history.
Use `/set api_key clear` to remove a key. Values are persisted in the existing
INI format by `/save`.

| Setting | Values |
| --- | --- |
| `mcp_url` | HTTP/HTTPS URL, or `clear` |
| `mcp_token` | Hidden entry, or `clear` |
| `mcp_transport` | `streamable-http`, `sse` |
| `mcp_verify_tls` | `on`, `off` |
| `mcp_timeout` | 100-300000 milliseconds |
| `mcp_retry_interval` | 100-300000 milliseconds |
| `mcp_max_retries` | 0-1000 (0 means unlimited) |
| `cache_enabled` | `on`, `off` |
| `cache_ttl` | 1-86400 seconds |
| `cache_max_kb` | 1-10240 KB |

Endpoint changes reset the old connection and tool cache. Saved changes refresh
affected GUI controls; GUI refresh waits until an active chat finishes.

Manual model choice applies to subsequent messages in the current CLI session.
Failover and review remain independently configurable. Existing `/skill`,
`/history`, `/multi` and `/clear` commands continue to work.

Settings are saved in `[agent]` and `[agent_model_1]` through `[agent_model_3]`
sections. The INI template lists the supported keys.

## Managed Tasks

`/task <goal>` starts a task with a structured plan, sequential steps and an
observable completion criterion for each step. `/task` or `/plan` shows the
current plan, step states and verification reasons. `/task cancel` cancels the
task between requests. Ordinary chat remains available; `/set task_mode on`
enables managed tasks for ordinary prompts and GUI chat, and `/save` persists
that preference. Task mode defaults to off.

```text
/task Set a breakpoint at the current function entry and verify it exists
/plan
/verify
/set task_retries 2
/save
```

Planning and verification use separate model requests with no executable tools.
The execution model works on one step at a time. After each batch of MCP calls,
the verifier compares actual results to the criterion and cites evidence IDs.
The client checks those IDs: failed, fabricated, truncated or earlier-step
evidence cannot complete a step. Observation/mutation steps require successful
read-only observations; a mutation additionally requires an observation after
the latest attempted state change. Text-only analysis steps can be assessed from
their candidate answer. Semantic assessment is performed by the model, not a
general deterministic proof engine.

Failed checks return a reason and adjustment to the execution model. Each step
allows `task_retries` (0-5, default 2) corrective retries, within the existing
tool-round limit. Exhausted retries or malformed verification block the task;
blocked tasks require a new `/task` or `/verify`. Transport success or a model
saying "done" does not by itself mark an observation/mutation step complete.
Failed or interrupted state-changing operations have an uncertain outcome and
require read-only verification or explicit `/resume retry` before repetition.

`/verify` rechecks the current task with fresh observations. It enforces
read-only tool calls and never replays writes or debugger execution operations.
Read-only classification uses MCP `annotations.readOnlyHint`, or the shared
Z0BDbg read-tool list for older plugin versions. Unknown tools without an
annotation cannot provide read-only verification evidence.

Progress, criteria, actual tool results and final states are recorded as JSON
under `%LOCALAPPDATA%\McpServer\tasks`. Current version-2 records also contain
operation receipts and conversation checkpoints and can be resumed from the CLI.

Clear debugger requests in ordinary CLI input (such as debugging an executable,
observing breakpoint hits, or analyzing an executable file) automatically enter
managed task mode. The planner creates observable steps and completion criteria;
general questions remain ordinary chat. An interrupted managed task resumes
through `/resume <task-id>`, including one started automatically.

`/observations [task-id]` shows concise debugger observations with evidence
receipt numbers; `/evidence <receipt-id>` expands the saved tool result. The
existing `/timeline [task-id]` retains all raw execution timeline entries.

For repeated software breakpoint hits, the managed task catalog exposes
`sample_breakpoint_hits` when `run`, `wait_debug_event`, and
`get_debug_context` are available. It requires an existing breakpoint
`address`, `max_hits` (1-16), and `timeout_seconds` (1-120). Each continuation
uses normal permissions, audit, target checks, and task checkpoints. Sampling
stops on a different pause, target change, event gap, call budget, cancellation,
or timeout. It leaves the target paused after the final requested hit; if stopped
while waiting, the target may still be running. The returned hit records include event cursors
and stop data. Use this tool only when the user requested repeated hits with
automatic continuation.
Completed execution-control operations can run again only after the paused
debugger context revision advances. Unknown outcomes still require recovery.

## Task Collaboration

Enable collaboration after configuring model slots:

```text
/set collaboration on
/set coordinator 0
/set tool_rounds 20
/team
/save
/task Analyze the current exception, inspect the relevant function, and explain the cause
/plan
/results
```

`coordinator` uses slot 0 (primary) or 1-3. The coordinator produces a plan with
`model_slot` and `depends_on` for each step, verifies worker results, and integrates
the final answer. Dependencies are 1-based earlier steps; future or duplicate
dependencies are rejected. Missing assignments use step-specific keyword routing.
Disabled/unconfigured assignments block execution before task tools run.

Workers execute steps sequentially against the shared debugger. Each receives
verified prior results, evidence IDs and actual observations. Results become shared
only after verification; summaries cannot complete steps. Task records include
assigned/actual model slots, dependencies and shared results. Failure switching
keeps the successful replacement for the remaining rounds of that step and does
not replay successful MCP operations. Planner, verifier and final integration
requests have no executable tools. Collaboration also enables managed tasks for
ordinary prompts. A manual `/model` choice still controls ordinary non-collaborative
chat; collaboration uses the plan's assignments.

## Context Management

```text
/context
/compact
/set context_auto on
/set context_budget_kb 192
/set context_recent 6
/set tool_result_kb 8
/set context_summary_kb 4
/save
```

The budget is the actual serialized provider request size in KB, not a token
estimate. Every execution round, fallback, planning, verification and review
request is checked. Provider token limits remain separate. `context_budget_kb`
accepts 16-256, `context_recent` 2-20 complete message/tool blocks,
`tool_result_kb` 1-32, and `context_summary_kb` 1-16. Settings use `[context]`.

Over-budget execution requests summarize old complete blocks with a tool-free
model request. `history_limit` is a soft compression trigger; protected recent
blocks may exceed that count when the byte budget allows. `/compact` forces the
same summarization process. The actual current user request, latest request,
recent blocks, and tool-call/reply pairs are preserved. Large tool outputs sent
to models are explicitly marked head/tail excerpts with original byte counts;
original outputs stay in conversation memory until their blocks are summarized.
Task verification continues using its separate evidence records and existing
evidence size limits, rather than filtered model context.

Summary memory is persisted with CLI history, identified as unverified data, and
its internal marker is removed from provider requests. Failed/cancelled summaries
leave history unchanged. When protected context or the tool schema alone cannot
fit, execution stops with a budget error. Planning/verification requests are not
summarized because doing so could remove required task evidence. Existing local
history persistence limits still apply. Workers execute sequentially by default;
independent analysis steps may run concurrently with `parallel_workers > 1`. After a
restart, task recovery is explicitly selected with `/resume <task-id>`.

## Operation Permissions And Audit

```text
/permissions
/set permission_mode readonly
/set permission_mode confirm
/save
/audit
```

| Mode | Read-only | Modification | Dangerous/unknown |
| --- | --- | --- | --- |
| `readonly` | Automatic | Refused | Refused |
| `confirm` (default) | Automatic | Confirm each call | Confirm each call |
| `modify` | Automatic | Automatic | Confirm each call |

Known debugger tools share a classification with the plugin. Reads are read-only;
breakpoint edits and debugger view changes are modifications; memory/code writes,
execution/stepping, bulk deletion and persistent configuration writes are dangerous.
Unknown tools default to dangerous unless a read-only annotation identifies them
as reads. Known modifications/dangerous tools cannot downgrade their classification
with `readOnlyHint`; `destructiveHint` also raises the risk to dangerous. The plugin's
existing permission switches are an independent enforcement layer.

CLI confirmations show the tool, risk and exact arguments and require `yes`.
GUI model requests use a confirmation dialog defaulting to No. Raw JSON-RPC proxy
requests have no interactive confirmation channel and return a permission error
for calls requiring confirmation; `modify` permits their classified modifications.
The shared gate applies to every executable model tool call and JSON-RPC proxy call.

Every allow, denial, confirmation, receipt reuse and dispatch outcome is appended
and flushed to `%LOCALAPPDATA%\McpServer\audit\YYYY-MM-DD.jsonl`. Entries include UTC
time, operation/task/step IDs, model slot, source, MCP connection fingerprint,
classification, decision, outcome and arguments. Common credential field names are
redacted; argument excerpts are marked. Full tool responses are kept in task records
subject to existing limits. Audit files are local records, not tamper-proof storage;
arbitrary sensitive values inside tool arguments/history may still be present.
When audit or the pre-dispatch checkpoint cannot be saved, the command is not sent.

`/set permission_mode` is saved as `[permissions] mode=0|1|2`. There is no option to
disable confirmation for dangerous tools or disable the audit gate.

## Task Recovery

```text
/tasks
/resume <task-id>
/plan
/results
```

Managed tasks atomically persist a checkpoint before dispatch and a receipt after
the response. Checkpoints include the plan, verified steps, evidence, assigned and
actual models, operation IDs, canonical arguments, outcome and conversation memory.
A per-task file lease prevents two running sessions from executing the same task;
stale loaded checkpoints are rejected. Files remain under the existing task folder.

`/resume` requires confirmation that the debugger still uses the same target/session
and checks the MCP connection fingerprint. Completed steps remain completed. An
incomplete tool-call/reply block is removed from restored model history; its operation
ledger remains. The interrupted step uses fresh read-only observations, invalidates
its old evidence, and never automatically repeats a dispatched modification. Once
the step is verified, remaining steps may proceed under the permission policy.

A matching completed modification (same step, tool and canonical arguments) reuses
its saved receipt without sending a command. Canonicalization handles object key
order and whitespace; it does not infer equivalent addresses/expressions. A missing
receipt after dispatch, transport failure or failed mutation is uncertain. Successful
fresh verification resolves that uncertainty. If the criterion cannot be verified,
the task stops; inspect the target before explicitly authorizing:

```text
/resume retry
```

This separately confirms and audits the risk of repeating prior changes in the current
step, resets its receipts for retry, and keeps all previous operations in the ledger.
Ordinary operation confirmations still apply. Ctrl+C requests cancellation; closing
or crashing the process leaves the most recent on-disk checkpoint for later recovery.
An in-flight command may finish remotely even after cancellation.

This is client-side recovery, not an exactly-once guarantee from the remote server.
The updated plugin additionally exposes a process/session identity. Managed tasks
compare it during execution and recovery; a target replacement invalidates the old
task. Servers lacking that extension still require explicit user confirmation and
fresh reads, and guarded modifications are refused. Version-1 records, corrupt records and unfinished
plans are not inferred into executable checkpoints. Automatic background resumption
is not enabled. Use `/task` for crash recovery with operation receipts. Ordinary
CLI chat saves each complete round and a continuation marker. After a round or
time limit, `/continue` (or `继续`) resumes from saved history. At the round limit,
a final no-tool request records partial findings, unresolved work and the next step
when the time budget permits. When a non-read-only
call was in flight, `/continue` permits only read-only verification; after reviewing
`/history`, `/continue retry` explicitly authorizes further changes. This does not
prove the prior operation's outcome or automatically repeat it. Ordinary chat still
has no managed-task operation ledger. When the pending call has a target identity,
recovery first checks that the debugger still has the same session and process.
An unknown mutation result stops the current batch before later calls are sent.

## Adaptive Execution And Runtime

```text
/set task_replans 2
/set task_rounds 32
/set debug_guard on
/set event_wait_seconds 30
/set collaboration on
/set parallel_workers 2
/debug
/capabilities
/events
/events wait
/cancel <task-id> <step-number|all>
```

Verification may request `replan` to choose a different approach. Exhausted ordinary
step retries also trigger replanning when authorized and budget remains. The coordinator
revises unfinished execution strategies/model assignments while retaining step order,
dependencies, completion criteria, kinds, verified steps and operation receipts.
Plans weakening criteria are rejected. Uncertain changes and recovery stay read-only;
replanning cannot authorize their repetition. Defaults allow two replans and 32 managed
execution rounds; configure 0..5 replans and 1..128 rounds. Evidence, operation and
evaluation limits also bound execution. Tasks stop on missing authorization, cancellation,
unavailable prerequisites or exhausted budgets; goal completion is not guaranteed.

The plugin's `get_debug_context` extension returns a runtime-v1 session ID, process ID,
CPU thread ID, numeric debugger status, context revision, event cursor and live module
list (at most 128 modules; `modules_known=false` when enumeration fails). Status 18
means paused. The session identity changes on target changes and plugin restarts.
Thread/status/module/stop changes invalidate current evidence; older completed evidence
is retained as history but excluded from live shared results. Verifier assessments are
discarded if context changes while the model reasons. Guarded commands carry expected
target/revision in MCP `params._meta`, checked by the updated plugin before dispatch.
Paused state is required for ordinary inspection/modification; run/go/pause/status and
runtime tools have their own use.

`debug_guard` defaults on for managed tasks. A server without `get_debug_context` can
still serve read-only tasks, but guarded modifications are refused. Explicitly setting
`debug_guard off` enables legacy servers without session protection. Runtime guarantees
depend on debugger callbacks and this extension, not on the base MCP protocol. Manual
debugger edits and servers ignoring `_meta` cannot be protected by the client mutex.

`/capabilities` forces discovery and shows a catalog fingerprint, risks and input schemas.
Managed execution refreshes tools each model round and before each dispatch. Removed
tools and incompatible parameters return corrective errors without dispatch. Local
validation checks object/array/scalar types, required fields, enums, numeric/array bounds
and additional-property exclusions; advanced JSON Schema rules remain the server's
responsibility. The plugin omits tools whose required host exports are missing; runtime
extensions include their version in descriptions. Structured JSON parsing separates
tool names from arguments, including numeric/hex addresses, named arguments and Unicode.

`wait_debug_event` implements cursor-based long polling for up to 1000 ms per request,
with a 256-event ring. Breakpoints/exceptions, target exits and state transitions wake
waiters even when outbound forwarding is disabled. `gap=true` identifies lost events
or a cursor from an earlier feed. Managed run/go/step/trace calls wait for a pause event
and refresh state before continuing, within `event_wait_seconds` (1..300 seconds).
Timeout/failure leaves the task unverified and never reissues the run command. This is
a debugger extension, not a universal MCP subscription API; servers without it retain
ordinary execution. Event payloads are untrusted data, not executable instructions.

With collaboration enabled, `parallel_workers` (1..4, default 1) allows consecutive,
independent, ready analysis steps to run concurrently on assigned models. Children
receive verified shared data and no tools. Dependency-bound analysis and debugger
operations remain ordered. Managed tasks using tools own an exclusive mutex for their
MCP URL throughout execution; individual chat/proxy operations use the same lock.
Different credentials at the same URL share the lock. URL aliases, different user/session
namespaces and unrelated clients are not a distributed transaction lock. Waiting respects
the MCP timeout and cancellation. Child usage is merged into the parent's evaluation.

Ctrl+C cancels all active children. From another CLI with the same MCP configuration,
`/tasks` lists checkpoints and `/cancel <task-id> <step>|all` signals active analysis children.
Cancellation is cooperative: a pending non-streaming HTTP call may finish or time out
before the child exits. Cancelled results are not verified and dependent work does not
execute. Checkpoints retain session identity, revision, evidence revision and replan count;
older version-2 checkpoints without these fields remain readable. These settings are
stored in `[agent]`; use `/save` to persist CLI changes.

## Long-Term Memory

```text
/set memory_project my-project
/set project_path D:\source\my-project
/memory index
/memory import <UTF-8 file>
/memory add knowledge <project note>
/memory add preference <user preference>
/memory search <query>
/memory list
/memory forget <id>
/memory sync
```

New requests automatically retrieve relevant local notes for planning and execution.
Default retrieval matches identifiers and adjacent Chinese characters. Optional
semantic reranking uses the configured primary chat model. Project knowledge and results are isolated by
`memory_project` plus the normalized `project_path`; explicitly saved preferences are global. Preferences are not
inferred from conversation. Historical notes cannot authorize tools and are not
inserted into the verifier's evidence. Verified completed tasks are automatically
archived once per project/task. Failure-rated results from the same run are excluded.

`/memory sync` explicitly imports completed version-2 checkpoints matching the current
MCP connection into the current project, examining at most 256 files in filesystem
enumeration order. Existing memories and failure-rated tasks are skipped. Version-1
records are not imported. Importing old results does not confirm the current target state.

Indexing reads UTF-8 `.md` and `.txt` documents, at most 1024 files and three directory
levels, skipping hidden/system/reparse and build/vendor directories. Each file is
limited to 64 KB and split into UTF-8-safe chunks. Changed/deleted source documents
invalidate their old recall entries; reindex to refresh. Each scope holds at most
8192 entries; user notes are not automatically evicted. Local JSON files are under
`%LOCALAPPDATA%\McpServer\memory`. Chat and Skill storage remain separate.

Settings: `/set memory_enabled on|off`, `memory_hits 1..10`,
`memory_context_kb 2..16`, `memory_project <name>` and `project_path <directory>|clear`.
Use `/save` to persist CLI configuration. INI uses `[memory] enabled`, `project`,
`project_path`, `hits`, and `context_kb`.

## Task Evaluation

```text
/eval
/eval last
/eval models
/eval export <file>
/rate success
/rate failure
/set primary.input_price 2
/set primary.output_price 8
/set primary.cached_input_price 0.5
/set primary.price_currency USD
```

Each conversation run records elapsed time, model phase, HTTP attempts, reported
input/output/cache/reasoning tokens, and tool proposals, dispatches, successes,
failures, denials, invalid proposals, reused receipts and uncertain operations.
Task success uses the latest run per task ID and verifier results; a user rating
overrides that outcome. Unrated ordinary chat, running tasks and cancelled tasks
are excluded from the success denominator and reported separately. Tool success
means a successful MCP result, not proof of the user's full goal. Verified/planned
steps are reported separately. Elapsed time includes confirmation waits.

Prices are user-configured amounts per million tokens, not downloaded vendor rates.
Use `primary.` or `1.`/`2.`/`3.` prefixes for independent model prices; `clear` removes
a price. Changing model name/endpoint clears old rates. USD/CNY totals remain separate.
Missing rates, usage, or a required cache rate produce unknown cost, not zero.
Known subtotals are estimates; earlier HTTP retry billing is unknown. Streaming usage
can be enabled with `/set stream_usage on` only when the provider accepts
`stream_options.include_usage`; it defaults off.

Snapshots are saved before/after model calls and tool dispatch, so interrupted runs
remain visible. `/eval` reads at most the latest 512 run records in the current project.
Records live in `%LOCALAPPDATA%\McpServer\evaluations`; there is no outbound telemetry.
`/set evaluation_enabled off` disables recording. INI uses `[evaluation] enabled`
and `stream_usage`; prices are stored in `[model]` and `[agent_model_N]`.

## Verification Tests

`AgentModelsTest.cpp` uses fake model responses to check routing, failed and
malformed responses, preserved tool history, cancellation, reviewer isolation,
provider-specific history conversion, and manual model choice. Live API
availability depends on configured endpoints, keys and model capabilities.
Tests also cover scoped memory, Chinese matching, stale documents, checkpoint
imports, rating corrections, token/cache pricing, interrupted runs, task deduplication,
streamed usage, evaluation export and settings persistence. These are simulated
tasks; they do not measure live model task success or actual provider invoices.
Runtime tests also cover replanning/criteria retention, target replacement, stale
evidence, catalog changes, parallel overlap/cancellation, resource conflicts and event
gaps. `DebugRuntimeTest.cpp` executes the native plugin dispatcher in a test host,
including module enumeration, metadata rejection and breakpoint long polling with
forwarding disabled. Real debugger/model workflows still require end-to-end validation
with the configured target and API.

## Semantic Knowledge Recall

```text
/set memory_semantic on
/memory search how to inspect a failing process
/memory fact build-mode Build with debug symbols
/memory conflicts
/memory resolve <chosen-fact-id>
/memory expire <id> 2027-12-31
/memory expire <id> clear
```

Semantic recall is explicit opt-in and scans all eligible scoped candidates in batches
of 32 excerpts (1024 bytes each), then recursively reranks the batch selections. IDs
and sources go to the primary chat model with tools disabled. Candidates are ordered
by lexical relevance then recency. This uses model reranking rather than an embedding
database. Relevance beyond the excerpt and discarded batch selections can be missed. Failure or
invalid/foreign/duplicate IDs fall back to lexical recall. Conversation retrieval calls
are measured under the `retrieval` phase; standalone `/memory search` is not a task run.

Retrieved entries include source metadata and instruct the model to cite facts using
`[memory:<id>]`. Citations are grounding instructions, not a guarantee of answer truth.
Dates use UTC and are valid through the specified day. Expired or superseded entries
and changed/deleted documents are excluded from recall. Two active entries with the
same project and explicit fact key but different text are both excluded until the user
chooses one with `resolve`; other entries are marked superseded, retaining their source.
`/memory audit` also scans pairs of active scoped entries for contradictions in prose.
It requires semantic retrieval enabled and sends excerpts to the configured model;
pairwise scans can incur substantial requests/cost for large collections. Detected
pairs are suspected conflicts, excluded from recall until `/memory resolve <id>`
selects an entry. The model can miss conflicts or flag compatible statements; inspect
`/memory conflicts` and the source before resolving. Scans do not select a winner.

## Repeatable Debugger Benchmarks

```text
/bench
/bench run before-fix sample-crash-01 3
/bench run after-fix sample-crash-01 3
/bench compare <baseline-id> <candidate-id>
```

The fixed `debugger-observe-v1` suite has three basic live observation tasks: target
identity/context, paused status (18), and current CPU thread. It runs 1-10 repetitions
using the selected model, fresh task/history state, no memory, read-only permissions
and target guards. Start the same fixture and pause the debugger before each batch.
The debugger resource lock is held across the batch. Missing runtime support prevents
the batch from starting; target/session/revision changes or cancellation stop it.

Pass requires task verification plus a nontruncated successful tool receipt matching
the actual runtime snapshot. A model claiming completion without the required tool
evidence fails. These checks establish the observation criteria; they do not evaluate
arbitrary natural-language interpretations or complex crash diagnosis.

Reports under `%LOCALAPPDATA%\McpServer\benchmarks` contain fixture/version labels,
suite, actual runtime context, executable stamp, catalog fingerprint, selected model,
model configuration, requested case count and each case's full timing/usage/cost/tool
measurements. Results using fake transports/models are tagged `simulated`; real configured
connections are tagged `live`. Compare requires completed batches with the same suite,
fixture label and sample type, and reports passed/total and mean recorded time per case.
Interrupted reports are retained but excluded from comparison. Fixture labels are user
provided; use the recorded context to verify that the initial fixtures were equivalent.
No live success rate is claimed by the automated regression tests.

## Project And Target Execution Isolation

```text
/set memory_project crash-investigation
/set project_path D:\work\sample-project
/set permission_mode readonly
/set isolation_target on
/set isolation_tools get_debug_context,get_status,get_cpu_thread_id,read_memory,disassemble
/set isolation_calls 64
/set isolation_argument_kb 16
/set isolation_result_kb 256
/isolation save
/isolation bind
```

Project policies are stored under `%LOCALAPPDATA%\McpServer\policies` and keyed by
project/path and MCP connection identity. Every new run/request intersects the saved
policy with session configuration: neither model output nor looser session settings can
widen the saved tool list, risk permissions or quotas. Explicit `/isolation save` updates
the project policy. `bind` pins the current live target/session; replacement is refused
until the user explicitly binds the new target. Identity remains pinned across policy saves.
Target guards require a server supporting runtime identity and dispatch metadata.

The gate covers chat, GUI, raw JSON-RPC `tools/call` and internal observations. Internal
reads consume call budget and must be in the allowlist (include `get_debug_context`
and `wait_debug_event` when needed). Budgets are per run/request, including each resumed
run; raw requests have independent budgets. Tool responses exceeding the limit are
discarded and modifying operations become uncertain rather than automatically retried.
HTTP reception is bounded before large allocation; SSE buffering also has global size
and pending-response limits. Existing HTTP timeouts still bound individual calls.

Knowledge, evaluation and policy scopes include project name/path. Task checkpoints
also include server identity; conversation files include project/path, connection and
the explicitly pinned target identity. Rebinding loads a different conversation scope.
Changing CLI scope loads that scope's conversation and clears the active task/rating;
GUI conversations likewise reject history from a different project/connection.
Task evidence/receipts remain separate by task ID, with existing task/resource locks.
Old unscoped checkpoints and pathless memories are retained but are not automatically
imported into a new scoped project. Global preferences remain intentionally shared.

## Deeper Tasks And Headless Evaluation

BuildTerminalTests.cmd also builds `DebugAgentFixture.exe` for each architecture.
Run it under Z0BDbg with `DebugAgentFixture.exe D:\work\suite.json`. At its initial
break, the generated suite checks a known memory cell, expression evaluation,
CALL decoding and call destination. With `--crash`, continue past the initial break
to the access violation before running the suite. Generated addresses are valid only
while that exact fixture process remains alive. `--describe` only emits the suite.

```text
/bench run baseline fixture-call 3 D:\work\suite.json
/bench run candidate fixture-call 3 D:\work\suite.json
/bench compare <baseline-id> <candidate-id>
McpServer.exe --agent-bench candidate fixture-call 3 D:\work\suite.json
```

Custom suites contain an ID and 1-16 cases, each with a goal and 1-8 checks specifying
`tool`, `arguments` and `expected`. Tools must be known read-only capabilities with
valid arguments. The expected object matches a subset of the tool result; arguments
match canonical JSON exactly. A nontruncated successful receipt and completed task
are required. Comparisons require identical suite fingerprints. Headless execution
uses the executable's INI settings and exits 0 for all passed, 1 for failed cases,
or 2 for interrupted/unavailable/invalid runs. These regression tasks test defined
observations, not open-ended diagnostic accuracy or live model success rates.

## Server Enforcement And Process Limits

`McpTools.agent-isolation.ini.template` documents plugin settings to merge into
McpTools.ini. `[agent_isolation]` enforces project scope, target metadata, tools,
read quotas and optional address bounds on the server, including legacy aliases.
`/isolation` prints the scope digest to put in the plugin's `scope` setting.
When address bounds are set, indirect evaluation/navigation is refused; only
bounded memory/disassembly and basic runtime observations are allowed.

For local stdio helpers, `[stdio] isolate=1` uses a restricted Windows token,
selective standard-handle inheritance and a Job Object limiting processes, memory
and CPU time. Closing the job terminates children. Startup fails closed if Windows
denies token/job setup. Only SystemRoot/TEMP/TMP and explicit configured variables
are inherited. Resource/token restrictions are not a complete filesystem or network
sandbox. Remote servers and external debugger clients are outside this containment.

## Cancellation, Retry And Recovery

The Agent terminal uses a full-screen transcript viewport. Mouse wheel and
PageUp/PageDown scroll only earlier output; the draft input and model/effort row
remain at the bottom. New output preserves a scrolled view, and submitting a
prompt returns to the latest output. Resizing reflows the transcript. Console
selection mode is disabled so mouse events reach the viewport; host-level copy
behavior depends on the terminal. Hidden API-key entry is never added to the
transcript.

```text
/set task_timeout_seconds 300
/set read_retries 2
/recover
/resume <task-id>
```

The deadline accepts 10-86400 seconds, read retries 0-3. HTTP requests have independent
cancellation watchers: cancelling one worker does not close another's request.
The deadline stops new work and aborts owned HTTP requests. Only failed read-only
transport requests reconnect/retry; modifications are never retried automatically.
Each attempt consumes budgets and is recorded. Checkpoints preserve receipts and
uncertain writes. `/recover` lists incomplete tasks for the current scope; resume
performs fresh verification rather than blindly replaying completed writes.
Recovery is explicit, and does not promise uninterrupted execution across crashes.

## Deterministic Task Contracts

`/taskfile <file.json>` imports a goal and steps with read-only `checks` containing
`tool`, `arguments` and an `expected` result object. See
`fixtures/paused-target.task.json`. Every observation or mutation step must have
checks. The actual server catalog and argument schemas are validated before work.
The local checker compares structured result fields; model approval cannot override
a failed assertion. Only the newest matching receipt in the current step/revision
counts, and truncated/error results do not count. Mutation checks must follow the
write. Replanning preserves assertions; checkpoints preserve and validate them.
Ordinary model-generated plans without checks still use the existing model verifier.

## Debug Fixture V2 And Diagnosis Evaluation

`DebugAgentFixture.exe --describe` emits five cases: known memory, expression,
CALL decoding, three CALLs, and a two-level pointer chain. A live fixture emits
its suite with process-specific addresses; use the suite while that process lives.
`--breakpoint` adds a stop-reason case; `--crash` adds an access-violation diagnosis
case after continuing past the initial breakpoint under the debugger.
`--repeat-breakpoints` adds the stop-reason case and executes 30 numbered
`DebugBreak` calls after the initial stop, with 100 ms between resumed stops.
Cases with `expected_answer` hide reference values from the model and require a
final JSON diagnosis. Reports separately record `evidence_passed` and
`diagnosis_passed`, plus budget/routing/capability/price configuration.
Repeat the suite with the existing `/bench` command and compare saved reports.
Passing simulated regressions does not establish live model success rates;
run the fixture against each actual provider and debugger version to measure them.

### Live Long-Run Regression

Build the fixture with `CodexBuild\BuildTerminalTests.cmd x86` or its x64 variant.
Use an isolated debugger and MCP server instance, with a separate test project and
model profile. Start `DebugAgentFixture.exe <suite.json> --repeat-breakpoints`
under Z0BDbg and connect the Agent CLI to that debugger. Record the fixture PID,
debugger session, MCP endpoint and CLI version before starting. The generated suite
belongs only to that process; never reuse it after restarting the fixture.

1. At the initial pause, request `get_debug_context`; save its session and cursor.
   Resume, wait for a breakpoint event, and repeat through all 30 numbered hits.
   Each event must advance the cursor, identify the same fixture PID/session and
   allow exactly one continuation. Reject gaps, duplicated hits and unrelated PIDs.
2. While paused on a middle hit, disconnect and reconnect the MCP transport. Check
   the fresh debugger context before resuming. A changed target/session must block
   replay; a matching target may continue at the next cursor without duplicating a
   modifying call.
3. Use a small context budget and enough Agent rounds to trigger compression during
   the remaining hits. Verify that the final answer cites fresh event evidence and
   that the compressed history keeps complete tool call/reply pairs.
4. Interrupt the CLI between two hits, restart it and use `/continue` for ordinary
   chat or `/resume <task-id>` for a managed task. Verify the saved cursor and target
   before continuing, and inspect `/history` and `/evidence` afterward. An operation
   with an unknown result requires read-only verification and explicit retry approval.

Keep the test transcript, server/debugger versions, hit count, cursor sequence,
connection failures and final answer with the run record. This is a live integration
gate: `AgentModelsTest.cpp` uses simulated tools and does not establish that these
four scenarios passed against a real debugger and model provider.

## Token And Cost Budgets

```text
/set context_budget_tokens 32000
/set task_token_budget 100000
/set task_cost_budget 0.25
/set budget_currency CNY
/set primary.input_price 2
/set primary.output_price 8
/set primary.price_currency CNY
/budget
```

Zero token limits and `task_cost_budget off` disable limits. Input/output prices
are per million tokens. Fees require known prices in the budget currency; no
currency conversion is performed. Before sending, the Agent reserves input plus
maximum output, reducing the output limit when needed. Parallel workers share
the ledger. Actual usage releases excess reservations; missing usage retains
them, including failed/uncertain requests. Budgeted HTTP requests do not retry
internally. Managed tasks persist reservations before sending in a companion
`.budget.json` checkpoint and retain them on recovery; a journal failure stops work.
New settings apply to the next run; enabling budgets cannot reconstruct spending
from earlier runs that had no ledger.

Admission estimates use serialized UTF-8 bytes plus 128, not a vendor tokenizer.
These deliberately conservative limits can reject requests that would fit.
Fees are estimates rather than a billing guarantee: provider-reported usage,
pricing and output-limit compliance still matter. A response that exceeds the
ledger prevents proposed tools from executing. For an absolute financial limit,
also configure the provider account's spending cap.

## Adaptive Routing

```text
/set auto_route on
/set routing_mode balanced
/set primary.context_tokens 32000
/set 1.quality 90
/set 1.latency_ms 1500
/set 1.tool_calls on
/route diagnose this exception
```

Modes are `keyword`, `balanced`, `quality`, `economy`, and `latency`.
Manual `/model` selection takes priority. Adaptive selection excludes unusable
endpoints, disabled profiles, insufficient configured windows, missing tool-call
capability and incompatible cost settings. Scores combine configured quality,
keyword matches, request reliability, recorded task outcomes, measured latency
and configured prices. Unassigned collaboration workers and fallback order use
the same policy. `/route` displays scores and historical sample counts.
History is scoped to the project and model name plus endpoint digest.
Quality is a user-provided hint; shared-task outcomes are observational data,
not independent proof of each participating model's diagnostic quality.

## Large Knowledge Collections

```text
/set memory_vector on
/set memory_candidates 64
/set memory_cache_seconds 300
/memory index
/memory search <query>
```

The local persistent index uses normalized hashed Latin/Chinese term vectors and
cosine similarity. It is lexical vector retrieval, not a neural embedding service
or an approximate nearest-neighbor database. Modified entries alone are revectorized;
unchanged documents retain their chunks and timestamps, and shortened files remove
obsolete chunks. Deleted/modified sources, expired/conflicting/superseded facts and
unverified results are excluded. Parsed documents are reused after checking file
timestamps. Query results cache for 0-3600 seconds, invalidated by corpus, scope,
model credentials/configuration, retrieval settings and the UTC date.
With vectors enabled, semantic reranking examines at most `memory_candidates`
(16-256) candidates, reducing model requests. This trades recall for cost: knowledge
with no shared terms can miss the shortlist. `memory_vector off` retains full
semantic reranking across the bounded corpus. No extra model API is needed for
the local index. Index/cache files are data, never fresh debugger evidence.

## Durable Background Queue

```text
/queue add Use fresh evidence to inspect the paused target
/save
/queue start
/queue
/queue pause <id>
/queue continue <id>
/queue cancel <id>
/queue resume <existing-task-id>
/queue stop
/watch <id>
```

Queue records are scoped to project plus MCP connection, with creation order and
a single worker per scope. Up to 128 records are retained. The hidden worker runs
independently of the Agent window. Closing that window does not stop it; `/queue stop`
does. Pause/cancel controls persist and interrupt active HTTP work. Continue keeps
checkpoint receipts and performs read-only recovery before unfinished work.
After worker/process/OS restart, `/queue start` reloads saved entries; there is no
Windows service or automatic startup installation. Missing/invalid checkpoints
block interrupted entries instead of replaying them. Queue execution is read-only;
changes requiring interactive confirmation block and must be handled in the foreground.
Active Skill instructions and the selected model are captured when enqueueing;
other settings load from the saved INI, and changing scope stops the worker.

Event waits persist cursor and target identity in task checkpoints. `/queue resume`
can adopt an interrupted waiting task. The worker subscribes with the saved cursor,
checks fresh paused state, and refuses a changed target/session before resuming.
Unavailable/disconnected feeds are retried while waiting; a cursor/checkpoint or
identity error blocks the task. An existing queue entry uses `continue`, not a
second `resume` entry. Completed/cancelled entries cannot restart.

## Explicit Access Policy And Strict Helpers

```text
/set isolation_files D:\AgentProject
/set isolation_network https://model.example|http://127.0.0.1:8765
/set isolation_strict on
/set isolation_require_remote on
/isolation save
```

Allowlist entries use `|`. File paths must be absolute, within existing configured
directories, and cannot traverse reparse points, UNC/device paths, alternate data
streams or reserved DOS devices. Nested tool file/URL arguments are checked.
Unknown tools are refused in strict mode. HTTP/SSE/model destinations use exact
scheme, host and port matching; redirects are disabled. This constrains requests
made by this client, not arbitrary code on a remote machine.
`/isolation save` pins the policy to the current project and MCP connection.
Saved strict policy applies before model requests; session and saved allowlists
are intersected, so session settings cannot widen the saved access policy.

Merge matching `[agent_isolation] strict/files/network/scope/require_target` into
the plugin INI. The native dispatcher applies the same checks to tools and aliases.
`get_isolation_policy` reports the policy; with `isolation_require_remote`, the
client requires matching version, scope, strict policy, target guard and allowlists.
Third-party servers lacking this contract are refused. This is policy negotiation
with a trusted server, not proof of a remote OS/container sandbox. Remote host
isolation still belongs to the server operator. Protect server credentials and INI.

For local helpers, `[stdio] strict=1` additionally requires a Windows 8+ AppContainer
with no network capabilities and the existing resource/token/handle restrictions.
`[stdio] files` lists dedicated existing directories; opt-in adds persistent
read/write/execute ACL grants for the container SID on those directories.
Include the helper binary directory and data directory. The profile/SID derives
from command and policy, so changing policies uses a different container identity.
Windows grants to system resources/ALL APPLICATION PACKAGES still apply; these
directories are additional application-data grants, not a claim that every other
OS path is inaccessible. Use narrow dedicated directories. Grants/profile remain
after exit and can be managed in Windows ACL/profile tools. Strict mode has no
fallback to ordinary process creation if AppContainer, ACL or token setup fails.
The regression environment denies restricted process creation: fail-closed startup
is tested, but actual AppContainer file/network behavior needs a supported host.

## Collaboration Visibility And Disagreements

`/watch <task-id>` pins a live subtask panel above the input/model footer; `off`
detaches it. `/watch` shows the current task. History still scrolls separately.
`/task` prints proposals, group, model, start/end timestamps and failure category.
`/timeline [task-id]` prints up to 256 timestamped task/model/child events.
Evaluation records include `failure_class`; classification from error messages
is a diagnostic hint, with `unknown` when no category matches.

Plans may add `agreement_group` to consecutive independent analysis steps for the
same factual question. Collaboration and enough parallel workers are required;
group members cannot depend on each other. Workers return
`{"claims":{"fact-name":"value"},"answer":"explanation"}` independently.
The Agent compares canonical claims objects before verifying/sharing results.
Different or missing claims block the group; arbitrary prose uses exact comparison
and is not semantic contradiction detection. Proposals persist in checkpoints.
`/resolve <group> <step>` explicitly selects the user's accepted proposal, records
the decision in audit/timeline, and keeps rejected proposals for inspection.
Send a message to continue subsequent steps. This resolves analysis only and cannot
override debugger observation/mutation assertions or authorize tool modifications.

## Service Recovery And Circuit Health

`/health` displays per-process model and MCP circuit states using hashed service
identities (endpoint/credentials are not printed). Three retryable failures open
the circuit for 15 seconds. Failed recovery probes increase the cooldown to
30/60/120 seconds. After cooldown, the next request is the single recovery probe;
no extra paid model request is made in the background. A successful response
closes the circuit. Cancellation releases the probe without counting a failure.
The registry is limited to 256 service identities and resets on process restart.

Read-only MCP retries back off at 250/500/1000/2000/4000 ms, within the existing
retry, cancellation and task deadline limits. Changes are never automatically
retried after an uncertain transport outcome. Following a recovered read, the
Agent rechecks target/session/revision and rejects an observation if context
changed. Existing model failover, event waits and checkpoint recovery remain in
effect. Circuit health is a transport signal, not proof that a task succeeded.

## Guarded Memory Undo

```text
/undo
/undo <operation-id>
```

Managed `write_memory` calls with valid hexadecimal bytes and size <=4096 save
the original bytes, requested new bytes and target/session in the operation
checkpoint before dispatch. An incomplete/unavailable snapshot blocks such a
write. `/undo` lists operation and rollback states. Undo requires a saved task,
the same live paused target, current write permission, explicit confirmation,
matching current bytes and server `write_memory.expected_hex` capability.
The native plugin checks expected bytes immediately before writing and reports
partial writes as failures. This is a conditional debugger write, not an OS-level
atomic transaction against unrelated external writers.

Undo intent persists before dispatch; successful undo requires complete read-back.
Interrupted/uncertain undo cannot automatically replay. Changed memory, changed
targets and servers without conditional writes are refused. Previous completion
claims are invalidated after undo; fresh read-only verification is required.
Older checkpoints and other operations (including register changes, breakpoint
changes, execution control, assembly and writes >4096 bytes) are explicitly shown
as lacking automatic rollback. The current catalog does not expose a register
write or complete breakpoint snapshot/restore contract. No general rollback is
claimed for those operations. Snapshot data contains target memory and follows
the existing local checkpoint access/storage policy.

## Inspectable Debugger Evidence

```text
/evidence
/evidence <receipt-id>
```

New managed tool receipts persist UTC observation time, project digest, target
identity, debugger context (including thread/modules when available), arguments
and SHA256 of the full returned result. Receipt IDs connect verified step results
and model conclusions to these sources. The selected receipt displays its source
and retained result; large results still obey the existing truncation limits.
The hash is for integrity comparison, not a signed attestation from the server.

`/evidence` checks the live target before displaying current-context status.
Failed, modified, truncated, legacy or unmatched-context receipts are marked
stale/unconfirmed. Freshness is the debugger context match, not a new read of
every referenced memory location. Target changes invalidate old completion
evidence. Benchmark checks now reject receipts from an older context revision.

## Scheduling, Knowledge And Operations (5-8)

```text
/set queue_workers 2
/set queue_slice_seconds 60
/set queue_max_slices 10
/queue priority <id> 5
/set embedding_url https://provider.example/v1/embeddings
/set embedding_model <embedding-model>
/set embedding_key
/set embedding_enabled on
/memory embed 8
/memory trust <id> 80
/memory dedupe
/set memory_min_confidence 50
/set sensitive_guard on
/config migrate
/storage
/storage clean 30
/storage clean 30 apply
/storage export D:\exports\agent-data.json
/config export D:\exports\agent-settings.json
/config import D:\exports\agent-settings.json
/audit query tool read_memory
/save
```

Queue priorities range from -5 to 5. Aging and consumed-slice penalties reduce
starvation; 1-4 process slots claim each task independently. Deadlines cancel
cooperatively and checkpoint read-only recovery before requeueing. This cannot
forcibly interrupt an unresponsive external server. The shared debugger resource
lock still serializes tool operations. Exhausted slices require `/queue continue`.

Embedding is opt-in and sends up to 3072 bytes per eligible knowledge item plus
queries to the configured compatible `/embeddings` endpoint. Configure its input
price per million tokens; accounting uses the configured primary price currency.
Dense normalized vectors combine with lexical retrieval by reciprocal rank fusion
and confidence weighting. Persistence supports incremental changed-item updates;
endpoint/model/revision changes build a new v2 index alongside the lexical index.
Bump `embedding_revision` when dimensions or model semantics change. The index
uses bounded cosine scans, not ANN: at most 8192 nodes, 4096 dimensions and
2,000,000 scalar values (about 1302 nodes at 1536 dimensions). Retrieval builds
1-16 batches of up to 32 items; `/memory embed` permits 1-128 batches and reports
coverage. Conflicted, stale, expired and unverified result entries are excluded.
Dedupe merges exact normalized text within equivalent scope/metadata, retains
source aliases (up to 16), and takes the lower confidence; it does not merge
semantically similar claims automatically. Trust scores are user metadata.

Saved connection credentials use current-Windows-user DPAPI. Legacy plaintext
loads remain supported; `/save` or `/config migrate` protects them. Encrypted
credentials cannot simply be copied to a different Windows account. Diagnostic
and audit output redact configured secrets and common bearer/query patterns.
New local managed JSON records, terminal histories, chat continuation markers and
task checkpoints are encrypted with current-Windows-user DPAPI before atomic disk
writes. This includes raw tool results and memory contents saved in those records.
Existing plaintext records remain readable for compatibility and are encrypted on
their next write; archived records that are never rewritten remain plaintext until
removed by the user. `AgentModelsTest.cpp` checks the encrypted bytes and round-trip.
DPAPI protects files at rest from other Windows users; the current account, the
running Agent and any process acting as that account can read them. Data sent to a
model/MCP endpoint, CLI output, debugger process memory, audit JSONL, custom files
written by tools and explicit `/storage export` output are outside this protection.
Exports are readable JSON and should be stored only at a location the user trusts.
The sensitive guard requires interactive user authorization for modifying tools,
including permissive mode; headless execution cannot supply that consent. This
is an authorization barrier against injected instructions, not a semantic detector.

Managed data writes enforce a shared 16-4096 MB quota (default 512 MB), excluding
configuration INI and files outside the managed root. Stop/cancel markers remain
writable when full. Cleanup previews by default and only deletes old terminal
task/queue/evaluation records in the current scope, preserving active and
uncertain-operation checkpoints, knowledge and audit. Export paths must be
outside managed data. Data export includes scoped memory/evaluations/queue, is
limited to 16 MB and excludes snapshots and audit; it is not a complete backup.
Portable configuration import validates all settings before applying, excludes
keys/permissions/bindings, supports versions 1/2 and clears keys on endpoint
changes. Audit queries filter current scope and scan at most 32 recent daily
files (4 MB each), displaying at most 200 matches.

## Benchmark Regression Gate

```text
/bench run baseline fixture-a 3 fixture-suite.json
/bench run candidate fixture-a 3 fixture-suite.json
/bench compare <baseline-report-id> <candidate-report-id>
/bench gate <baseline-report-id> <candidate-report-id>
/bench gate <baseline-report-id> <candidate-report-id> 0 25 25
```

The optional gate limits are allowed success-rate drop (percentage points),
elapsed-time increase (%) and estimated-cost increase (%). Defaults are 0/25/25.
Reports must be completed and use the same suite fingerprint, fixture label,
sample type and case/repeat set. Duplicate cases and invalid evaluations are
refused. The gate fails for success/time/cost regressions or unavailable cost
comparison, and saves a separate `gate-*.json` verdict. It requires known costs
in the same currency; missing prices/usage, unfinished requests or unknown retry
billing cannot silently count as zero cost. Comparison still shows timing and
success results when costs are unknown.

The headless benchmark entry point returns 0 for a passed gate, 1 for a failed
gate and 2 for invalid input/report or save failures. Use
`McpServer.exe --agent-bench gate <baseline-id> <candidate-id> 0 25 25`.
It loads the saved configuration and reports from its project scope. This is a deterministic
threshold check on recorded batches, not a statistical confidence test. Repeated
live fixture/provider runs are still needed to establish actual success rates;
the automated regression suite includes simulated tasks and native/loopback
checks and does not demonstrate paid-provider task performance.
