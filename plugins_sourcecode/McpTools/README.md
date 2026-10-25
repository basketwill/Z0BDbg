# Local MCP Server

### Automatic debugger startup

The local MCP Server can start the debugger when the model first requests local tools. Set the debugger executable and startup timeout in the left-side local server settings, then save the configuration. The debugger must load the MCP Tools plugin configured to connect back to the local MCP Server. Remote MCP settings are not used for this local flow.

`McpServer.exe` listens on the address and port in `McpServer.ini`. In local
mode it serves the tools registered by the debugger's MCP Tools plugin directly;
the optional remote settings are only a forwarding layer.
Closing or minimizing the main window keeps the server running in the system
tray. Double-click the tray icon to restore the window. Its right-click menu
provides Open, About and Exit; Exit stops the server and closes the program.

## Data cache

The Data cache management controls govern an in-memory copy of the remote
`tools/list` result. The default is enabled, with a 300-second TTL and a
1024-KB maximum entry size. Valid cached data is returned without contacting
the remote server. An expired entry is fetched again; if that fetch fails, the
server returns an empty tools list. Tool call results are never cached because
calls may change debugger state.

The window shows cache bytes, age, hits and misses. `Tools list` forces a
refresh; `Clear cache` immediately invalidates the entry. Changing remote
connection or cache settings also invalidates it. The cache is lost when the
process exits. Settings are stored under `[cache]` in `McpServer.ini` beside
the executable:

```ini
[cache]
enabled=1
ttl_seconds=300
max_kb=1024
```

The allowed TTL is 1-86400 seconds and the allowed size is 1-10240 KB.

## Model conversation

The rightmost section of `McpServer.exe` has an optional model conversation area. Set
the remote MCP URL first, then select a provider preset (Qwen, DeepSeek, or GLM)
or enter any Chat Completions compatible model API URL and model name. Enter
the provider's API key, type a request, and select Send. Changing providers
clears the previous API key and conversation. The server loads the
remote `tools/list`, sends its tool schemas to the model, executes returned
`tools/call` requests, and displays the model's answer. The UI shows the tool
name and arguments used for each call. Clear chat starts a new conversation.
The JSON button switches the conversation area to the most recent model
request and raw response body, formatted for reading when they contain valid
JSON. It does not show the API key or HTTP headers; the view is held in memory
and cleared when the conversation is cleared.

The Terminal button beside Send opens a separate console window with the current
saved model and remote MCP settings. It runs the same model and tool-call flow
with its own conversation history, independently of the main window. Enter
one prompt per line. `/multi` accepts a multi-line prompt until an empty line,
`/history` displays recent messages, `/clear` starts a new conversation,
`/skill` manages local skills, `/help` lists commands, and `/exit` closes the console. The terminal shows
tool names and arguments before each answer. Completed conversations are
cached under `%LOCALAPPDATA%\McpServer\terminal-<profile>.json` and restored
when the same model and MCP configuration is used again. `/clear` deletes
that profile's saved messages while retaining its active skill. The cache contains conversation content and
tool results, but not the API key.

Enter `/skill` to list saved skills and see commands. `/skill add NAME`
collects instructions until a line containing only `.`; `/skill save` writes
the draft and activates it. `/skill show NAME` displays its content,
`/skill use NAME` activates a saved skill, and `/skill off` disables it.
Names use letters, digits, hyphens and underscores. Each skill is saved as
`%LOCALAPPDATA%\McpServer\skills\NAME\SKILL.md`. The active skill is restored
with terminal history and included in the model's system message on each turn.
These local prompt skills do not install Codex skills or add MCP tools.

Model settings are saved under `[model]` in `McpServer.ini`. The API key is
stored as plain text in that local file, as the existing MCP tokens are.
Keep access to the file restricted to the current user. GUI conversations
are held in memory; terminal conversations use the local cache described
above. The model API URL must be HTTPS, except for a local HTTP endpoint.

Provider-specific request handling is selected from the model URL host:
Alibaba Cloud Qwen models add `enable_thinking=false` for tool calls; GLM
can send the selected `reasoning_effort`. DeepSeek's response can include `reasoning_content`
beside `content` and `tool_calls`; it is preserved in assistant history for
subsequent requests with tools. Qwen may return null `content` alongside
`tool_calls`; its continuation uses an empty string. GLM and other
compatible endpoints use the standard `choices[0].message.tool_calls` shape.
Custom models at a recognized provider endpoint use that provider's handling.

The request bodies share `model`, `messages`, `tools` and `tool_choice` because
all three configured URLs are Chat Completions compatible endpoints. The
provider-specific fields are:

| Provider | Additional request field | Response fields used |
| --- | --- | --- |
| Qwen | `"enable_thinking":false` for Qwen models | `choices[0].message.content`, `tool_calls`; null content becomes an empty string when continuing a tool call |
| DeepSeek | None for the compatible endpoint | `content`, `tool_calls`, and `reasoning_content`; reasoning content is retained in later tool-enabled requests |
| GLM (`glm-*`) | Selected `reasoning_effort` value, unless Auto | `content` and `tool_calls` from the standard compatible response |

For example, a Qwen request includes `{"model":"qwen-plus", ..., "enable_thinking":false}`;
a GLM Coding Plan request set to High includes `{"model":"glm-4.5", ..., "reasoning_effort":"high"}`.
The preset stores the Coding Plan Base URL
`https://open.bigmodel.cn/api/coding/paas/v4`; the client appends
`/chat/completions` when sending an OpenAI Chat Completions request.
A DeepSeek tool response may include
`{"message":{"content":null,"reasoning_content":"...","tool_calls":[...]}}`.
The remote MCP request remains JSON-RPC `tools/call` for every provider.

The rightmost model settings include Reasoning: Auto, Low, Medium or High.
Auto omits `reasoning_effort`; Low, Medium and High send the corresponding
JSON field for OpenAI, GLM and custom compatible endpoints. The GLM preset defaults
to Low to preserve its prior behavior. Qwen and DeepSeek do not use this
field, so the control is disabled for those presets. A custom endpoint must
support the field itself; unsupported values are reported by its API.

Advanced model settings provide a maximum output token count (0 uses the
provider default), a model request timeout (5-300 seconds), optional
Temperature (0-2) and Top-p (greater than 0, up to 1), and Tool choice.
Auto lets the model decide whether to call a tool. Required asks it to call
a tool; this needs an MCP server with advertised tools. None sends a plain
chat request without an MCP URL or tool schemas. OpenAI requests use
`max_completion_tokens`; Qwen, DeepSeek, GLM and custom compatible endpoints
use `max_tokens`. Empty sampling values omit their JSON fields. Providers and
specific models may reject unsupported sampling values or tool modes; the
model API error is shown in the conversation. These settings are saved in
`McpServer.ini` and used by both the GUI and terminal conversations.

Max tool rounds (1-50, default 12) limits completed model-to-MCP call cycles;
the bridge permits one final model response after the last allowed cycle.
History messages (2-100, default 24) bounds the message count sent to the
model, including the system message. Older complete turns are removed when
needed; the 256-KB request limit still applies. Stream replies is off by
default. When enabled, the bridge sends `"stream":true`, reads Chat
Completions SSE events and assembles streamed tool calls before executing
them. The GUI and terminal show answer text as it arrives. The GUI Send
button becomes Stop during a request and closes the active model HTTP request
when pressed. The JSON view shows the raw SSE response in this mode.

The model bridge validates MCP tool names and object input schemas before
sending them. Names outside the common function-name character set receive a
model-facing alias, which is mapped back to the original MCP name on calls.
The bridge accepts tool arguments as either a JSON string or object and
validates all calls in a batch before execution. Its local guard allows at
most 128 advertised tools and eight calls in one model turn; these are bridge
limits, not vendor limits.

Model API requests retry at most twice after HTTP 408, 429, or selected 5xx
responses. `Retry-After` seconds or HTTP dates are honored up to 30 seconds. HTTP
400/401/403/404 errors are reported without retry, including the provider's
JSON error message when available. The model area marks known tool-capable
presets as supported, embedding/rerank models as unavailable, and other model
IDs as unverified. Unverified models can still be tried.
Previous conversation turns are removed as complete groups when the request
would exceed 24 messages or the bridge's local 256-KB request limit. A current
turn that alone exceeds the byte limit returns an error instead of sending an
oversized request. This byte limit does not represent a vendor token limit.
