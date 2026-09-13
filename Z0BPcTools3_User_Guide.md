# Z0BPcTools3 Debugger User Guide

This document describes the main UI, shortcuts, debugging features, trace features, script system, and plugin development APIs of the Z0BPcTools3 debugger.

## 1. Basic Concepts

Z0BPcTools3 is a Windows user-mode debugger with an MDI-style interface. After a debug session starts, you can open CPU, memory, stack, modules, threads, breakpoints, patches, call stack, handles, windows, SEH chain, references, source code, and other views from menus or shortcuts.

Common windows:

| English | Description |
| --- | --- |
| CPU Window | Shows disassembly, registers, data, and stack. This is the main debugging view. |
| Log Window | Shows debugger logs, plugin output, and script output. |
| Modules Window | Lists loaded EXE/DLL modules in the debuggee. |
| Memory Window | Shows memory regions and supports navigation, searching, and memory breakpoints. |
| Stack Window | Shows the current thread stack. |
| Threads Window | Lists and switches threads. |
| Breakpoints Window | Lists, deletes, and manages breakpoints. |
| Patches Window | Shows and manages patched code or data. |
| Call Stack Window | Shows the current thread call stack. |
| Trace Windows | Shows RUN trace, HIT trace, and related trace results. |

## 2. Shortcuts

| Shortcut | English Function |
| --- | --- |
| `Alt+L` | Show Log window |
| `Alt+E` | Show Modules window |
| `Alt+C` | Show CPU window |
| `F9` | Run or continue |
| `F12` | Pause or suspend debuggee |
| `Ctrl+F2` | Restart last debug command |
| `Alt+F2` | Stop current debug session |
| `F7` | Step into |
| `F8` | Step over |
| `Ctrl+F7` | Auto step into |
| `Ctrl+F8` | Auto step over |
| `Ctrl+F9` | Run until return |
| `Alt+F9` | Run to user code |
| `Ctrl+F11` | Trace into |
| `Ctrl+F12` | Trace over |
| `Ctrl+T` | Set RUN trace condition |
| `Alt+F5` | Toggle always on top |
| `-` or numpad `-` | Move CPU view back to the previous instruction position |
| `Alt+G` | Go to or follow expression in CPU view |
| `Enter` | Follow selected address or disassembly position in memory view |
| `F2` | Set memory access breakpoint in memory view |
| `Ctrl+B` | Binary search in memory view |

Note: Some shortcuts work only when the related window is active.

## 3. Menu Reference

### 3.1 File

| Menu | English Description |
| --- | --- |
| Open | Open and start debugging an executable file. |
| Attach | Attach to a running process. |
| Exit | Exit the debugger. |

### 3.2 View

The View menu opens debugger windows.

| Menu | English Description |
| --- | --- |
| Log | Open Log window. |
| Modules | Open Modules window. |
| Memory | Open Memory window. |
| Stack | Open Stack window. |
| Threads | Open Threads window. |
| Windows | Open Windows list. |
| Handles | Open Handles list. |
| CPU | Open CPU window. |
| SEH Chain | Open SEH chain window. |
| Patches | Open Patches window. |
| Call Stack | Open Call Stack window. |
| Breakpoints | Open Breakpoints window. |
| Watch | Open Watch window. |
| References | Open References window. |
| Source | Open Source window. |
| Source Files | Open Source Files window. |

### 3.3 Debug

| Menu | Shortcut | English Description |
| --- | --- | --- |
| Run | `F9` | Run or continue the debuggee. |
| Pause | `F12` | Pause the current debuggee. |
| Restart | `Ctrl+F2` | Restart the last debug command. |
| Stop | `Alt+F2` | Stop the current debug session. |
| Step Into | `F7` | Execute one instruction and enter calls. |
| Step Over | `F8` | Execute one instruction and step over calls. |
| Run Until Return | `Ctrl+F9` | Run until the current function returns. |
| Run to User Code | `Alt+F9` | Run from system code to user code. |
| Hardware Breakpoint |  | Set or manage hardware breakpoints. |
| Check |  | Open register or runtime check dialog. |
| Call DLL Export Function |  | Call exported functions from a target DLL. |
| Arguments |  | Configure command-line arguments. |
| Select Import Library Directory |  | Select import library directory. |
| Select Symbol Search Path |  | Select symbol search path. |

### 3.4 Trace

The Trace menu groups auto execution, RUN trace, HIT trace, and conditional trace features.

| Menu | Shortcut | English Description |
| --- | --- | --- |
| Auto Step Into | `Ctrl+F7` | Repeatedly execute step-into operations. |
| Auto Step Over | `Ctrl+F8` | Repeatedly execute step-over operations. |
| RUN Trace |  | Record execution path or runtime instruction information. |
| HIT Trace |  | Record hit code locations for coverage or path observation. |
| Open or Clear RUN Trace |  | Open or clear RUN trace results. |
| Trace Into | `Ctrl+F11` | Trace one step into. |
| Trace Over | `Ctrl+F12` | Trace one step over. |
| Set Condition | `Ctrl+T` | Set RUN trace condition, count, or pause behavior. |
| Stop RUN Trace |  | Stop current RUN trace. |

### 3.5 Script

The Script menu is used for ODbgScript, OllyPython, and OllyLua scripts. Script files are discovered from directories and converted into menu entries automatically.

| Script System | Directory | Description |
| --- | --- | --- |
| ODbgScript | Determined by ODbgScript settings; usually managed via the script plugin | OllyDbg/ODbgScript-style scripts. |
| OllyPython | `plugins\OllyPython\*.py` | Each `.py` file appears as `Script -> OllyPython -> filename -> Run`. |
| OllyLua | `plugins\OllyLua\*.lua` | Each `.lua` file appears as `Script -> OllyLua -> filename -> Run`. |

### 3.6 Plugin

| Menu | English Description |
| --- | --- |
| Find/Add Plugin | Select and load a plugin DLL from disk. |
| Plugin Name -> Plugin Menu Items | Each plugin is grouped by plugin name and exposes its own submenu. |

Plugins should be placed in the `plugins` directory or loaded from "Find/Add Plugin". Plugin bitness must match debugger bitness. For example, the x64 debugger requires x64 plugin DLLs.

### 3.7 Tools

| Menu | English Description |
| --- | --- |
| IDA Static Disassembly -> Memory Mode | Open IDA-style static disassembly using memory-oriented mode. Recommended for targets smaller than 50 MB. |
| IDA Static Disassembly -> Cache Mode | Open IDA-style static disassembly using cache mode. |

### 3.8 Options

| Menu | English Description |
| --- | --- |
| Properties | Open the unified settings dialog. The left side is a fully expanded tree, and the right side shows the selected settings panel. |
| JIT Debug Options | Configure just-in-time debugging options. |
| Pause at Entry Point | Pause at program entry point after launch. |
| Run Immediately | Run immediately after launch. |
| Terminate Process on Close | Terminate debuggee when closing debug window. |
| Detach Process on Close | Detach from debuggee when closing debug window. |
| Function Signature Recognition | Enable or disable function signature recognition. |
| Add to Explorer Context Menu | Add debugger entry to Windows Explorer context menu. |

### 3.9 Window

| Menu | Shortcut | English Description |
| --- | --- | --- |
| Always on Top | `Alt+F5` | Toggle always-on-top for the main window. |
| Chinese |  | Switch UI language to Chinese. |
| English |  | Switch UI language to English. |
| Cascade |  | Cascade MDI child windows. |
| Tile Horizontally |  | Tile MDI child windows horizontally. |
| Tile Vertically |  | Tile MDI child windows vertically. |

### 3.10 Help

| Menu | English Description |
| --- | --- |
| About | Show program version and copyright information. |
| Help Contents | Open help dialog with basic debugger usage, script guide, Python/Lua APIs, and plugin APIs. |
| Official Site | Open official site: `http://www.nt5core.com`. |

## 4. Debugging Workflow

### 4.1 Launch a New Process

1. Use `File -> Open` to select an EXE.
2. Use `Debug -> Arguments` first if command-line arguments are needed.
3. Choose `Pause at entry point` or `Run immediately` in Options as needed.
4. After launch, use the CPU window to inspect entry point, registers, stack, and memory.

### 4.2 Command-Line Startup

Z0BPcTools3 can start directly from the command line. Paths containing spaces should be quoted.

| Command | Description |
| --- | --- |
| `Z0BPcTools3.exe -open target.exe arg1 "arg two"` | Open and debug `target.exe`, passing the remaining arguments to the debuggee. |
| `Z0BPcTools3.exe -debug target.exe arg1` | Same as `-open`. |
| `Z0BPcTools3.exe target.exe arg1` | Shorthand form for opening a debug target. |
| `Z0BPcTools3.exe -py script.py arg1 "arg two"` | Run a Python script after the debugger UI and plugins are initialized. |
| `Z0BPcTools3.exe script.py arg1` | Shorthand form for running a Python script. |

`--` may be used before target arguments when you want to visually separate the command from the arguments:

```bat
Z0BPcTools3.exe -open target.exe -- arg1 "arg two"
Z0BPcTools3.exe -py script.py -- arg1 "arg two"
```

When a Python script is launched from the command line, `sys.argv[0]` is the script path and the remaining command-line values are passed as `sys.argv[1:]`.

### 4.3 Attach to Process

1. Use `File -> Attach` to open the process list.
2. Select the target process and confirm.
3. After attaching, you can pause and inspect threads, modules, memory, and CPU state.

### 4.4 Execution Control

| Operation | English Description |
| --- | --- |
| Run | Continue until breakpoint, exception, pause, or process exit. |
| Pause | Interrupt a running debuggee and return control to the debugger. |
| Step Into | Single step and enter calls. |
| Step Over | Single step but skip call internals. |
| Run Until Return | Break when the current function returns. |
| Run to User Code | Skip system code and return to user module code. |
| Restart | Restart the last debug target. |
| Stop | Terminate or close current debug session. |

## 5. Breakpoints

Z0BPcTools3 supports software breakpoints, memory breakpoints, and hardware breakpoints. Breakpoints can be controlled from CPU context menus, memory view, breakpoints window, script APIs, or plugin APIs.

| Type | English Description |
| --- | --- |
| Software Breakpoint | Breaks at target address using software breakpoint mechanisms. |
| Memory Breakpoint | Breaks on memory access or write. |
| Hardware Execute Breakpoint | Uses CPU debug registers to break on execution. |
| Hardware Access Breakpoint | Breaks on access to target address. |
| Hardware Write Breakpoint | Breaks on write to target address. |

Common operations:

| Operation | English Description |
| --- | --- |
| Set Breakpoint | Select an address in CPU or memory view and set breakpoint. |
| Delete Breakpoint | Delete from Breakpoints window or context menu. |
| Delete All Breakpoints | Delete all breakpoints from Breakpoints window, script API, or plugin API. |
| View Breakpoints | Open `View -> Breakpoints`. |
| Condition/Count | Trace conditions and some breakpoint logic can use expressions. |

Command bar breakpoint commands:

| Command | English Description |
| --- | --- |
| `bp <address|symbol|register>` | Set a software breakpoint. Register operands use the current CPU thread context, for example `bp esp`, `bp eax`, `bp rsp`, or `bp r8`. |
| `bpm <address|symbol|register>` | Set a memory access breakpoint. This is kept for compatibility. |
| `mp <address|symbol|register>` | Set a memory access breakpoint. |
| `hp <address|symbol|register>` | Set a hardware execute breakpoint. |
| `bc <address|symbol|register>` | Clear a breakpoint at the address. It tries software, memory-region, then hardware breakpoint removal. |
| `attach <pid>` | Attach to a running process by process ID. |

## 6. CPU, Memory, and Stack Views

### 6.1 CPU Window

The CPU window is the main debugging workspace and usually contains disassembly, registers, data, and stack panes.

Common operations:

| Operation | English Description |
| --- | --- |
| Assemble | Assemble instruction at selected address. |
| Go to/Follow | Go to or follow expression, address, call target, or data reference. |
| Binary Edit | Edit, fill zero, fill NOP, copy, or paste binary data. |
| Copy Text | Copy disassembly or data text. |
| Set Memory Breakpoint | Set access/write memory breakpoint or remove it. |
| Set Hardware Breakpoint | Set execute/access/write hardware breakpoints with length. |
| Display Mode | Switch 8/16/32-byte display and ANSI/Unicode/UTF-8 text display. |
| Step Back Display | Use `-` to move back to the previous instruction display position. |

### 6.2 Memory Window

The Memory window is used to inspect memory regions, follow addresses, search binary data, and set memory breakpoints.

| Shortcut | English Function |
| --- | --- |
| `Enter` | Follow selected address or disassembly position |
| `F2` | Set memory access breakpoint |
| `Ctrl+B` | Binary search |

### 6.3 Stack Window

The Stack window shows the current thread stack and can be used with the CPU window to inspect return addresses, function arguments, and local data.

## 7. Trace Features

Trace features record execution paths, hit addresses, auto-step results, or condition-controlled execution results.

| Feature | English Description |
| --- | --- |
| Auto Step Into | Repeated step into, useful for observing instruction-by-instruction execution. |
| Auto Step Over | Repeated step over, useful for skipping function internals. |
| RUN Trace | Records execution path or instructions during run. |
| HIT Trace | Records hit code locations. |
| Trace Into | One traced step into. |
| Trace Over | One traced step over. |
| Trace Condition | Controls tracing with conditions, counts, or pause-on-command behavior. |

Recommended usage:

1. Locate the code of interest in the CPU window.
2. Use RUN trace when you need to record an execution path.
3. Use HIT trace when you only need to know whether addresses were executed.
4. Use `Ctrl+T` to set condition, count, or pause behavior when trace output is too large.
5. Stop tracing with `Stop RUN Trace` when finished.

## 8. Script System

Z0BPcTools3 currently supports ODbgScript, OllyPython, and OllyLua. The Script menu organizes scripts by script type and filename.

### 8.1 ODbgScript

ODbgScript uses OllyDbg script syntax and is suitable for automating breakpoints, execution, memory operations, assembling, searching, labels, and comments.

Common commands:

| Command | English Description |
| --- | --- |
| `bp addr` | Set software breakpoint. |
| `bphwc addr` | Set hardware execution breakpoint. |
| `bphws addr` | Set hardware write breakpoint. |
| `bpm addr` | Set memory breakpoint. |
| `bphwm addr` | Set hardware memory breakpoint. |
| `bc addr` | Clear breakpoint. |
| `run` | Run or continue. |
| `sti` | Step into. |
| `sto` | Step over. |
| `pause` | Pause. |
| `readstr` | Read string. |
| `writemem` | Write memory. |
| `asm` | Assemble instruction. |
| `exec ... ende` | Execute a multi-line assembly block. |
| `find` | Search in current area. |
| `findmem` | Search memory. |
| `gpa` | Get API address. |
| `lbl` | Set label. |
| `cmt` | Set comment. |
| `eval` | Evaluate expression. |

Full ODbgScript syntax can be found in `odbgscript-master\doc\ODbgScript.txt`.

### 8.2 OllyPython

OllyPython uses an embedded Python 3.x runtime and does not support Python 2.x. The runtime is loaded dynamically from DLLs to avoid increasing the main executable size through static linking.

Recommended directory layout:

```text
plugins\
  python313\
    python313.dll
    python313.zip
    DLLs\
    Lib\
  OllyPython\
    example.py
```

`.py` files are shown as:

```text
Script -> OllyPython -> example -> Run
```

The Python module name is `z0dbg`.

Example:

```python
import z0dbg

print(z0dbg.get_status())
data = z0dbg.read_memory(0x401000, 16)
print(data.hex())
z0dbg.set_breakpoint(0x401000)
z0dbg.step_over()
```

Currently supported `z0dbg` APIs:

| API | English Description |
| --- | --- |
| `read_memory(address, size)` | Read debuggee memory. |
| `write_memory(address, data)` | Write debuggee memory. |
| `get_status()` | Get debugger status. |
| `get_cpu_thread_id()` | Get current CPU thread ID. |
| `set_breakpoint(address)` | Set software breakpoint. |
| `delete_breakpoint(address)` | Delete breakpoint at address. |
| `delete_breakpoints()` | Delete all software breakpoints. |
| `set_memory_breakpoint(address, size, type)` | Set memory breakpoint. |
| `remove_memory_breakpoint(address)` | Remove memory breakpoint. |
| `set_hardware_breakpoint(address, size, type)` | Set hardware breakpoint. |
| `delete_hardware_breakpoint(address)` | Delete hardware breakpoint. |
| `delete_hardware_breakpoint_index(index)` | Delete hardware breakpoint by slot index. |
| `run()` | Run or continue. |
| `go(address)` | Run to address. |
| `suspend()` | Suspend debuggee. |
| `step_into()` | Step into. |
| `step_over()` | Step over. |
| `auto_step_into()` | Auto step into. |
| `auto_step_over()` | Auto step over. |
| `stop_animation()` | Stop auto stepping or animation. |
| `set_temp_breakpoint(address)` | Set temporary breakpoint. |
| `find_name(name)` | Find symbol or name. |
| `insert_name(address, name)` | Insert name. |
| `decode_address(address)` | Decode address into module, symbol, or text. |
| `evaluate(expression)` | Evaluate expression. |
| `disasm(address)` | Disassemble address. |
| `assemble(address, text)` | Assemble instruction text. |
| `patch_assemble(address, text)` | Assemble and patch memory. |
| `find_data(address, data)` | Search binary data. |
| `follow_call(address)` | Follow call target. |
| `get_breakpoint_type(address)` | Get breakpoint type. |
| `get_next_breakpoint(address)` | Find next breakpoint. |
| `redraw_disasm()` | Redraw disassembly. |
| `redraw_registers()` | Redraw registers. |
| `redraw_list()` | Redraw list window. |
| `suspend_all_threads()` | Suspend all threads. |
| `show_memory()` | Show Memory window. |
| `show_breakpoints()` | Show Breakpoints window. |
| `show_threads()` | Show Threads window. |
| `show_trace()` | Show Trace window. |
| `show_windows()` | Show Windows list. |
| `show_patches()` | Show Patches window. |
| `set_trace_condition(expression)` | Set trace condition. |
| `set_trace_count(count)` | Set trace count. |
| `set_trace_pause_on_commands(enable)` | Set pause-on-command behavior for trace. |
| `is_prefix(address)` | Test whether instruction at address is a prefix. |
| `input_text(title, prompt)` | Show input dialog and return text. |
| `show_text(title, text)` | Show text dialog. |
| `API_VERSION` | Python API version constant. |
| `ADDRESS_BITS` | Current address bit width. |
| `ADDRESS_API_BITS` | Address API bit width. |

### 8.3 OllyLua

OllyLua dynamically loads the Lua DLL. The current DLL name is `lua55.dll`. It runs source `.lua` scripts directly and does not require users to precompile bytecode.

Lua DLL search locations:

```text
plugins\lua55.dll
lua\lua55.dll
程序目录\lua55.dll
当前目录\lua55.dll
PATH 中的 lua55.dll
```

Recommended directory layout:

```text
plugins\
  lua55.dll
  OllyLua\
    example.lua
```

`.lua` files are shown as:

```text
Script -> OllyLua -> example -> Run
```

Lua scripts access debugger features through the `z0dbg` table.

Common APIs:

| API | English Description |
| --- | --- |
| `z0dbg.read_memory(address, size)` | Read debuggee memory. |
| `z0dbg.write_memory(address, data)` | Write debuggee memory. |
| `z0dbg.get_status()` | Get debugger status. |
| `z0dbg.get_cpu_thread_id()` | Get current CPU thread ID. |
| `z0dbg.set_breakpoint(address)` | Set software breakpoint. |
| `z0dbg.delete_breakpoint(address)` | Delete breakpoint at address. |
| `z0dbg.delete_breakpoints()` | Delete all software breakpoints. |
| `z0dbg.set_memory_breakpoint(address, size, type)` | Set memory breakpoint. |
| `z0dbg.set_hardware_breakpoint(address, size, type)` | Set hardware breakpoint. |
| `z0dbg.run()` | Run or continue. |
| `z0dbg.go(address)` | Run to address. |
| `z0dbg.suspend()` | Suspend debuggee. |
| `z0dbg.step_into()` | Step into. |
| `z0dbg.step_over()` | Step over. |
| `z0dbg.find_name(name)` | Find name. |
| `z0dbg.insert_name(address, name)` | Insert name. |
| `z0dbg.decode_address(address)` | Decode address. |
| `z0dbg.input_text(title, prompt)` | Show input dialog. |
| `z0dbg.show_text(title, text)` | Show text dialog. |

## 9. Plugin Development

Z0BPcTools3 supports OllyDbg 2.0-style plugin interfaces and provides SDK headers and import libraries for this debugger.

SDK locations:

```text
sdk\include\plugin.h
sdk\lib\x64\Release\Z0BPcTools3.lib
sdk\lib\Win32\Release\Z0BPcTools3.lib
```

Plugin DLLs must export required ODBG2 plugin functions. Common exports:

| Export | English Description |
| --- | --- |
| `ODBG2_Pluginquery` | Query plugin name, version, and compatibility. |
| `ODBG2_Plugininit` | Initialize plugin. |
| `ODBG2_Pluginmenu` | Return plugin menu structure. |
| `ODBG2_Pluginaction` | Handle plugin menu actions. |
| `ODBG2_Pluginmainloop` | Receive debugger main loop events. |
| `ODBG2_Pluginsaveudd` | Save user database data. |
| `ODBG2_Pluginuddrecord` | Load user database records. |
| `ODBG2_Pluginclose` | Debug session close notification. |
| `ODBG2_Plugindestroy` | Plugin unload cleanup. |

Common debugger APIs:

| API | English Description |
| --- | --- |
| `Readmemory` | Read debuggee memory. |
| `Writememory` | Write debuggee memory. |
| `Getstatus` | Get debugger status. |
| `Getcputhreadid` | Get current CPU thread ID. |
| `Setbreakpoint` | Set breakpoint. |
| `Deletebreakpoints` | Delete breakpoints. |
| `Setmembreakpoint` | Set memory breakpoint. |
| `Sethardwarebreakpoint` | Set hardware breakpoint. |
| `Findname` | Find name. |
| `Insertname` | Insert name. |
| `Decodeaddress` | Decode address. |
| `Expression` | Evaluate expression. |
| `Disasm` | Disassemble. |
| `Assemble` | Assemble. |
| `Finddata` | Find binary data. |
| `Followcall` | Follow call. |
| `Isprefix` | Test instruction prefix. |
| `Addtolist` | Add log entry to list. |
| `Redrawdisassembler` | Redraw disassembler. |
| `Createthreadwindow` | Create or open thread window. |
| `Settracecondition` | Set trace condition. |
| `Settracecount` | Set trace count. |
| `Settracepauseoncommands` | Set trace pause-on-command behavior. |
| `Redrawcpudisasm` | Redraw CPU disassembly pane. |
| `Redrawcpureg` | Redraw CPU register pane. |
| `Redrawlist` | Redraw list. |
| `Setcpu` | Set CPU window position. |
| `Setdisasm` | Set disassembly position. |

SDK helper functions:

| API | English Description |
| --- | --- |
| `Z0B_InitSorted` | Initialize sorted table structure. |
| `Z0B_InitTable` | Initialize table structure. |
| `Z0B_InitTableColumn` | Initialize table column. |
| `Z0B_CreateTableWindow` | Create table window. |

Plugin menu display rule:

```text
Plugin -> PluginName -> Plugin-defined menu items
```

Notes:

| Issue | English Description |
| --- | --- |
| Bitness Mismatch | x64 debugger loads only x64 plugins, and Win32 debugger loads only Win32 plugins. |
| Version Check Failed | Plugin must return a compatible ODBG2 version. |
| Missing Exports | Plugin DLL must export required entry points. |
| Duplicate Load | The same path or same plugin name should not be loaded repeatedly. |

### 9.1 MCP Tools Plugin

`MCP Tools` is an ODBG2-style plugin that adds MCP Server configuration entries to the Plugin menu.

Menu location:

```text
插件 -> MCP Tools -> 设置 MCP Server
插件 -> MCP Tools -> 重新读取配置
插件 -> MCP Tools -> 显示配置文件路径
插件 -> MCP Tools -> 发送测试事件
插件 -> MCP Tools -> 关于

Plugin -> MCP Tools -> Configure MCP Server
Plugin -> MCP Tools -> Reload configuration
Plugin -> MCP Tools -> Show configuration file path
Plugin -> MCP Tools -> Send test event
Plugin -> MCP Tools -> About
```

Plugin output locations:

```text
x64\Release\plugins\McpTools.dll
Release\plugins\McpTools.dll
```

Configuration file location:

```text
<debugger directory>\plugins\McpTools.ini
```

Configuration fields:

| Field | English Description |
| --- | --- |
| `enabled` | Whether the MCP Server configuration is enabled. |
| `name` | Server name. |
| `transport` | Transport type: `stdio`, `http`, or `sse`. |
| `url` | Server URL for `http` or `sse` mode. |
| `command` | Command used to start MCP Server in `stdio` mode. |
| `arguments` | Startup arguments for `stdio` mode. |
| `workdir` | Working directory for `stdio` mode. |
| `env` | Environment variables, one `NAME=VALUE` per line. |
| `timeout_ms` | Connection or request timeout in milliseconds. |

The MCP Tools plugin UI follows the current main-menu language selection, "Chinese / English", and does not use a separate language setting.

Event transport:

| Transport | English Description |
| --- | --- |
| `stdio` | The plugin starts the configured MCP Server process and writes one JSON event per line to server stdin. |
| `http` | The plugin sends HTTP POST requests to the configured URL with JSON request bodies. |
| `sse` | Currently sends events as HTTP POST. It can be extended to a real SSE session later. |

Events are sent by a worker thread. Debugger callback threads only enqueue events. The queue limit is 512 items; when full, the oldest item is dropped to avoid blocking the debugger.

Basic event JSON format:

```json
{
  "jsonrpc": "2.0",
  "method": "z0dbg/event",
  "params": {
    "source": "Z0BPcTools3",
    "plugin": "MCP Tools",
    "event": "debug_event",
    "tick": 12345678
  }
}
```

Supported events:

| Event | English Description |
| --- | --- |
| `plugin_init` | Plugin initialized. |
| `plugin_destroy` | Plugin destroyed. |
| `config_reloaded` | Configuration reloaded. |
| `test` | Test event triggered from menu. |
| `debug_event` | Windows debug event from `ODBG2_Pluginmainloop(DEBUG_EVENT*)`. |
| `notify` | Debugger notification event from `ODBG2_Pluginnotify()`. |

`debug_event` includes:

| Field | English Description |
| --- | --- |
| `debugEventCode` | Windows debug event code. |
| `debugEventName` | Event name such as `exception`, `create_process`, or `load_dll`. |
| `processId` | Process ID. |
| `threadId` | Thread ID. |
| `exceptionCode` | Exception code, only for exception events. |
| `exceptionAddress` | Exception address, only for exception events. |
| `firstChance` | Whether this is a first-chance exception. |
| `imageBase`、`dllBase` | Process image base or DLL base. |
| `startAddress` | New process or thread start address. |
| `exitCode` | Process or thread exit code. |

`notify` includes:

| Field | English Description |
| --- | --- |
| `notifyCode` | Notification code. |
| `notifyName` | Notification name such as `new_process`, `new_module`, or `end_process`. |
| `dataPointer` | Raw data pointer address for advanced server-side handling. |
| `parm1`、`parm2` | Notification parameters, usually address or range values. |

Current MCP control tools:

| Category | Tools |
| --- | --- |
| Status | `get_status`, `get_cpu_thread_id` |
| Execution control | `run`, `go`, `pause`, `step_into`, `step_over`, `trace_into`, `trace_over`, `auto_step_into`, `auto_step_over` |
| Memory | `read_memory`, `write_memory`, `list_memory`, `find_memory`, `find_data_ptr` |
| Software breakpoints | `set_software_breakpoint`, `set_software_breakpoint_ext`, `delete_software_breakpoint`, `delete_breakpoint_range`, `delete_all_breakpoints` |
| Memory breakpoints | `set_memory_breakpoint`, `delete_memory_breakpoint` |
| Hardware breakpoints | `set_hardware_breakpoint`, `delete_hardware_breakpoint`, `get_breakpoint_type`, `get_breakpoint_type_count`, `get_next_breakpoint`, `set_temp_breakpoint`, `plugin_temp_breakpoint` |
| Disassembly and assembly | `disassemble`, `assemble` |
| CPU window | `set_cpu`, `set_disasm` |
| Expressions, symbols, modules, and threads | `evaluate`, `find_name`, `insert_name`, `decode_address`, `decode_name`, `comment_address`, `simple_address`, `find_label`, `find_module`, `find_thread`, `find_data`, `find_decode`, `find_strings`, `find_references`, `find_import_by_name`, `find_file_offset`, `follow_call`, `walk_reference`, `walk_reference_ex`, `is_prefix` |
| CPU context | `get_last_error`, `get_cpu_disasm_dump`, `get_cpu_disasm_table` |
| Plugin INI | `plugin_read_ini_int`, `plugin_write_ini_int`, `plugin_read_ini_string`, `plugin_write_ini_string` |
| Refresh and thread control | `redraw_disasm`, `redraw_registers`, `redraw_list`, `redraw_all`, `suspend_all_threads`, `resume_all_threads` |
| Windows | `show_memory`, `show_breakpoints`, `show_hardware_breakpoints`, `show_threads`, `show_trace`, `show_windows`, `show_patches`, `show_watch` |
| Trace settings | `set_trace_condition`, `set_trace_count`, `set_trace_pause_on_commands` |
| Dump and plugin notification helpers | `set_dump_type`, `dump_backup`, `plugin_module_changed` |

Total: 81 control tools. Address parameters support 64-bit addresses; `"0x..."` JSON strings are recommended. In x64 builds, disassembly and assembly use the debugger's x64 instruction decoding/assembling path. In x64 mode, host APIs returning pointers through `int` are not exposed as control tools to avoid truncating 64-bit values.

Register write, thread enumeration/per-thread suspend/resume, module enumeration, detailed patch management, and more APIs can be added later to approach xdbg64 MCP's 79-tool scale.

When using `stdio`, the MCP Server sends one JSON-RPC request per line to stdout, and the plugin writes one JSON-RPC response per line back to server stdin.

Tool list request:

```json
{"jsonrpc":"2.0","id":1,"method":"z0dbg.tools"}
```

Tool call request:

```json
{"jsonrpc":"2.0","id":2,"method":"z0dbg.call","params":{"tool":"read_memory","address":"0x401000","size":16}}
```

The tool name can also be placed directly after `method`:

```json
{"jsonrpc":"2.0","id":3,"method":"z0dbg.step_over"}
```

The current version supports MCP Server configuration, test events, structured debug event forwarding, notification forwarding, and the first 81 debugger control tools.

## 10. Common Tasks

### 10.1 Read Memory at an Address

1. Open CPU or Memory window.
2. Use Go to or Follow to locate the address.
3. Inspect bytes, strings, or data in Memory window.
4. For automation, use Python `z0dbg.read_memory(address, size)` or Lua `z0dbg.read_memory(address, size)`.

### 10.2 Patch Instruction

1. Select an address in CPU disassembly pane.
2. Use Assemble from the context menu.
3. Enter the new instruction and confirm.
4. Check changes in the Patches window.

### 10.3 Set Hardware Breakpoint

1. Select the target address in CPU or Memory view.
2. Choose hardware breakpoint type: execute, access, or write.
3. Select breakpoint length according to data size.
4. Run the program. The debugger breaks when the breakpoint is hit.

### 10.4 Automate with Scripts

1. Place Python scripts in `plugins\OllyPython`.
2. Place Lua scripts in `plugins\OllyLua`.
3. Select the script name from the Script menu and click Run.
4. ODbgScript scripts run through the ODbgScript plugin window and configured script directory.

## 11. Troubleshooting

| Symptom | English Fix |
| --- | --- |
| Plugin menu not shown | Check DLL location, bitness, and required ODBG2 exports. |
| Version check failed prompt | Rebuild plugin and ensure `ODBG2_Pluginquery` returns a compatible version. |
| Python script cannot run | Check `python313.dll`, stdlib zip, or Lib/DLLs under `plugins\python313`. |
| z0dbg module install failed | Check Python initialization, plugin directory completeness, and runtime bitness. |
| Lua DLL not found | Put `lua55.dll` in `plugins\lua55.dll` or another search path. |
| Lua stdlib is nil | Ensure standard libraries are opened and the correct DLL is loaded. |
| Invalid address read | Ensure the address belongs to the debuggee and the memory page is readable. |
| Wrong close behavior | Check Terminate or Detach options on close. |

## 12. Official Site

Official site:

```text
http://www.nt5core.com
```

## 13. Notes

This document is based on the current project menus, shortcuts, script help, and SDK APIs. When new menus, shortcuts, script APIs, or plugin APIs are added, update this document and the built-in `Help -> Help Contents` dialog together.


---

# Z0BPcTools3 调试器使用说明

本文档说明 Z0BPcTools3 调试器的主要界面、快捷键、调试功能、跟踪功能、脚本系统和插件开发接口。

## 1. 基本概念

Z0BPcTools3 是一个 Windows 用户态调试器，界面采用多文档窗口结构。调试会话打开后，可以通过菜单或快捷键打开 CPU、内存、堆栈、模块、线程、断点、补丁、调用栈、句柄、窗口、SEH 链、引用、源代码等窗口。

常用窗口：

| 中文 | 说明 |
| --- | --- |
| CPU 窗口 | 显示反汇编、寄存器、数据窗口和堆栈，是主要调试视图。 |
| 记录窗口 | 显示调试器日志、插件输出和脚本输出。 |
| 模块窗口 | 查看当前进程加载的 EXE/DLL 模块。 |
| 内存窗口 | 查看内存区段，支持跳转、搜索和内存断点。 |
| 堆栈窗口 | 查看当前线程堆栈。 |
| 线程窗口 | 查看和切换线程。 |
| 断点窗口 | 查看、删除、管理断点。 |
| 补丁窗口 | 查看和管理已修改的代码或数据。 |
| 调用栈窗口 | 查看当前线程调用栈。 |
| 跟踪窗口 | 查看 RUN trace、HIT trace 等跟踪结果。 |

## 2. 快捷键

| 快捷键 | 中文功能 |
| --- | --- |
| `Alt+L` | 打开记录窗口 |
| `Alt+E` | 打开模块窗口 |
| `Alt+C` | 打开 CPU 窗口 |
| `F9` | 运行或继续执行 |
| `F12` | 暂停当前调试进程 |
| `Ctrl+F2` | 重新开始上一次调试命令 |
| `Alt+F2` | 停止当前调试会话 |
| `F7` | 单步步入 |
| `F8` | 单步步过 |
| `Ctrl+F7` | 自动步入 |
| `Ctrl+F8` | 自动步过 |
| `Ctrl+F9` | 执行到返回 |
| `Alt+F9` | 执行到用户代码 |
| `Ctrl+F11` | 跟踪步入 |
| `Ctrl+F12` | 跟踪步过 |
| `Ctrl+T` | 设置 RUN 跟踪条件 |
| `Alt+F5` | 切换总在最前 |
| `-` 或小键盘 `-` | CPU 视图中回退到上一条指令显示位置 |
| `Alt+G` | CPU 视图中跳转或跟随表达式 |
| `Enter` | 内存视图中跟随选中地址或反汇编位置 |
| `F2` | 内存视图中设置内存访问断点 |
| `Ctrl+B` | 内存视图中执行二进制搜索 |

说明：部分快捷键只有在对应窗口处于活动状态时才生效。

## 3. 菜单功能

### 3.1 文件

| 菜单 | 中文说明 |
| --- | --- |
| 打开 | 选择并启动一个可执行文件进行调试。 |
| 附加 | 附加到已经运行的进程。 |
| 退出 | 退出调试器。 |

### 3.2 查看

查看菜单用于打开各类调试窗口。

| 菜单 | 中文说明 |
| --- | --- |
| 记录 | 打开日志窗口。 |
| 模块 | 打开模块窗口。 |
| 内存 | 打开内存窗口。 |
| 堆栈 | 打开堆栈窗口。 |
| 线程 | 打开线程窗口。 |
| 窗口 | 打开被调试进程窗口列表。 |
| 句柄 | 打开进程句柄列表。 |
| CPU | 打开 CPU 主窗口。 |
| SEH 链 | 打开结构化异常处理链窗口。 |
| 补丁 | 打开补丁窗口。 |
| 调用栈 | 打开调用栈窗口。 |
| 断点 | 打开断点窗口。 |
| 监视 | 打开监视窗口。 |
| 引用 | 打开引用窗口。 |
| 源代码 | 打开源代码窗口。 |
| 源文件 | 打开源文件窗口。 |

### 3.3 调试

| 菜单 | 快捷键 | 中文说明 |
| --- | --- | --- |
| 运行 | `F9` | 运行或继续执行被调试程序。 |
| 暂停 | `F12` | 暂停当前调试进程。 |
| 重新开始 | `Ctrl+F2` | 重新开始上一次调试命令。 |
| 关闭 | `Alt+F2` | 停止当前调试会话。 |
| 步入 | `F7` | 执行一条指令，遇到调用会进入目标函数。 |
| 步过 | `F8` | 执行一条指令，遇到调用会直接执行完调用。 |
| 执行到返回 | `Ctrl+F9` | 运行到当前函数返回位置。 |
| 执行到用户代码 | `Alt+F9` | 从系统代码运行到用户代码。 |
| 硬件断点 |  | 设置或管理硬件断点。 |
| 检查 |  | 打开寄存器或运行状态检查相关对话框。 |
| 调用 DLL 导出函数 |  | 调用目标 DLL 的导出函数。 |
| 参数 |  | 设置程序启动参数。 |
| 选择导入库目录 |  | 设置导入库目录。 |
| 选择符号路径 |  | 设置符号文件搜索路径。 |

### 3.4 跟踪

跟踪菜单把自动执行、RUN trace、HIT trace 和条件跟踪功能集中在一起。

| 菜单 | 快捷键 | 中文说明 |
| --- | --- | --- |
| 自动步入 | `Ctrl+F7` | 连续执行步入操作。 |
| 自动步过 | `Ctrl+F8` | 连续执行步过操作。 |
| RUN 跟踪 |  | 记录运行路径或运行过程中的指令信息。 |
| HIT 跟踪 |  | 记录命中的代码位置，用于覆盖率或路径观察。 |
| 打开或清除 RUN 跟踪 |  | 打开 RUN 跟踪窗口或清除已有跟踪结果。 |
| 跟踪步入 | `Ctrl+F11` | 执行一次带记录的步入。 |
| 跟踪步过 | `Ctrl+F12` | 执行一次带记录的步过。 |
| 设置条件 | `Ctrl+T` | 设置 RUN 跟踪条件、计数或暂停行为。 |
| 关闭 RUN 跟踪 |  | 停止当前 RUN 跟踪。 |

### 3.5 脚本

脚本菜单用于 ODbgScript、OllyPython、OllyLua 脚本。脚本文件会按目录自动生成菜单。

| 脚本系统 | 目录 | 说明 |
| --- | --- | --- |
| ODbgScript | 由 ODbgScript 配置项决定，通常通过脚本插件管理 | OllyDbg/ODbgScript 风格脚本。 |
| OllyPython | `plugins\OllyPython\*.py` | 每个 `.py` 文件显示为 `脚本 -> OllyPython -> 文件名 -> 运行`。 |
| OllyLua | `plugins\OllyLua\*.lua` | 每个 `.lua` 文件显示为 `脚本 -> OllyLua -> 文件名 -> 运行`。 |

### 3.6 插件

| 菜单 | 中文说明 |
| --- | --- |
| 查找/添加插件 | 从文件中选择并加载插件 DLL。 |
| 插件名 -> 插件菜单项 | 每个插件按插件名分组显示自己的菜单。 |

插件应放在 `plugins` 目录或通过“查找/添加插件”加载。插件位数必须和当前调试器位数一致，例如 x64 调试器需要 x64 插件 DLL。

### 3.7 工具

| 菜单 | 中文说明 |
| --- | --- |
| IDA 静态反汇编 -> 内存模式 | 以 IDA 风格查看静态反汇编，偏向内存读取模式，建议小于 50M 的目标使用。 |
| IDA 静态反汇编 -> 缓存模式 | 以 IDA 风格查看静态反汇编，使用缓存模式。 |

### 3.8 选项

| 菜单 | 中文说明 |
| --- | --- |
| 属性设置 | 打开统一设置对话框。左侧是全部展开的树结构，右侧显示当前设置面板。 |
| JIT 调试选项 | 配置即时调试相关选项。 |
| 暂停在程序入口点 | 启动调试后在入口点暂停。 |
| 立即运行 | 启动调试后立即运行。 |
| 关闭窗口时终止进程 | 关闭调试窗口时终止被调试进程。 |
| 关闭窗口时脱离进程 | 关闭调试窗口时从被调试进程脱离。 |
| 函数签名识别 | 启用或关闭函数签名识别。 |
| 添加到资源管理器右键菜单 | 将调试入口添加到 Windows Explorer 右键菜单。 |

### 3.9 窗口

| 菜单 | 快捷键 | 中文说明 |
| --- | --- | --- |
| 总在最前 | `Alt+F5` | 切换主窗口总在最前。 |
| 中文 |  | 切换到中文界面。 |
| English |  | 切换到英文界面。 |
| 层叠 |  | 层叠排列 MDI 子窗口。 |
| 水平平铺 |  | 水平平铺 MDI 子窗口。 |
| 垂直平铺 |  | 垂直平铺 MDI 子窗口。 |

### 3.10 帮助

| 菜单 | 中文说明 |
| --- | --- |
| 关于 | 显示程序版本和版权信息。 |
| 帮助内容 | 打开帮助对话框，包含调试器基本用法、脚本说明、Python/Lua API 和插件 API。 |
| 官方主页 | 打开官方主页：`http://www.nt5core.com`。 |

## 4. 调试流程

### 4.1 启动新进程

1. 使用“文件 -> 打开”选择 EXE。
2. 如需参数，先使用“调试 -> 参数”设置命令行参数。
3. 根据需要在“选项”中选择“暂停在程序入口点”或“立即运行”。
4. 程序启动后，使用 CPU 窗口查看入口点、寄存器、堆栈和内存。

### 4.2 命令行启动

Z0BPcTools3 支持从命令行直接启动。路径包含空格时需要加引号。

| 命令 | 说明 |
| --- | --- |
| `Z0BPcTools3.exe -open target.exe arg1 "arg two"` | 打开并调试 `target.exe`，后续参数会传给被调试进程。 |
| `Z0BPcTools3.exe -debug target.exe arg1` | 等同于 `-open`。 |
| `Z0BPcTools3.exe target.exe arg1` | 打开调试目标的简写形式。 |
| `Z0BPcTools3.exe -py script.py arg1 "arg two"` | 在调试器界面和插件初始化完成后执行 Python 脚本。 |
| `Z0BPcTools3.exe script.py arg1` | 执行 Python 脚本的简写形式。 |

可以在目标参数前使用 `--`，用于区分调试器命令和传递给目标的参数：

```bat
Z0BPcTools3.exe -open target.exe -- arg1 "arg two"
Z0BPcTools3.exe -py script.py -- arg1 "arg two"
```

从命令行启动 Python 脚本时，`sys.argv[0]` 为脚本路径，后续命令行值会作为 `sys.argv[1:]` 传入脚本。

### 4.3 附加到进程

1. 使用“文件 -> 附加”打开进程列表。
2. 选择目标进程并确认。
3. 附加后可以暂停、查看线程、模块、内存和 CPU 状态。

### 4.4 基本执行控制

| 操作 | 中文说明 |
| --- | --- |
| 运行 | 继续执行直到断点、异常、暂停或进程退出。 |
| 暂停 | 中断正在运行的进程，返回调试器控制。 |
| 步入 | 单步执行并进入调用。 |
| 步过 | 单步执行但跳过调用内部。 |
| 执行到返回 | 当前函数返回时中断。 |
| 执行到用户代码 | 跳过系统代码，回到用户模块代码。 |
| 重新开始 | 重新启动上一次调试目标。 |
| 关闭 | 终止或关闭当前调试会话。 |

## 5. 断点

Z0BPcTools3 支持软件断点、内存断点和硬件断点。断点可以通过 CPU 窗口右键菜单、内存窗口、断点窗口、脚本 API 或插件 API 操作。

| 类型 | 中文说明 |
| --- | --- |
| 软件断点 | 使用断点指令或调试器机制在目标地址中断。 |
| 内存断点 | 对内存访问、写入等行为设置断点。 |
| 硬件执行断点 | 使用 CPU 调试寄存器在执行目标地址时中断。 |
| 硬件访问断点 | 在访问目标地址时中断。 |
| 硬件写入断点 | 在写入目标地址时中断。 |

常用操作：

| 操作 | 中文说明 |
| --- | --- |
| 设置断点 | 在 CPU 或内存窗口选择地址后设置。 |
| 删除断点 | 在断点窗口或右键菜单删除。 |
| 删除全部断点 | 通过断点窗口、脚本 API 或插件 API 清空。 |
| 查看断点 | 打开“查看 -> 断点”。 |
| 条件/计数 | 跟踪条件和部分断点逻辑可配合条件表达式使用。 |

## 6. CPU、内存、堆栈窗口

### 6.1 CPU 窗口

CPU 窗口是主要调试工作区，通常包括反汇编、寄存器、数据和堆栈区域。

支持的常见操作：

| 操作 | 中文说明 |
| --- | --- |
| 汇编 | 修改选中地址处的指令。 |
| 跳转/跟随 | 跳转到表达式、地址、调用目标或数据引用。 |
| 二进制编辑 | 编辑、填零、填 NOP、复制或粘贴二进制数据。 |
| 复制文本 | 复制反汇编或数据文本。 |
| 设置内存断点 | 设置访问、写入或删除内存断点。 |
| 设置硬件断点 | 设置执行、访问、写入硬件断点，并选择长度。 |
| 显示模式 | 切换 8/16/32 字节显示，ANSI、Unicode、UTF-8 字符显示。 |
| 回退显示 | 使用 `-` 回退到上一条指令显示位置。 |

### 6.2 内存窗口

内存窗口用于查看进程内存区域、跟随地址、搜索二进制内容和设置内存断点。

| 快捷键 | 中文功能 |
| --- | --- |
| `Enter` | 跟随选中地址或反汇编位置 |
| `F2` | 设置内存访问断点 |
| `Ctrl+B` | 二进制搜索 |

### 6.3 堆栈窗口

堆栈窗口显示当前线程栈内容，可配合 CPU 窗口查看返回地址、函数参数和局部数据。

## 7. 跟踪功能

跟踪功能用于记录程序执行路径、命中地址、自动步进结果或受条件控制的运行结果。

| 功能 | 中文说明 |
| --- | --- |
| 自动步入 | 连续执行步入，适合观察每条指令执行。 |
| 自动步过 | 连续执行步过，适合跳过函数内部细节。 |
| RUN 跟踪 | 记录运行期间的路径或指令。 |
| HIT 跟踪 | 记录命中的代码位置。 |
| 跟踪步入 | 单次带记录的步入。 |
| 跟踪步过 | 单次带记录的步过。 |
| 跟踪条件 | 使用条件表达式、计数或暂停命令控制跟踪。 |

建议用法：

1. 先在 CPU 窗口定位到关注代码。
2. 如果只想记录一段运行路径，启用 RUN 跟踪。
3. 如果只关心某些地址是否执行，使用 HIT 跟踪。
4. 如果跟踪太多，使用 `Ctrl+T` 设置条件、次数或暂停行为。
5. 完成后使用“关闭 RUN 跟踪”停止记录。

## 8. 脚本系统

Z0BPcTools3 当前支持 ODbgScript、OllyPython 和 OllyLua。脚本菜单会按脚本类型和文件名自动组织。

### 8.1 ODbgScript

ODbgScript 使用 OllyDbg 脚本语法，适合自动化断点、运行、内存读写、汇编、搜索、标签和注释等操作。

常用命令：

| 命令 | 中文说明 |
| --- | --- |
| `bp addr` | 设置软件断点。 |
| `bphwc addr` | 设置硬件执行断点。 |
| `bphws addr` | 设置硬件写入断点。 |
| `bpm addr` | 设置内存断点。 |
| `bphwm addr` | 设置硬件内存断点。 |
| `bc addr` | 删除断点。 |
| `run` | 运行或继续。 |
| `sti` | 步入。 |
| `sto` | 步过。 |
| `pause` | 暂停。 |
| `readstr` | 读取字符串。 |
| `writemem` | 写内存。 |
| `asm` | 汇编指令。 |
| `exec ... ende` | 执行多行汇编块。 |
| `find` | 在当前区域搜索。 |
| `findmem` | 在内存中搜索。 |
| `gpa` | 获取 API 地址。 |
| `lbl` | 设置标签。 |
| `cmt` | 设置注释。 |
| `eval` | 计算表达式。 |

完整 ODbgScript 语法可以参考 `odbgscript-master\doc\ODbgScript.txt`。

### 8.2 OllyPython

OllyPython 使用内置 Python 3.x 运行时，不支持 Python 2.x。Python 运行时按动态 DLL 方式加载，避免静态链接导致主程序变大。

推荐目录结构：

```text
plugins\
  python313\
    python313.dll
    python313.zip
    DLLs\
    Lib\
  OllyPython\
    example.py
```

`.py` 文件会显示为：

```text
脚本 -> OllyPython -> example -> 运行
```

Python 模块名为 `z0dbg`。

示例：

```python
import z0dbg

print(z0dbg.get_status())
data = z0dbg.read_memory(0x401000, 16)
print(data.hex())
z0dbg.set_breakpoint(0x401000)
z0dbg.step_over()
```

当前支持的 `z0dbg` 接口：

| 中文说明 |
| --- |
| 读取被调试进程内存。 |
| 写入被调试进程内存。 |
| 获取调试器运行状态。 |
| 获取当前 CPU 线程 ID。 |
| 设置软件断点。 |
| 删除指定断点。 |
| 删除全部软件断点。 |
| 设置内存断点。 |
| 删除内存断点。 |
| 设置硬件断点。 |
| 删除硬件断点。 |
| 按硬件断点槽位删除断点。 |
| 运行或继续。 |
| 运行到指定地址。 |
| 暂停调试进程。 |
| 单步步入。 |
| 单步步过。 |
| 自动步入。 |
| 自动步过。 |
| 停止自动步进或动画执行。 |
| 设置临时断点。 |
| 查找符号或名称。 |
| 插入名称。 |
| 解码地址为模块、符号或文本形式。 |
| 计算表达式。 |
| 反汇编指定地址。 |
| 汇编指令文本。 |
| 汇编并写入补丁。 |
| 搜索二进制数据。 |
| 跟随调用目标。 |
| 获取断点类型。 |
| 查找下一个断点。 |
| 刷新反汇编窗口。 |
| 刷新寄存器窗口。 |
| 刷新列表窗口。 |
| 暂停全部线程。 |
| 打开内存窗口。 |
| 打开断点窗口。 |
| 打开线程窗口。 |
| 打开跟踪窗口。 |
| 打开窗口列表。 |
| 打开补丁窗口。 |
| 设置跟踪条件。 |
| 设置跟踪计数。 |
| 设置跟踪命令暂停行为。 |
| 判断地址处是否为前缀指令。 |
| 显示输入框并返回文本。 |
| 显示文本对话框。 |
| Python API 版本常量。 |
| 当前地址位数。 |
| 地址 API 位数。 |

### 8.3 OllyLua

OllyLua 使用动态加载的 Lua DLL。当前加载名为 `lua55.dll`，运行的是原始 `.lua` 脚本文件，不要求用户先编译为字节码。

Lua DLL 搜索位置：

```text
plugins\lua55.dll
lua\lua55.dll
程序目录\lua55.dll
当前目录\lua55.dll
PATH 中的 lua55.dll
```

推荐目录结构：

```text
plugins\
  lua55.dll
  OllyLua\
    example.lua
```

`.lua` 文件会显示为：

```text
脚本 -> OllyLua -> example -> 运行
```

Lua 中也通过 `z0dbg` 表访问调试器功能。

常用接口：

| 中文说明 |
| --- |
| 读取被调试进程内存。 |
| 写入被调试进程内存。 |
| 获取调试器状态。 |
| 获取当前 CPU 线程 ID。 |
| 设置软件断点。 |
| 删除指定断点。 |
| 删除全部软件断点。 |
| 设置内存断点。 |
| 设置硬件断点。 |
| 运行或继续。 |
| 运行到指定地址。 |
| 暂停调试进程。 |
| 单步步入。 |
| 单步步过。 |
| 查找名称。 |
| 插入名称。 |
| 解码地址。 |
| 显示输入框。 |
| 显示文本。 |

## 9. 插件开发

Z0BPcTools3 支持 OllyDbg 2.0 风格插件接口，并提供当前调试器 SDK 头文件和导入库。

SDK 位置：

```text
sdk\include\plugin.h
sdk\lib\x64\Release\Z0BPcTools3.lib
sdk\lib\Win32\Release\Z0BPcTools3.lib
```

插件 DLL 必须导出必要的 ODBG2 插件函数。常见导出函数：

| 导出函数 | 中文说明 |
| --- | --- |
| `ODBG2_Pluginquery` | 查询插件名称、版本和兼容性。 |
| `ODBG2_Plugininit` | 插件初始化。 |
| `ODBG2_Pluginmenu` | 返回插件菜单结构。 |
| `ODBG2_Pluginaction` | 处理插件菜单命令。 |
| `ODBG2_Pluginmainloop` | 接收调试器主循环事件。 |
| `ODBG2_Pluginsaveudd` | 保存用户数据库数据。 |
| `ODBG2_Pluginuddrecord` | 读取用户数据库记录。 |
| `ODBG2_Pluginclose` | 调试会话关闭通知。 |
| `ODBG2_Plugindestroy` | 插件卸载清理。 |

常用调试器 API：

| 中文说明 |
| --- |
| 读取被调试进程内存。 |
| 写入被调试进程内存。 |
| 获取调试器状态。 |
| 获取 CPU 当前线程 ID。 |
| 设置断点。 |
| 删除断点。 |
| 设置内存断点。 |
| 设置硬件断点。 |
| 查找名称。 |
| 插入名称。 |
| 解码地址。 |
| 计算表达式。 |
| 反汇编。 |
| 汇编。 |
| 搜索二进制数据。 |
| 跟随调用。 |
| 判断指令前缀。 |
| 输出日志到列表。 |
| 刷新反汇编窗口。 |
| 创建或打开线程窗口。 |
| 设置跟踪条件。 |
| 设置跟踪计数。 |
| 设置跟踪暂停行为。 |
| 刷新 CPU 反汇编区域。 |
| 刷新 CPU 寄存器区域。 |
| 刷新列表。 |
| 设置 CPU 窗口定位。 |
| 设置反汇编窗口定位。 |

SDK 辅助函数：

| 中文说明 |
| --- |
| 初始化排序表结构。 |
| 初始化表格结构。 |
| 初始化表格列。 |
| 创建表格窗口。 |

插件菜单显示规则：

```text
插件 -> 插件名 -> 插件自己的菜单项
```

注意事项：

| 问题 | 中文说明 |
| --- | --- |
| 位数不匹配 | x64 调试器只能加载 x64 插件，Win32 调试器只能加载 Win32 插件。 |
| 版本检查失败 | 插件需要返回兼容的 ODBG2 版本。 |
| 缺少导出函数 | 插件 DLL 必须导出必要入口。 |
| 重复加载 | 同一路径或同名插件不应重复加载。 |

### 9.1 MCP Tools 插件

`MCP Tools` 是一个 ODBG2 风格插件，用于在插件菜单中提供 MCP Server 配置入口。

菜单位置：

```text
插件 -> MCP Tools -> 设置 MCP Server
插件 -> MCP Tools -> 重新读取配置
插件 -> MCP Tools -> 显示配置文件路径
插件 -> MCP Tools -> 发送测试事件
插件 -> MCP Tools -> 关于

Plugin -> MCP Tools -> Configure MCP Server
Plugin -> MCP Tools -> Reload configuration
Plugin -> MCP Tools -> Show configuration file path
Plugin -> MCP Tools -> Send test event
Plugin -> MCP Tools -> About
```

插件输出位置：

```text
x64\Release\plugins\McpTools.dll
Release\plugins\McpTools.dll
```

配置文件位置：

```text
<调试器目录>\plugins\McpTools.ini
```

配置项：

| 配置 | 中文说明 |
| --- | --- |
| `enabled` | 是否启用 MCP Server 配置。 |
| `name` | Server 名称。 |
| `transport` | 传输类型，支持 `stdio`、`http`、`sse`。 |
| `url` | `http` 或 `sse` 模式使用的 Server URL。 |
| `command` | `stdio` 模式启动 MCP Server 的命令。 |
| `arguments` | `stdio` 模式启动参数。 |
| `workdir` | `stdio` 模式工作目录。 |
| `env` | 环境变量，每行一个 `NAME=VALUE`。 |
| `timeout_ms` | 连接或请求超时时间，单位毫秒。 |

当前版本负责保存和管理 MCP Server 配置，后续可在此基础上增加 MCP 协议连接、工具枚举和调用功能。

MCP Tools 插件界面语言跟随主菜单“中文 / English”的当前选择，不使用独立语言配置。

事件传输：

| 传输 | 中文说明 |
| --- | --- |
| `stdio` | 插件按配置启动 MCP Server 进程，每个事件作为一行 JSON 写入 server stdin。 |
| `http` | 插件向配置的 URL 发送 HTTP POST，请求体为 JSON。 |
| `sse` | 当前按 HTTP POST 发送事件，后续可扩展为真正 SSE 会话。 |

事件由后台线程发送，调试器回调线程只负责入队，队列上限为 512 条，满队列时丢弃最旧事件，避免调试器卡住。

事件 JSON 基本格式：

```json
{
  "jsonrpc": "2.0",
  "method": "z0dbg/event",
  "params": {
    "source": "Z0BPcTools3",
    "plugin": "MCP Tools",
    "event": "debug_event",
    "tick": 12345678
  }
}
```

支持的事件：

| 事件 | 中文说明 |
| --- | --- |
| `plugin_init` | 插件初始化完成。 |
| `plugin_destroy` | 插件卸载。 |
| `config_reloaded` | 重新读取配置。 |
| `test` | 菜单触发的测试事件。 |
| `debug_event` | Windows 调试事件，来自 `ODBG2_Pluginmainloop(DEBUG_EVENT*)`。 |
| `notify` | 调试器通知事件，来自 `ODBG2_Pluginnotify()`。 |

`debug_event` 会附加字段：

| 字段 | 中文说明 |
| --- | --- |
| `debugEventCode` | Windows 调试事件代码。 |
| `debugEventName` | 事件名称，例如 `exception`、`create_process`、`load_dll`。 |
| `processId` | 进程 ID。 |
| `threadId` | 线程 ID。 |
| `exceptionCode` | 异常码，仅异常事件包含。 |
| `exceptionAddress` | 异常地址，仅异常事件包含。 |
| `firstChance` | 是否 first chance 异常。 |
| `imageBase`、`dllBase` | 进程映像或 DLL 基址。 |
| `startAddress` | 新进程或线程入口地址。 |
| `exitCode` | 进程或线程退出码。 |

`notify` 会附加字段：

| 字段 | 中文说明 |
| --- | --- |
| `notifyCode` | 通知代码。 |
| `notifyName` | 通知名称，例如 `new_process`、`new_module`、`end_process`。 |
| `dataPointer` | 原始 data 指针地址，供高级 server 侧解析。 |
| `parm1`、`parm2` | 通知参数，通常是地址或范围值。 |

当前版本已完成 MCP Server 配置、测试事件、调试事件和通知事件的结构化转发。后续可继续增加 MCP 标准工具枚举、工具调用和调试器 API 反向控制。

当前 MCP 控制工具：

| 分类 | 工具 |
| --- | --- |
| 状态 | `get_status`, `get_cpu_thread_id` |
| 执行控制 | `run`, `go`, `pause`, `step_into`, `step_over`, `trace_into`, `trace_over`, `auto_step_into`, `auto_step_over` |
| 内存 | `read_memory`, `write_memory`, `list_memory`, `find_memory`, `find_data_ptr` |
| 软件断点 | `set_software_breakpoint`, `set_software_breakpoint_ext`, `delete_software_breakpoint`, `delete_breakpoint_range`, `delete_all_breakpoints` |
| 内存断点 | `set_memory_breakpoint`, `delete_memory_breakpoint` |
| 硬件断点 | `set_hardware_breakpoint`, `delete_hardware_breakpoint`, `get_breakpoint_type`, `get_breakpoint_type_count`, `get_next_breakpoint`, `set_temp_breakpoint`, `plugin_temp_breakpoint` |
| 反汇编与汇编 | `disassemble`, `assemble` |
| CPU 窗口 | `set_cpu`, `set_disasm` |
| 表达式、符号、模块与线程 | `evaluate`, `find_name`, `insert_name`, `decode_address`, `decode_name`, `comment_address`, `simple_address`, `find_label`, `find_module`, `find_thread`, `find_data`, `find_decode`, `find_strings`, `find_references`, `find_import_by_name`, `find_file_offset`, `follow_call`, `walk_reference`, `walk_reference_ex`, `is_prefix` |
| CPU 上下文 | `get_last_error`, `get_cpu_disasm_dump`, `get_cpu_disasm_table` |
| 插件 INI | `plugin_read_ini_int`, `plugin_write_ini_int`, `plugin_read_ini_string`, `plugin_write_ini_string` |
| 刷新与线程控制 | `redraw_disasm`, `redraw_registers`, `redraw_list`, `redraw_all`, `suspend_all_threads`, `resume_all_threads` |
| 窗口 | `show_memory`, `show_breakpoints`, `show_hardware_breakpoints`, `show_threads`, `show_trace`, `show_windows`, `show_patches`, `show_watch` |
| 跟踪设置 | `set_trace_condition`, `set_trace_count`, `set_trace_pause_on_commands` |
| Dump 与插件通知辅助 | `set_dump_type`, `dump_backup`, `plugin_module_changed` |

合计：81 个控制工具。地址参数统一支持 64 位地址，JSON 中建议使用 `"0x..."` 字符串；反汇编/汇编在 x64 构建下使用当前调试器的 x64 指令解码/汇编能力。x64 下不会通过返回 `int` 的宿主接口暴露进程基址或句柄，避免 64 位值被截断。

寄存器写入、线程枚举/单线程挂起恢复、模块枚举、补丁详细管理等接口后续可以继续补齐，向 xdbg64 MCP 的 79 个工具规模扩展。

控制命令通过 `stdio` 传输时，由 MCP Server 每行发送一个 JSON-RPC 请求到 stdout，插件每行回写一个 JSON-RPC 响应到 server stdin。

工具列表请求：

```json
{"jsonrpc":"2.0","id":1,"method":"z0dbg.tools"}
```

工具调用请求：

```json
{"jsonrpc":"2.0","id":2,"method":"z0dbg.call","params":{"tool":"read_memory","address":"0x401000","size":16}}
```

也支持直接把工具名放在 method 后面：

```json
{"jsonrpc":"2.0","id":3,"method":"z0dbg.step_over"}
```

## 10. 常见任务

### 10.1 查看某个地址的内存

1. 打开 CPU 或内存窗口。
2. 使用跳转或跟随功能定位地址。
3. 在内存窗口查看字节、字符串或数据。
4. 需要自动化时使用 Python `z0dbg.read_memory(address, size)` 或 Lua `z0dbg.read_memory(address, size)`。

### 10.2 修改指令

1. 在 CPU 反汇编区域选中地址。
2. 使用右键菜单中的汇编功能。
3. 输入新指令并确认。
4. 在补丁窗口查看修改记录。

### 10.3 设置硬件断点

1. 在 CPU 或内存窗口选择目标地址。
2. 选择硬件断点类型：执行、访问或写入。
3. 根据数据大小选择断点长度。
4. 运行程序，命中后调试器会中断。

### 10.4 使用脚本自动化

1. 将 Python 脚本放入 `plugins\OllyPython`。
2. 将 Lua 脚本放入 `plugins\OllyLua`。
3. 从“脚本”菜单中选择脚本名并点击“运行”。
4. ODbgScript 脚本通过 ODbgScript 插件窗口和配置目录运行。

## 11. 故障排查

| 现象 | 中文处理方式 |
| --- | --- |
| 插件菜单不显示 | 检查 DLL 是否在 `plugins` 目录，位数是否匹配，是否导出 ODBG2 必要函数。 |
| 提示版本检查失败 | 重新编译插件并确认 `ODBG2_Pluginquery` 返回兼容版本。 |
| Python 脚本无法运行 | 检查 `plugins\python313` 下是否有 `python313.dll`、标准库 zip 或 Lib/DLLs。 |
| 提示安装 z0dbg 模块失败 | 检查 Python 初始化是否成功，插件目录是否完整，运行时位数是否匹配。 |
| Lua 提示找不到 DLL | 将 `lua55.dll` 放到 `plugins\lua55.dll` 或其他搜索路径。 |
| Lua 标准函数为 nil | 确认标准库已经打开，脚本运行时使用的是正确 DLL。 |
| 读取无效地址 | 确认地址属于被调试进程且内存页可读。 |
| 调试器关闭窗口时行为不对 | 检查“终止进程”或“脱离进程”选项。 |

## 12. 官方主页

官方主页：

```text
http://www.nt5core.com
```

## 13. 版本说明

本文档根据当前工程菜单、快捷键、脚本帮助和 SDK 接口整理。后续如果增加新的菜单、快捷键、脚本 API 或插件 API，应同步更新本文档和“帮助 -> 帮助内容”中的内置说明。
