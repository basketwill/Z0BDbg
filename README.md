# Z0BPcTools3 User Guide


This document describes the main UI, shortcuts, debugging features, trace features, script system, and plugin development APIs of the Z0BPcTools3 debugger.


## 🙏 Buy Me a Coffee

  
If this project helps you, consider buying me a coffee. Your support keeps me going!
-------------------------------------------------------------------------------------
## paypal account：
     zerobuffer@qq.com
  ## first name:           
                 JUN
  ## last name : 
                 WAN

--------------------------------------------------------------------------------------
## alipay and wechat

<img width="888" height="426" alt="image" src="https://github.com/user-attachments/assets/be651118-ce30-42c2-9c0d-7e73944d8c3a" />


## 1.  Basic Concepts


Z0BPcTools3 is a Windows user-mode debugger with an MDI-style interface. After a debug session starts, you can open CPU, memory, stack, modules, threads, breakpoints, patches, call stack, handles, windows, SEH chain, references, source code, and other views from menus or shortcuts.
<img width="1665" height="963" alt="image" src="https://github.com/user-attachments/assets/efdc0312-ff33-4572-9dc2-366481eb9fda" />

<img width="1656" height="957" alt="image" src="https://github.com/user-attachments/assets/5e27f839-c363-4e74-81bc-a69ae6503066" />

<img width="1669" height="968" alt="image" src="https://github.com/user-attachments/assets/06a5e4ce-e16e-46ca-9d2b-797a02fcaed1" />

<img width="2223" height="1333" alt="image" src="https://github.com/user-attachments/assets/f71e15e9-97ff-4726-8e2e-e6a2f44407ff" />

<img width="2232" height="1344" alt="image" src="https://github.com/user-attachments/assets/e913b069-b274-49fe-82a5-bc9e0112eb37" />

<img width="2237" height="1332" alt="image" src="https://github.com/user-attachments/assets/9904b3d3-2db5-4241-879b-1e894cab5fa2" />


Common windows:
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

### 4.2 Attach to Process

1. Use `File -> Attach` to open the process list.
2. Select the target process and confirm.
3. After attaching, you can pause and inspect threads, modules, memory, and CPU state.

### 4.3 Execution Control

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
