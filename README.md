# Z0BPcTools3 调试器使用说明 / User Guide

本文档说明 Z0BPcTools3 调试器的主要界面、快捷键、调试功能、跟踪功能、脚本系统和插件开发接口。

This document describes the main UI, shortcuts, debugging features, trace features, script system, and plugin development APIs of the Z0BPcTools3 debugger.

## 1. 基本概念 / Basic Concepts

Z0BPcTools3 是一个 Windows 用户态调试器，界面采用多文档窗口结构。调试会话打开后，可以通过菜单或快捷键打开 CPU、内存、堆栈、模块、线程、断点、补丁、调用栈、句柄、窗口、SEH 链、引用、源代码等窗口。

Z0BPcTools3 is a Windows user-mode debugger with an MDI-style interface. After a debug session starts, you can open CPU, memory, stack, modules, threads, breakpoints, patches, call stack, handles, windows, SEH chain, references, source code, and other views from menus or shortcuts.
<img width="1665" height="963" alt="image" src="https://github.com/user-attachments/assets/efdc0312-ff33-4572-9dc2-366481eb9fda" />

<img width="1656" height="957" alt="image" src="https://github.com/user-attachments/assets/5e27f839-c363-4e74-81bc-a69ae6503066" />

常用窗口：

Common windows:

| 中文 | English | 说明 / Description |
| --- | --- | --- |
| CPU 窗口 | CPU Window | 显示反汇编、寄存器、数据窗口和堆栈，是主要调试视图。 / Shows disassembly, registers, data, and stack. This is the main debugging view. |
| 记录窗口 | Log Window | 显示调试器日志、插件输出和脚本输出。 / Shows debugger logs, plugin output, and script output. |
| 模块窗口 | Modules Window | 查看当前进程加载的 EXE/DLL 模块。 / Lists loaded EXE/DLL modules in the debuggee. |
| 内存窗口 | Memory Window | 查看内存区段，支持跳转、搜索和内存断点。 / Shows memory regions and supports navigation, searching, and memory breakpoints. |
| 堆栈窗口 | Stack Window | 查看当前线程堆栈。 / Shows the current thread stack. |
| 线程窗口 | Threads Window | 查看和切换线程。 / Lists and switches threads. |
| 断点窗口 | Breakpoints Window | 查看、删除、管理断点。 / Lists, deletes, and manages breakpoints. |
| 补丁窗口 | Patches Window | 查看和管理已修改的代码或数据。 / Shows and manages patched code or data. |
| 调用栈窗口 | Call Stack Window | 查看当前线程调用栈。 / Shows the current thread call stack. |
| 跟踪窗口 | Trace Windows | 查看 RUN trace、HIT trace 等跟踪结果。 / Shows RUN trace, HIT trace, and related trace results. |

## 2. 快捷键 / Shortcuts

| 快捷键 / Shortcut | 中文功能 | English Function |
| --- | --- | --- |
| `Alt+L` | 打开记录窗口 | Show Log window |
| `Alt+E` | 打开模块窗口 | Show Modules window |
| `Alt+C` | 打开 CPU 窗口 | Show CPU window |
| `F9` | 运行或继续执行 | Run or continue |
| `F12` | 暂停当前调试进程 | Pause or suspend debuggee |
| `Ctrl+F2` | 重新开始上一次调试命令 | Restart last debug command |
| `Alt+F2` | 停止当前调试会话 | Stop current debug session |
| `F7` | 单步步入 | Step into |
| `F8` | 单步步过 | Step over |
| `Ctrl+F7` | 自动步入 | Auto step into |
| `Ctrl+F8` | 自动步过 | Auto step over |
| `Ctrl+F9` | 执行到返回 | Run until return |
| `Alt+F9` | 执行到用户代码 | Run to user code |
| `Ctrl+F11` | 跟踪步入 | Trace into |
| `Ctrl+F12` | 跟踪步过 | Trace over |
| `Ctrl+T` | 设置 RUN 跟踪条件 | Set RUN trace condition |
| `Alt+F5` | 切换总在最前 | Toggle always on top |
| `-` 或小键盘 `-` | CPU 视图中回退到上一条指令显示位置 | Move CPU view back to the previous instruction position |
| `Alt+G` | CPU 视图中跳转或跟随表达式 | Go to or follow expression in CPU view |
| `Enter` | 内存视图中跟随选中地址或反汇编位置 | Follow selected address or disassembly position in memory view |
| `F2` | 内存视图中设置内存访问断点 | Set memory access breakpoint in memory view |
| `Ctrl+B` | 内存视图中执行二进制搜索 | Binary search in memory view |

说明：部分快捷键只有在对应窗口处于活动状态时才生效。

Note: Some shortcuts work only when the related window is active.

## 3. 菜单功能 / Menu Reference

### 3.1 文件 / File

| 菜单 / Menu | 中文说明 | English Description |
| --- | --- | --- |
| 打开 | 选择并启动一个可执行文件进行调试。 | Open and start debugging an executable file. |
| IDA 静态反汇编内存模式 | 以 IDA 风格查看静态反汇编，偏向内存读取模式。 | Open IDA-style static disassembly using memory-oriented mode. |
| IDA 静态反汇编缓存模式 | 以 IDA 风格查看静态反汇编，使用缓存模式。 | Open IDA-style static disassembly using cache mode. |
| 附加 | 附加到已经运行的进程。 | Attach to a running process. |
| 退出 | 退出调试器。 | Exit the debugger. |

### 3.2 查看 / View

查看菜单用于打开各类调试窗口。

The View menu opens debugger windows.

| 菜单 / Menu | 中文说明 | English Description |
| --- | --- | --- |
| 记录 | 打开日志窗口。 | Open Log window. |
| 模块 | 打开模块窗口。 | Open Modules window. |
| 内存 | 打开内存窗口。 | Open Memory window. |
| 堆栈 | 打开堆栈窗口。 | Open Stack window. |
| 线程 | 打开线程窗口。 | Open Threads window. |
| 窗口 | 打开被调试进程窗口列表。 | Open Windows list. |
| 句柄 | 打开进程句柄列表。 | Open Handles list. |
| CPU | 打开 CPU 主窗口。 | Open CPU window. |
| SEH 链 | 打开结构化异常处理链窗口。 | Open SEH chain window. |
| 补丁 | 打开补丁窗口。 | Open Patches window. |
| 调用栈 | 打开调用栈窗口。 | Open Call Stack window. |
| 断点 | 打开断点窗口。 | Open Breakpoints window. |
| 监视 | 打开监视窗口。 | Open Watch window. |
| 引用 | 打开引用窗口。 | Open References window. |
| 源代码 | 打开源代码窗口。 | Open Source window. |
| 源文件 | 打开源文件窗口。 | Open Source Files window. |

### 3.3 调试 / Debug

| 菜单 / Menu | 快捷键 / Shortcut | 中文说明 | English Description |
| --- | --- | --- | --- |
| 运行 | `F9` | 运行或继续执行被调试程序。 | Run or continue the debuggee. |
| 暂停 | `F12` | 暂停当前调试进程。 | Pause the current debuggee. |
| 重新开始 | `Ctrl+F2` | 重新开始上一次调试命令。 | Restart the last debug command. |
| 关闭 | `Alt+F2` | 停止当前调试会话。 | Stop the current debug session. |
| 步入 | `F7` | 执行一条指令，遇到调用会进入目标函数。 | Execute one instruction and enter calls. |
| 步过 | `F8` | 执行一条指令，遇到调用会直接执行完调用。 | Execute one instruction and step over calls. |
| 执行到返回 | `Ctrl+F9` | 运行到当前函数返回位置。 | Run until the current function returns. |
| 执行到用户代码 | `Alt+F9` | 从系统代码运行到用户代码。 | Run from system code to user code. |
| 硬件断点 |  | 设置或管理硬件断点。 | Set or manage hardware breakpoints. |
| 检查 |  | 打开寄存器或运行状态检查相关对话框。 | Open register or runtime check dialog. |
| 调用 DLL 导出函数 |  | 调用目标 DLL 的导出函数。 | Call exported functions from a target DLL. |
| 参数 |  | 设置程序启动参数。 | Configure command-line arguments. |
| 选择导入库目录 |  | 设置导入库目录。 | Select import library directory. |
| 选择符号路径 |  | 设置符号文件搜索路径。 | Select symbol search path. |

### 3.4 跟踪 / Trace

跟踪菜单把自动执行、RUN trace、HIT trace 和条件跟踪功能集中在一起。

The Trace menu groups auto execution, RUN trace, HIT trace, and conditional trace features.

| 菜单 / Menu | 快捷键 / Shortcut | 中文说明 | English Description |
| --- | --- | --- | --- |
| 自动步入 | `Ctrl+F7` | 连续执行步入操作。 | Repeatedly execute step-into operations. |
| 自动步过 | `Ctrl+F8` | 连续执行步过操作。 | Repeatedly execute step-over operations. |
| RUN 跟踪 |  | 记录运行路径或运行过程中的指令信息。 | Record execution path or runtime instruction information. |
| HIT 跟踪 |  | 记录命中的代码位置，用于覆盖率或路径观察。 | Record hit code locations for coverage or path observation. |
| 打开或清除 RUN 跟踪 |  | 打开 RUN 跟踪窗口或清除已有跟踪结果。 | Open or clear RUN trace results. |
| 跟踪步入 | `Ctrl+F11` | 执行一次带记录的步入。 | Trace one step into. |
| 跟踪步过 | `Ctrl+F12` | 执行一次带记录的步过。 | Trace one step over. |
| 设置条件 | `Ctrl+T` | 设置 RUN 跟踪条件、计数或暂停行为。 | Set RUN trace condition, count, or pause behavior. |
| 关闭 RUN 跟踪 |  | 停止当前 RUN 跟踪。 | Stop current RUN trace. |

### 3.5 脚本 / Script

脚本菜单用于 ODbgScript、OllyPython、OllyLua 脚本。脚本文件会按目录自动生成菜单。

The Script menu is used for ODbgScript, OllyPython, and OllyLua scripts. Script files are discovered from directories and converted into menu entries automatically.

| 脚本系统 / Script System | 目录 / Directory | 说明 / Description |
| --- | --- | --- |
| ODbgScript | 由 ODbgScript 配置项决定，通常通过脚本插件管理 | OllyDbg/ODbgScript 风格脚本。 / OllyDbg/ODbgScript-style scripts. |
| OllyPython | `plugins\OllyPython\*.py` | 每个 `.py` 文件显示为 `脚本 -> OllyPython -> 文件名 -> 运行`。 / Each `.py` file appears as `Script -> OllyPython -> filename -> Run`. |
| OllyLua | `plugins\OllyLua\*.lua` | 每个 `.lua` 文件显示为 `脚本 -> OllyLua -> 文件名 -> 运行`。 / Each `.lua` file appears as `Script -> OllyLua -> filename -> Run`. |

### 3.6 插件 / Plugin

| 菜单 / Menu | 中文说明 | English Description |
| --- | --- | --- |
| 查找/添加插件 | 从文件中选择并加载插件 DLL。 | Select and load a plugin DLL from disk. |
| 插件名 -> 插件菜单项 | 每个插件按插件名分组显示自己的菜单。 | Each plugin is grouped by plugin name and exposes its own submenu. |

插件应放在 `plugins` 目录或通过“查找/添加插件”加载。插件位数必须和当前调试器位数一致，例如 x64 调试器需要 x64 插件 DLL。

Plugins should be placed in the `plugins` directory or loaded from "Find/Add Plugin". Plugin bitness must match debugger bitness. For example, the x64 debugger requires x64 plugin DLLs.

### 3.7 选项 / Options

| 菜单 / Menu | 中文说明 | English Description |
| --- | --- | --- |
| 属性设置 | 打开统一设置对话框。左侧是全部展开的树结构，右侧显示当前设置面板。 | Open the unified settings dialog. The left side is a fully expanded tree, and the right side shows the selected settings panel. |
| JIT 调试选项 | 配置即时调试相关选项。 | Configure just-in-time debugging options. |
| 暂停在程序入口点 | 启动调试后在入口点暂停。 | Pause at program entry point after launch. |
| 立即运行 | 启动调试后立即运行。 | Run immediately after launch. |
| 关闭窗口时终止进程 | 关闭调试窗口时终止被调试进程。 | Terminate debuggee when closing debug window. |
| 关闭窗口时脱离进程 | 关闭调试窗口时从被调试进程脱离。 | Detach from debuggee when closing debug window. |
| 函数签名识别 | 启用或关闭函数签名识别。 | Enable or disable function signature recognition. |
| 添加到资源管理器右键菜单 | 将调试入口添加到 Windows Explorer 右键菜单。 | Add debugger entry to Windows Explorer context menu. |

### 3.8 窗口 / Window

| 菜单 / Menu | 快捷键 / Shortcut | 中文说明 | English Description |
| --- | --- | --- | --- |
| 总在最前 | `Alt+F5` | 切换主窗口总在最前。 | Toggle always-on-top for the main window. |
| 中文 |  | 切换到中文界面。 | Switch UI language to Chinese. |
| English |  | 切换到英文界面。 | Switch UI language to English. |
| 层叠 |  | 层叠排列 MDI 子窗口。 | Cascade MDI child windows. |
| 水平平铺 |  | 水平平铺 MDI 子窗口。 | Tile MDI child windows horizontally. |
| 垂直平铺 |  | 垂直平铺 MDI 子窗口。 | Tile MDI child windows vertically. |

### 3.9 帮助 / Help

| 菜单 / Menu | 中文说明 | English Description |
| --- | --- | --- |
| 关于 | 显示程序版本和版权信息。 | Show program version and copyright information. |
| 帮助内容 | 打开帮助对话框，包含调试器基本用法、脚本说明、Python/Lua API 和插件 API。 | Open help dialog with basic debugger usage, script guide, Python/Lua APIs, and plugin APIs. |
| 官方主页 | 打开官方主页：`http://www.nt5core.com`。 | Open official site: `http://www.nt5core.com`. |

## 4. 调试流程 / Debugging Workflow

### 4.1 启动新进程 / Launch a New Process

1. 使用“文件 -> 打开”选择 EXE。
2. 如需参数，先使用“调试 -> 参数”设置命令行参数。
3. 根据需要在“选项”中选择“暂停在程序入口点”或“立即运行”。
4. 程序启动后，使用 CPU 窗口查看入口点、寄存器、堆栈和内存。

English:

1. Use `File -> Open` to select an EXE.
2. Use `Debug -> Arguments` first if command-line arguments are needed.
3. Choose `Pause at entry point` or `Run immediately` in Options as needed.
4. After launch, use the CPU window to inspect entry point, registers, stack, and memory.

### 4.2 附加到进程 / Attach to Process

1. 使用“文件 -> 附加”打开进程列表。
2. 选择目标进程并确认。
3. 附加后可以暂停、查看线程、模块、内存和 CPU 状态。

English:

1. Use `File -> Attach` to open the process list.
2. Select the target process and confirm.
3. After attaching, you can pause and inspect threads, modules, memory, and CPU state.

### 4.3 基本执行控制 / Execution Control

| 操作 / Operation | 中文说明 | English Description |
| --- | --- | --- |
| 运行 / Run | 继续执行直到断点、异常、暂停或进程退出。 | Continue until breakpoint, exception, pause, or process exit. |
| 暂停 / Pause | 中断正在运行的进程，返回调试器控制。 | Interrupt a running debuggee and return control to the debugger. |
| 步入 / Step Into | 单步执行并进入调用。 | Single step and enter calls. |
| 步过 / Step Over | 单步执行但跳过调用内部。 | Single step but skip call internals. |
| 执行到返回 / Run Until Return | 当前函数返回时中断。 | Break when the current function returns. |
| 执行到用户代码 / Run to User Code | 跳过系统代码，回到用户模块代码。 | Skip system code and return to user module code. |
| 重新开始 / Restart | 重新启动上一次调试目标。 | Restart the last debug target. |
| 关闭 / Stop | 终止或关闭当前调试会话。 | Terminate or close current debug session. |

## 5. 断点 / Breakpoints

Z0BPcTools3 支持软件断点、内存断点和硬件断点。断点可以通过 CPU 窗口右键菜单、内存窗口、断点窗口、脚本 API 或插件 API 操作。

Z0BPcTools3 supports software breakpoints, memory breakpoints, and hardware breakpoints. Breakpoints can be controlled from CPU context menus, memory view, breakpoints window, script APIs, or plugin APIs.

| 类型 / Type | 中文说明 | English Description |
| --- | --- | --- |
| 软件断点 | 使用断点指令或调试器机制在目标地址中断。 | Breaks at target address using software breakpoint mechanisms. |
| 内存断点 | 对内存访问、写入等行为设置断点。 | Breaks on memory access or write. |
| 硬件执行断点 | 使用 CPU 调试寄存器在执行目标地址时中断。 | Uses CPU debug registers to break on execution. |
| 硬件访问断点 | 在访问目标地址时中断。 | Breaks on access to target address. |
| 硬件写入断点 | 在写入目标地址时中断。 | Breaks on write to target address. |

常用操作：

Common operations:

| 操作 / Operation | 中文说明 | English Description |
| --- | --- | --- |
| 设置断点 | 在 CPU 或内存窗口选择地址后设置。 | Select an address in CPU or memory view and set breakpoint. |
| 删除断点 | 在断点窗口或右键菜单删除。 | Delete from Breakpoints window or context menu. |
| 删除全部断点 | 通过断点窗口、脚本 API 或插件 API 清空。 | Delete all breakpoints from Breakpoints window, script API, or plugin API. |
| 查看断点 | 打开“查看 -> 断点”。 | Open `View -> Breakpoints`. |
| 条件/计数 | 跟踪条件和部分断点逻辑可配合条件表达式使用。 | Trace conditions and some breakpoint logic can use expressions. |

## 6. CPU、内存、堆栈窗口 / CPU, Memory, and Stack Views

### 6.1 CPU 窗口 / CPU Window

CPU 窗口是主要调试工作区，通常包括反汇编、寄存器、数据和堆栈区域。

The CPU window is the main debugging workspace and usually contains disassembly, registers, data, and stack panes.

支持的常见操作：

Common operations:

| 操作 / Operation | 中文说明 | English Description |
| --- | --- | --- |
| 汇编 | 修改选中地址处的指令。 | Assemble instruction at selected address. |
| 跳转/跟随 | 跳转到表达式、地址、调用目标或数据引用。 | Go to or follow expression, address, call target, or data reference. |
| 二进制编辑 | 编辑、填零、填 NOP、复制或粘贴二进制数据。 | Edit, fill zero, fill NOP, copy, or paste binary data. |
| 复制文本 | 复制反汇编或数据文本。 | Copy disassembly or data text. |
| 设置内存断点 | 设置访问、写入或删除内存断点。 | Set access/write memory breakpoint or remove it. |
| 设置硬件断点 | 设置执行、访问、写入硬件断点，并选择长度。 | Set execute/access/write hardware breakpoints with length. |
| 显示模式 | 切换 8/16/32 字节显示，ANSI、Unicode、UTF-8 字符显示。 | Switch 8/16/32-byte display and ANSI/Unicode/UTF-8 text display. |
| 回退显示 | 使用 `-` 回退到上一条指令显示位置。 | Use `-` to move back to the previous instruction display position. |

### 6.2 内存窗口 / Memory Window

内存窗口用于查看进程内存区域、跟随地址、搜索二进制内容和设置内存断点。

The Memory window is used to inspect memory regions, follow addresses, search binary data, and set memory breakpoints.

| 快捷键 / Shortcut | 中文功能 | English Function |
| --- | --- | --- |
| `Enter` | 跟随选中地址或反汇编位置 | Follow selected address or disassembly position |
| `F2` | 设置内存访问断点 | Set memory access breakpoint |
| `Ctrl+B` | 二进制搜索 | Binary search |

### 6.3 堆栈窗口 / Stack Window

堆栈窗口显示当前线程栈内容，可配合 CPU 窗口查看返回地址、函数参数和局部数据。

The Stack window shows the current thread stack and can be used with the CPU window to inspect return addresses, function arguments, and local data.

## 7. 跟踪功能 / Trace Features

跟踪功能用于记录程序执行路径、命中地址、自动步进结果或受条件控制的运行结果。

Trace features record execution paths, hit addresses, auto-step results, or condition-controlled execution results.

| 功能 / Feature | 中文说明 | English Description |
| --- | --- | --- |
| 自动步入 | 连续执行步入，适合观察每条指令执行。 | Repeated step into, useful for observing instruction-by-instruction execution. |
| 自动步过 | 连续执行步过，适合跳过函数内部细节。 | Repeated step over, useful for skipping function internals. |
| RUN 跟踪 | 记录运行期间的路径或指令。 | Records execution path or instructions during run. |
| HIT 跟踪 | 记录命中的代码位置。 | Records hit code locations. |
| 跟踪步入 | 单次带记录的步入。 | One traced step into. |
| 跟踪步过 | 单次带记录的步过。 | One traced step over. |
| 跟踪条件 | 使用条件表达式、计数或暂停命令控制跟踪。 | Controls tracing with conditions, counts, or pause-on-command behavior. |

建议用法：

Recommended usage:

1. 先在 CPU 窗口定位到关注代码。
2. 如果只想记录一段运行路径，启用 RUN 跟踪。
3. 如果只关心某些地址是否执行，使用 HIT 跟踪。
4. 如果跟踪太多，使用 `Ctrl+T` 设置条件、次数或暂停行为。
5. 完成后使用“关闭 RUN 跟踪”停止记录。

English:

1. Locate the code of interest in the CPU window.
2. Use RUN trace when you need to record an execution path.
3. Use HIT trace when you only need to know whether addresses were executed.
4. Use `Ctrl+T` to set condition, count, or pause behavior when trace output is too large.
5. Stop tracing with `Stop RUN Trace` when finished.

## 8. 脚本系统 / Script System

Z0BPcTools3 当前支持 ODbgScript、OllyPython 和 OllyLua。脚本菜单会按脚本类型和文件名自动组织。

Z0BPcTools3 currently supports ODbgScript, OllyPython, and OllyLua. The Script menu organizes scripts by script type and filename.

### 8.1 ODbgScript

ODbgScript 使用 OllyDbg 脚本语法，适合自动化断点、运行、内存读写、汇编、搜索、标签和注释等操作。

ODbgScript uses OllyDbg script syntax and is suitable for automating breakpoints, execution, memory operations, assembling, searching, labels, and comments.

常用命令：

Common commands:

| 命令 / Command | 中文说明 | English Description |
| --- | --- | --- |
| `bp addr` | 设置软件断点。 | Set software breakpoint. |
| `bphwc addr` | 设置硬件执行断点。 | Set hardware execution breakpoint. |
| `bphws addr` | 设置硬件写入断点。 | Set hardware write breakpoint. |
| `bpm addr` | 设置内存断点。 | Set memory breakpoint. |
| `bphwm addr` | 设置硬件内存断点。 | Set hardware memory breakpoint. |
| `bc addr` | 删除断点。 | Clear breakpoint. |
| `run` | 运行或继续。 | Run or continue. |
| `sti` | 步入。 | Step into. |
| `sto` | 步过。 | Step over. |
| `pause` | 暂停。 | Pause. |
| `readstr` | 读取字符串。 | Read string. |
| `writemem` | 写内存。 | Write memory. |
| `asm` | 汇编指令。 | Assemble instruction. |
| `exec ... ende` | 执行多行汇编块。 | Execute a multi-line assembly block. |
| `find` | 在当前区域搜索。 | Search in current area. |
| `findmem` | 在内存中搜索。 | Search memory. |
| `gpa` | 获取 API 地址。 | Get API address. |
| `lbl` | 设置标签。 | Set label. |
| `cmt` | 设置注释。 | Set comment. |
| `eval` | 计算表达式。 | Evaluate expression. |

完整 ODbgScript 语法可以参考 `odbgscript-master\doc\ODbgScript.txt`。

Full ODbgScript syntax can be found in `odbgscript-master\doc\ODbgScript.txt`.

### 8.2 OllyPython

OllyPython 使用内置 Python 3.x 运行时，不支持 Python 2.x。Python 运行时按动态 DLL 方式加载，避免静态链接导致主程序变大。

OllyPython uses an embedded Python 3.x runtime and does not support Python 2.x. The runtime is loaded dynamically from DLLs to avoid increasing the main executable size through static linking.

推荐目录结构：

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

`.py` 文件会显示为：

`.py` files are shown as:

```text
脚本 -> OllyPython -> example -> 运行
Script -> OllyPython -> example -> Run
```

Python 模块名为 `z0dbg`。

The Python module name is `z0dbg`.

示例：

Example:

```python
import z0dbg

print(z0dbg.get_status())
data = z0dbg.read_memory(0x401000, 16)
print(data.hex())
z0dbg.set_breakpoint(0x401000)
z0dbg.step_over()
```

当前支持的 `z0dbg` 接口：

Currently supported `z0dbg` APIs:

| API | 中文说明 | English Description |
| --- | --- | --- |
| `read_memory(address, size)` | 读取被调试进程内存。 | Read debuggee memory. |
| `write_memory(address, data)` | 写入被调试进程内存。 | Write debuggee memory. |
| `get_status()` | 获取调试器运行状态。 | Get debugger status. |
| `get_cpu_thread_id()` | 获取当前 CPU 线程 ID。 | Get current CPU thread ID. |
| `set_breakpoint(address)` | 设置软件断点。 | Set software breakpoint. |
| `delete_breakpoint(address)` | 删除指定断点。 | Delete breakpoint at address. |
| `delete_breakpoints()` | 删除全部软件断点。 | Delete all software breakpoints. |
| `set_memory_breakpoint(address, size, type)` | 设置内存断点。 | Set memory breakpoint. |
| `remove_memory_breakpoint(address)` | 删除内存断点。 | Remove memory breakpoint. |
| `set_hardware_breakpoint(address, size, type)` | 设置硬件断点。 | Set hardware breakpoint. |
| `delete_hardware_breakpoint(address)` | 删除硬件断点。 | Delete hardware breakpoint. |
| `delete_hardware_breakpoint_index(index)` | 按硬件断点槽位删除断点。 | Delete hardware breakpoint by slot index. |
| `run()` | 运行或继续。 | Run or continue. |
| `go(address)` | 运行到指定地址。 | Run to address. |
| `suspend()` | 暂停调试进程。 | Suspend debuggee. |
| `step_into()` | 单步步入。 | Step into. |
| `step_over()` | 单步步过。 | Step over. |
| `auto_step_into()` | 自动步入。 | Auto step into. |
| `auto_step_over()` | 自动步过。 | Auto step over. |
| `stop_animation()` | 停止自动步进或动画执行。 | Stop auto stepping or animation. |
| `set_temp_breakpoint(address)` | 设置临时断点。 | Set temporary breakpoint. |
| `find_name(name)` | 查找符号或名称。 | Find symbol or name. |
| `insert_name(address, name)` | 插入名称。 | Insert name. |
| `decode_address(address)` | 解码地址为模块、符号或文本形式。 | Decode address into module, symbol, or text. |
| `evaluate(expression)` | 计算表达式。 | Evaluate expression. |
| `disasm(address)` | 反汇编指定地址。 | Disassemble address. |
| `assemble(address, text)` | 汇编指令文本。 | Assemble instruction text. |
| `patch_assemble(address, text)` | 汇编并写入补丁。 | Assemble and patch memory. |
| `find_data(address, data)` | 搜索二进制数据。 | Search binary data. |
| `follow_call(address)` | 跟随调用目标。 | Follow call target. |
| `get_breakpoint_type(address)` | 获取断点类型。 | Get breakpoint type. |
| `get_next_breakpoint(address)` | 查找下一个断点。 | Find next breakpoint. |
| `redraw_disasm()` | 刷新反汇编窗口。 | Redraw disassembly. |
| `redraw_registers()` | 刷新寄存器窗口。 | Redraw registers. |
| `redraw_list()` | 刷新列表窗口。 | Redraw list window. |
| `suspend_all_threads()` | 暂停全部线程。 | Suspend all threads. |
| `show_memory()` | 打开内存窗口。 | Show Memory window. |
| `show_breakpoints()` | 打开断点窗口。 | Show Breakpoints window. |
| `show_threads()` | 打开线程窗口。 | Show Threads window. |
| `show_trace()` | 打开跟踪窗口。 | Show Trace window. |
| `show_windows()` | 打开窗口列表。 | Show Windows list. |
| `show_patches()` | 打开补丁窗口。 | Show Patches window. |
| `set_trace_condition(expression)` | 设置跟踪条件。 | Set trace condition. |
| `set_trace_count(count)` | 设置跟踪计数。 | Set trace count. |
| `set_trace_pause_on_commands(enable)` | 设置跟踪命令暂停行为。 | Set pause-on-command behavior for trace. |
| `is_prefix(address)` | 判断地址处是否为前缀指令。 | Test whether instruction at address is a prefix. |
| `input_text(title, prompt)` | 显示输入框并返回文本。 | Show input dialog and return text. |
| `show_text(title, text)` | 显示文本对话框。 | Show text dialog. |
| `API_VERSION` | Python API 版本常量。 | Python API version constant. |
| `ADDRESS_BITS` | 当前地址位数。 | Current address bit width. |
| `ADDRESS_API_BITS` | 地址 API 位数。 | Address API bit width. |

### 8.3 OllyLua

OllyLua 使用动态加载的 Lua DLL。当前加载名为 `lua55.dll`，运行的是原始 `.lua` 脚本文件，不要求用户先编译为字节码。

OllyLua dynamically loads the Lua DLL. The current DLL name is `lua55.dll`. It runs source `.lua` scripts directly and does not require users to precompile bytecode.

Lua DLL 搜索位置：

Lua DLL search locations:

```text
plugins\lua55.dll
lua\lua55.dll
程序目录\lua55.dll
当前目录\lua55.dll
PATH 中的 lua55.dll
```

推荐目录结构：

Recommended directory layout:

```text
plugins\
  lua55.dll
  OllyLua\
    example.lua
```

`.lua` 文件会显示为：

`.lua` files are shown as:

```text
脚本 -> OllyLua -> example -> 运行
Script -> OllyLua -> example -> Run
```

Lua 中也通过 `z0dbg` 表访问调试器功能。

Lua scripts access debugger features through the `z0dbg` table.

常用接口：

Common APIs:

| API | 中文说明 | English Description |
| --- | --- | --- |
| `z0dbg.read_memory(address, size)` | 读取被调试进程内存。 | Read debuggee memory. |
| `z0dbg.write_memory(address, data)` | 写入被调试进程内存。 | Write debuggee memory. |
| `z0dbg.get_status()` | 获取调试器状态。 | Get debugger status. |
| `z0dbg.get_cpu_thread_id()` | 获取当前 CPU 线程 ID。 | Get current CPU thread ID. |
| `z0dbg.set_breakpoint(address)` | 设置软件断点。 | Set software breakpoint. |
| `z0dbg.delete_breakpoint(address)` | 删除指定断点。 | Delete breakpoint at address. |
| `z0dbg.delete_breakpoints()` | 删除全部软件断点。 | Delete all software breakpoints. |
| `z0dbg.set_memory_breakpoint(address, size, type)` | 设置内存断点。 | Set memory breakpoint. |
| `z0dbg.set_hardware_breakpoint(address, size, type)` | 设置硬件断点。 | Set hardware breakpoint. |
| `z0dbg.run()` | 运行或继续。 | Run or continue. |
| `z0dbg.go(address)` | 运行到指定地址。 | Run to address. |
| `z0dbg.suspend()` | 暂停调试进程。 | Suspend debuggee. |
| `z0dbg.step_into()` | 单步步入。 | Step into. |
| `z0dbg.step_over()` | 单步步过。 | Step over. |
| `z0dbg.find_name(name)` | 查找名称。 | Find name. |
| `z0dbg.insert_name(address, name)` | 插入名称。 | Insert name. |
| `z0dbg.decode_address(address)` | 解码地址。 | Decode address. |
| `z0dbg.input_text(title, prompt)` | 显示输入框。 | Show input dialog. |
| `z0dbg.show_text(title, text)` | 显示文本。 | Show text dialog. |

## 9. 插件开发 / Plugin Development

Z0BPcTools3 支持 OllyDbg 2.0 风格插件接口，并提供当前调试器 SDK 头文件和导入库。

Z0BPcTools3 supports OllyDbg 2.0-style plugin interfaces and provides SDK headers and import libraries for this debugger.

SDK 位置：

SDK locations:

```text
sdk\include\plugin.h
sdk\lib\x64\Release\Z0BPcTools3.lib
sdk\lib\Win32\Release\Z0BPcTools3.lib
```

插件 DLL 必须导出必要的 ODBG2 插件函数。常见导出函数：

Plugin DLLs must export required ODBG2 plugin functions. Common exports:

| 导出函数 / Export | 中文说明 | English Description |
| --- | --- | --- |
| `ODBG2_Pluginquery` | 查询插件名称、版本和兼容性。 | Query plugin name, version, and compatibility. |
| `ODBG2_Plugininit` | 插件初始化。 | Initialize plugin. |
| `ODBG2_Pluginmenu` | 返回插件菜单结构。 | Return plugin menu structure. |
| `ODBG2_Pluginaction` | 处理插件菜单命令。 | Handle plugin menu actions. |
| `ODBG2_Pluginmainloop` | 接收调试器主循环事件。 | Receive debugger main loop events. |
| `ODBG2_Pluginsaveudd` | 保存用户数据库数据。 | Save user database data. |
| `ODBG2_Pluginuddrecord` | 读取用户数据库记录。 | Load user database records. |
| `ODBG2_Pluginclose` | 调试会话关闭通知。 | Debug session close notification. |
| `ODBG2_Plugindestroy` | 插件卸载清理。 | Plugin unload cleanup. |

常用调试器 API：

Common debugger APIs:

| API | 中文说明 | English Description |
| --- | --- | --- |
| `Readmemory` | 读取被调试进程内存。 | Read debuggee memory. |
| `Writememory` | 写入被调试进程内存。 | Write debuggee memory. |
| `Getstatus` | 获取调试器状态。 | Get debugger status. |
| `Getcputhreadid` | 获取 CPU 当前线程 ID。 | Get current CPU thread ID. |
| `Setbreakpoint` | 设置断点。 | Set breakpoint. |
| `Deletebreakpoints` | 删除断点。 | Delete breakpoints. |
| `Setmembreakpoint` | 设置内存断点。 | Set memory breakpoint. |
| `Sethardwarebreakpoint` | 设置硬件断点。 | Set hardware breakpoint. |
| `Findname` | 查找名称。 | Find name. |
| `Insertname` | 插入名称。 | Insert name. |
| `Decodeaddress` | 解码地址。 | Decode address. |
| `Expression` | 计算表达式。 | Evaluate expression. |
| `Disasm` | 反汇编。 | Disassemble. |
| `Assemble` | 汇编。 | Assemble. |
| `Finddata` | 搜索二进制数据。 | Find binary data. |
| `Followcall` | 跟随调用。 | Follow call. |
| `Isprefix` | 判断指令前缀。 | Test instruction prefix. |
| `Addtolist` | 输出日志到列表。 | Add log entry to list. |
| `Redrawdisassembler` | 刷新反汇编窗口。 | Redraw disassembler. |
| `Createthreadwindow` | 创建或打开线程窗口。 | Create or open thread window. |
| `Settracecondition` | 设置跟踪条件。 | Set trace condition. |
| `Settracecount` | 设置跟踪计数。 | Set trace count. |
| `Settracepauseoncommands` | 设置跟踪暂停行为。 | Set trace pause-on-command behavior. |
| `Redrawcpudisasm` | 刷新 CPU 反汇编区域。 | Redraw CPU disassembly pane. |
| `Redrawcpureg` | 刷新 CPU 寄存器区域。 | Redraw CPU register pane. |
| `Redrawlist` | 刷新列表。 | Redraw list. |
| `Setcpu` | 设置 CPU 窗口定位。 | Set CPU window position. |
| `Setdisasm` | 设置反汇编窗口定位。 | Set disassembly position. |

SDK 辅助函数：

SDK helper functions:

| API | 中文说明 | English Description |
| --- | --- | --- |
| `Z0B_InitSorted` | 初始化排序表结构。 | Initialize sorted table structure. |
| `Z0B_InitTable` | 初始化表格结构。 | Initialize table structure. |
| `Z0B_InitTableColumn` | 初始化表格列。 | Initialize table column. |
| `Z0B_CreateTableWindow` | 创建表格窗口。 | Create table window. |

插件菜单显示规则：

Plugin menu display rule:

```text
插件 -> 插件名 -> 插件自己的菜单项
Plugin -> PluginName -> Plugin-defined menu items
```

注意事项：

Notes:

| 问题 / Issue | 中文说明 | English Description |
| --- | --- | --- |
| 位数不匹配 | x64 调试器只能加载 x64 插件，Win32 调试器只能加载 Win32 插件。 | x64 debugger loads only x64 plugins, and Win32 debugger loads only Win32 plugins. |
| 版本检查失败 | 插件需要返回兼容的 ODBG2 版本。 | Plugin must return a compatible ODBG2 version. |
| 缺少导出函数 | 插件 DLL 必须导出必要入口。 | Plugin DLL must export required entry points. |
| 重复加载 | 同一路径或同名插件不应重复加载。 | The same path or same plugin name should not be loaded repeatedly. |

## 10. 常见任务 / Common Tasks

### 10.1 查看某个地址的内存 / Read Memory at an Address

中文：

1. 打开 CPU 或内存窗口。
2. 使用跳转或跟随功能定位地址。
3. 在内存窗口查看字节、字符串或数据。
4. 需要自动化时使用 Python `z0dbg.read_memory(address, size)` 或 Lua `z0dbg.read_memory(address, size)`。

English:

1. Open CPU or Memory window.
2. Use Go to or Follow to locate the address.
3. Inspect bytes, strings, or data in Memory window.
4. For automation, use Python `z0dbg.read_memory(address, size)` or Lua `z0dbg.read_memory(address, size)`.

### 10.2 修改指令 / Patch Instruction

中文：

1. 在 CPU 反汇编区域选中地址。
2. 使用右键菜单中的汇编功能。
3. 输入新指令并确认。
4. 在补丁窗口查看修改记录。

English:

1. Select an address in CPU disassembly pane.
2. Use Assemble from the context menu.
3. Enter the new instruction and confirm.
4. Check changes in the Patches window.

### 10.3 设置硬件断点 / Set Hardware Breakpoint

中文：

1. 在 CPU 或内存窗口选择目标地址。
2. 选择硬件断点类型：执行、访问或写入。
3. 根据数据大小选择断点长度。
4. 运行程序，命中后调试器会中断。

English:

1. Select the target address in CPU or Memory view.
2. Choose hardware breakpoint type: execute, access, or write.
3. Select breakpoint length according to data size.
4. Run the program. The debugger breaks when the breakpoint is hit.

### 10.4 使用脚本自动化 / Automate with Scripts

中文：

1. 将 Python 脚本放入 `plugins\OllyPython`。
2. 将 Lua 脚本放入 `plugins\OllyLua`。
3. 从“脚本”菜单中选择脚本名并点击“运行”。
4. ODbgScript 脚本通过 ODbgScript 插件窗口和配置目录运行。

English:

1. Place Python scripts in `plugins\OllyPython`.
2. Place Lua scripts in `plugins\OllyLua`.
3. Select the script name from the Script menu and click Run.
4. ODbgScript scripts run through the ODbgScript plugin window and configured script directory.

## 11. 故障排查 / Troubleshooting

| 现象 / Symptom | 中文处理方式 | English Fix |
| --- | --- | --- |
| 插件菜单不显示 | 检查 DLL 是否在 `plugins` 目录，位数是否匹配，是否导出 ODBG2 必要函数。 | Check DLL location, bitness, and required ODBG2 exports. |
| 提示版本检查失败 | 重新编译插件并确认 `ODBG2_Pluginquery` 返回兼容版本。 | Rebuild plugin and ensure `ODBG2_Pluginquery` returns a compatible version. |
| Python 脚本无法运行 | 检查 `plugins\python313` 下是否有 `python313.dll`、标准库 zip 或 Lib/DLLs。 | Check `python313.dll`, stdlib zip, or Lib/DLLs under `plugins\python313`. |
| 提示安装 z0dbg 模块失败 | 检查 Python 初始化是否成功，插件目录是否完整，运行时位数是否匹配。 | Check Python initialization, plugin directory completeness, and runtime bitness. |
| Lua 提示找不到 DLL | 将 `lua55.dll` 放到 `plugins\lua55.dll` 或其他搜索路径。 | Put `lua55.dll` in `plugins\lua55.dll` or another search path. |
| Lua 标准函数为 nil | 确认标准库已经打开，脚本运行时使用的是正确 DLL。 | Ensure standard libraries are opened and the correct DLL is loaded. |
| 读取无效地址 | 确认地址属于被调试进程且内存页可读。 | Ensure the address belongs to the debuggee and the memory page is readable. |
| 调试器关闭窗口时行为不对 | 检查“终止进程”或“脱离进程”选项。 | Check Terminate or Detach options on close. |

## 12. 官方主页 / Official Site

官方主页：

Official site:

```text
http://www.nt5core.com
```

## 13. 版本说明 / Notes

本文档根据当前工程菜单、快捷键、脚本帮助和 SDK 接口整理。后续如果增加新的菜单、快捷键、脚本 API 或插件 API，应同步更新本文档和“帮助 -> 帮助内容”中的内置说明。

This document is based on the current project menus, shortcuts, script help, and SDK APIs. When new menus, shortcuts, script APIs, or plugin APIs are added, update this document and the built-in `Help -> Help Contents` dialog together.
