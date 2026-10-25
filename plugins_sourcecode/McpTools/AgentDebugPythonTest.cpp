#include "AgentDebugPython.h"
#include <assert.h>
#include <stdio.h>
#include <crtdbg.h>

static bool TestTool(const std::string& name, const std::string& arguments,
    std::string* data, std::string*, void*)
{
    assert(name == "get_status" && arguments == "{}");
    *data = "{\"ok\":true,\"status\":18}";
    return true;
}

static void TestOutput(const std::string&, void*) {}
static bool TestCancelled(void*) { return false; }

int main()
{
    _set_error_mode(_OUT_TO_STDERR);
    _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    std::vector<std::string> functions(1, "get_status");
    AgentPythonRunResult result;
    bool started = RunAgentDebugPython("state = dbg.get_status()\nprint(state['status'])",
        functions, 4, 10000, TestTool, TestOutput, TestCancelled, NULL, &result);
    if (!started) fprintf(stderr, "Python bridge: %s\n", result.error.c_str());
    assert(started);
    assert(result.ok && result.calls == 1 && result.output == "18\n");
    assert(!RunAgentDebugPython("import os", functions, 4, 10000,
        TestTool, TestOutput, TestCancelled, NULL, &result));
    assert(result.calls == 0 && result.error.find("Import") != std::string::npos);
    assert(!RunAgentDebugPython("for i in range(3):\n    dbg.get_status()",
        functions, 2, 10000, TestTool, TestOutput, TestCancelled, NULL, &result));
    assert(result.error.find("call limit") != std::string::npos);
    puts("PASS: bounded Python bridge, debugger call, rejected import and call limit");
    return 0;
}
