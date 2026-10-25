#include "AgentCheckpoint.h"
#include <assert.h>
#include <stdio.h>

int main()
{
    const std::string miss = "{\"result\":{\"ok\":false,\"address\":\"0x0\"}}";
    assert(TaskObservationSucceeded("find_import_by_name", miss));
    assert(TaskObservationSucceeded("resolve_symbol", miss));
    assert(!TaskObservationSucceeded("read_memory", miss));
    assert(!TaskObservationSucceeded("find_import_by_name", "{\"error\":{\"code\":-32005},\"result\":{\"ok\":false,\"address\":\"0x0\"}}"));

    AgentAssertion absent;
    absent.tool = "find_import_by_name";
    absent.arguments = "{\"name\":\"WTSEnumerateProcesses\"}";
    absent.expected = "{\"ok\":false,\"address\":\"0x0\"}";
    assert(AssertionReceipt(absent, absent.arguments, miss));

    AgentTask task;
    task.steps.push_back(AgentTaskStep());
    task.steps[0].kind = "observation";
    task.steps[0].criterion = "Inspect imports";
    AgentTaskEvidence evidence = {};
    evidence.step = 0;
    evidence.tool = absent.tool;
    evidence.arguments = absent.arguments;
    evidence.result = miss;
    evidence.success = evidence.read_only = true;
    task.evidence.push_back(evidence);
    assert(ApplyTaskCheck("{\"step\":1,\"status\":\"verified\",\"evidence\":[1],\"reason\":\"No matching import in this range\"}",
        "The named import was not found in the queried range.", &task, 2));
    assert(task.steps[0].status == "done");

    task.state = "running";
    task.steps[0].status = "running";
    assert(ApplyTaskCheck("{\"step\":1,\"status\":\"verified\",\"evidence\":[9],\"reason\":\"bad evidence\"}",
        "", &task, 2));
    assert(task.steps[0].status == "verifying" && task.steps[0].retries == 0);

    AgentTask launch;
    launch.steps.push_back(AgentTaskStep());
    launch.steps[0].kind = "mutation";
    launch.steps[0].criterion = "debug_open_process loaded the requested executable";
    AgentTaskOperation operation;
    operation.step = 0;
    operation.tool = "debug_open_process";
    operation.state = "completed";
    operation.arguments = "{\"path\":\"D:\\\\tools\\\\procexp64.exe\"}";
    launch.operations.push_back(operation);
    launch.evidence.push_back(evidence);
    AgentTaskEvidence context = evidence;
    context.tool = "get_debug_context";
    context.result = "{\"result\":{\"process_id\":123,\"session\":\"current\",\"modules\":[{\"path\":\"D:\\\\tools\\\\procexp64.exe\"}]}}";
    launch.evidence.push_back(context);
    assert(ApplyTaskCheck("{\"step\":1,\"status\":\"verified\",\"evidence\":[1,2],\"reason\":\"Loaded\"}",
        "The requested process is loaded.", &launch, 2));
    assert(launch.steps[0].status == "done");

    task.state = "blocked";
    task.steps[0].status = "blocked";
    task.steps[0].failure = "verification";
    task.steps[0].reason = "Verifier supplied evidence that does not satisfy the current criterion.";
    assert(PrepareInvalidVerifierContinuation(&task));
    assert(task.state == "verifying" && task.steps[0].status == "verifying");

    task.state = "blocked";
    task.steps[0].status = "blocked";
    task.steps[0].failure = "verification";
    task.steps[0].reason = "Authorization required";
    task.last_feedback.clear();
    assert(!PrepareInvalidVerifierContinuation(&task));
    AgentTaskEvidence failed_read = evidence;
    failed_read.tool = "read_memory";
    failed_read.result = "{\"error\":{\"code\":-32005}}";
    failed_read.success = false;
    task.evidence.push_back(failed_read);
    assert(PrepareInvalidVerifierContinuation(&task));
    task.state = "blocked";
    task.steps[0].status = "blocked";
    AgentTaskEvidence failed_open = failed_read;
    failed_open.tool = "debug_open_process";
    failed_open.read_only = false;
    task.evidence.push_back(failed_open);
    assert(!PrepareInvalidVerifierContinuation(&task));
    assert(PrepareInvalidVerifierContinuation(&task, true));
    assert(task.recovering && task.steps[0].status == "verifying");
    puts("PASS: negative lookup evidence and recoverable verification blocks");
    return 0;
}
