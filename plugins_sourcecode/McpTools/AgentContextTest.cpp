#include "AgentContext.h"
#include <assert.h>
#include <stdio.h>

int main()
{
    ModelJson json;
    std::string summary;
    assert(ModelJson::parse("{\"observations\":\"static_disassemble @0x4563EF: TEST EDI,80h\","
        "\"inferences\":\"possible color branch\",\"pending\":\"reread branch\"}", &json));
    assert(ContextReadStructuredSummary(json, 4096, &summary));
    assert(summary.find("Observed tool results") != std::string::npos);
    assert(summary.find("Model inferences (unverified)") != std::string::npos);
    assert(!ContextReadStructuredSummary(json, 16, &summary));
    assert(ModelJson::parse("{\"summary\":\"unlabeled conclusion\"}", &json));
    assert(!ContextReadStructuredSummary(json, 4096, &summary));

    std::string conflict;
    assert(ContextImpossibleMaskComparison("```c\nif ((seglen & 0xF) > 0x14) draw();\n```", &conflict));
    assert(ContextImpossibleMaskComparison("```c\nif (flags & 0x7) == 0x8) draw();\n```", &conflict));
    assert(!ContextImpossibleMaskComparison("```c\nif ((seglen & 0xF) > 0xA) draw();\n```", &conflict));
    assert(!ContextImpossibleMaskComparison("The expression (x & 0xF) > 0x14 is impossible.", &conflict));
    std::vector<std::string> history;
    history.push_back(ContextSummaryMessage("Model inferences (unverified): possible branch"));
    assert(ContextRequiresStaticRead(true, history, false));
    assert(!ContextRequiresStaticRead(true, history, true));
    assert(!ContextRequiresStaticRead(false, history, false));
    std::vector<std::string> addresses;
    addresses.push_back("0x4563EF");
    assert(ContextCitesStaticAddress("branch at 0x4563ef", addresses));
    assert(!ContextCitesStaticAddress("branch at 0x456580", addresses));
    std::string verified = ContextVerifiedLabel();
    std::string inferred = ContextInferenceLabel();
    assert(ContextEvidenceStatusValid("## " + verified + "\n- TEST at 0x4563EF\n## " +
        inferred + "\n- callback identity is conjecture", addresses));
    assert(!ContextEvidenceStatusValid("## " + verified + "\n- TEST instruction\n## " +
        inferred + "\n- callback identity is conjecture", addresses));
    assert(!ContextEvidenceStatusValid("## " + verified + "\n- TEST at 0x456580\n## " +
        inferred + "\n- callback identity is conjecture", addresses));
    assert(!ContextEvidenceStatusValid("## " + verified + "\n- TEST at 0x4563EF", addresses));
    assert(ContextEvidenceStatusValid(verified + ": \xE6\x97\xA0\n" + inferred +
        "\n- callback identity is conjecture", addresses));
    assert(!ContextEvidenceStatusValid(verified + ": \xE6\x97\xA0\xE6\xB3\x95\xE7\xA1\xAE\xE8\xAE\xA4\n" +
        inferred + "\n- callback identity is conjecture", addresses));
    puts("PASS: structured memory and impossible masked comparison checks");
    return 0;
}
