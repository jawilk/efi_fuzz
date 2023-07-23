#include "CallGraph.h"
#include <Library/PrintLib.h>

BOOLEAN IsAfterExitBootServices()
{
    UINTN is_after;
    UINTN Size = sizeof(is_after);
    gRT->GetVariable(
        L"FatIsExitBootService",
        &gFatCallGraph,
        NULL,
        &Size,
        &is_after);

    return is_after;
}

UINTN GetFunctionCallCount(const char *func_name)
{
    CHAR16 funcNameUnicode[25];
    AsciiStrToUnicodeStrS(func_name, funcNameUnicode, 25);
    UINTN call_count = 0;
    UINTN Size = sizeof(call_count);
    gRT->GetVariable(
        funcNameUnicode,
        &gFatCallGraph,
        NULL,
        &Size,
        &call_count);
    call_count++;
    gRT->SetVariable(
        funcNameUnicode,
        &gFatCallGraph,
        (EFI_VARIABLE_NON_VOLATILE |
         EFI_VARIABLE_BOOTSERVICE_ACCESS |
         EFI_VARIABLE_RUNTIME_ACCESS),
        Size,
        &call_count);

    return call_count;
}

VOID WriteNvramVar(CHAR16 *input, const char *func_name)
{
    CHAR16 id[50];
    CHAR16 funcNameUnicode[25];
    UINTN is_after = IsAfterExitBootServices();
    UINTN CallCount = GetFunctionCallCount(func_name);
    AsciiStrToUnicodeStrS(func_name, funcNameUnicode, 25);
    UnicodeSPrint(id, sizeof(id), L"FatVar-%s-%d-%d", funcNameUnicode, CallCount, is_after);

    UINTN Size = StrLen(input) * sizeof(CHAR16);
    gRT->SetVariable(
        id,
        &gFatCallGraph,
        (EFI_VARIABLE_NON_VOLATILE |
         EFI_VARIABLE_BOOTSERVICE_ACCESS |
         EFI_VARIABLE_RUNTIME_ACCESS),
        Size,
        input);
}