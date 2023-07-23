#ifndef _CALLGRAPH_H_
#define _CALLGRAPH_H_

#include "Fat.h"

// typedef struct FuncMeta
// {
//     BOOLEAN IsAfterExitBootServices;
//     UINTN CallCount;
//     CHAR16 *Input;
// } FuncMeta;

BOOLEAN IsAfterExitBootServices();
UINTN GetFunctionCallCount(IN const char *func_name);
VOID WriteNvramVar(IN CHAR16 *input, IN const char *id);

#endif