#include <windows.h>
#include <Macro.h>

UINT_PTR LdrModulePeb( UINT_PTR hModuleHash );
PVOID LdrFunctionAddr( UINT_PTR hModule, UINT_PTR ProcHash );