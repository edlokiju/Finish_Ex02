#include "Debugger_detect.h"
#include <Windows.h>
#include <winternl.h>
#include <ntstatus.h>

typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    DWORD ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
    );

static BOOL SwallowedException = TRUE;

bool Debugger_detect::Check_Debugger()
{
    if (NtQueryInformationProcess_ProcessDebugFlags() ||
        NtQueryInformationProcess_ProcessDebugObject() ||
        NtQueryInformationProcess_ProcessDebugPort() ||
        NtQuerySystemInformation_SystemKernelDebuggerInformation() ||
        Check_Hardware_Breakpoint() ||
        Check_IsDebuggerPresentPEB() ||
        Check_Interrupt_0x2d() ||
        IsbeingDebug() ||
        Check_Remote_Debugger_Present_API()||
        IsDebuggerPresentAPI())
        return true;
    return false;
}

bool Debugger_detect::NtQueryInformationProcess_ProcessDebugFlags()
{
    const int ProcessDebugFlags = 0x1f;

    // Obtain the address of NtQueryInformationProcess
    auto NtQueryInfoProcess = reinterpret_cast<pNtQueryInformationProcess>(
        GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryInformationProcess")
        );

    // Other Vars
    NTSTATUS Status;
    DWORD NoDebugInherit = 0;

    // Call NtQueryInformationProcess
    Status = NtQueryInfoProcess(GetCurrentProcess(), ProcessDebugFlags, &NoDebugInherit, sizeof(DWORD), NULL);

    // Check the result
    if (Status == 0x00000000 && NoDebugInherit == 0)
        return true;
    else
        return false;
}

bool Debugger_detect::NtQueryInformationProcess_ProcessDebugObject()
{
    const int ProcessDebugObjectHandle = 0x1e;

    auto NtQueryInfoProcess = reinterpret_cast<pNtQueryInformationProcess>(
        GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryInformationProcess")
        );

    NTSTATUS Status;
    HANDLE hDebugObject = NULL;

//#if defined (ENV64BIT)
//    ULONG_PTR dProcessInformationLength = sizeof(ULONG_PTR) * 2;
//    DWORD64 IsRemotePresent = 0;
//
//#elif defined(ENV32BIT)
//    ULONG_PTR dProcessInformationLength = sizeof(ULONG_PTR);
//    DWORD32 IsRemotePresent = 0;
//#endif

    ULONG_PTR dProcessInformationLength = sizeof(ULONG_PTR);
    DWORD32 IsRemotePresent = 0;

    // Regular check
    Status = NtQueryInfoProcess(GetCurrentProcess(), ProcessDebugObjectHandle, &hDebugObject, sizeof(HANDLE), NULL);
    if (Status != STATUS_PORT_NOT_SET)
        return true;
    if (hDebugObject != NULL)
        return true;

    // Check with overlapping return length and debug object handle buffers to find anti-anti-debuggers
    Status = NtQueryInfoProcess(GetCurrentProcess(), ProcessDebugObjectHandle, &hDebugObject, sizeof(HANDLE), (PULONG)&hDebugObject);
    if (Status != STATUS_PORT_NOT_SET)
        return true;
    if (hDebugObject == NULL)
        return true; // Handle incorrectly zeroed
    if ((ULONG_PTR)hDebugObject != dProcessInformationLength)
        return true; // Return length incorrectly overwritten

    return false;
}

bool Debugger_detect::NtQueryInformationProcess_ProcessDebugPort()
{
    typedef NTSTATUS(NTAPI* TNtQueryInformationProcess)(
        IN HANDLE           ProcessHandle,
        IN PROCESSINFOCLASS ProcessInformationClass,
        OUT PVOID           ProcessInformation,
        IN ULONG            ProcessInformationLength,
        OUT PULONG          ReturnLength
        );

    HMODULE hNtdll = LoadLibraryA("ntdll.dll");
    if (hNtdll)
    {
        auto pfnNtQueryInformationProcess = (TNtQueryInformationProcess)GetProcAddress(
            hNtdll, "NtQueryInformationProcess");

        if (pfnNtQueryInformationProcess)
        {
            DWORD dwProcessDebugPort, dwReturned;
            NTSTATUS status = pfnNtQueryInformationProcess(
                GetCurrentProcess(),
                ProcessDebugPort,
                &dwProcessDebugPort,
                sizeof(DWORD),
                &dwReturned);

            if (NT_SUCCESS(status) && (-1 == dwProcessDebugPort))
                return true;
        }
    }
    return false;
}

bool Debugger_detect::NtQuerySystemInformation_SystemKernelDebuggerInformation()
{
    enum { SystemKernelDebuggerInformation = 0x23 };

    typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION {
        BOOLEAN DebuggerEnabled;
        BOOLEAN DebuggerNotPresent;
    } SYSTEM_KERNEL_DEBUGGER_INFORMATION, * PSYSTEM_KERNEL_DEBUGGER_INFORMATION;

  
        NTSTATUS status;
        SYSTEM_KERNEL_DEBUGGER_INFORMATION SystemInfo;

        status = NtQuerySystemInformation(
            (SYSTEM_INFORMATION_CLASS)SystemKernelDebuggerInformation,
            &SystemInfo,
            sizeof(SystemInfo),
            NULL);

        return SUCCEEDED(status)
            ? (SystemInfo.DebuggerEnabled && !SystemInfo.DebuggerNotPresent)
            : false;

}

bool Debugger_detect::Check_Hardware_Breakpoint()
{
    BOOL bResult = FALSE;

    // This structure is key to the function and is the 
    // medium for detection and removal
    PCONTEXT ctx = PCONTEXT(VirtualAlloc(NULL, sizeof(CONTEXT), MEM_COMMIT, PAGE_READWRITE));

    if (ctx) {

        SecureZeroMemory(ctx, sizeof(CONTEXT));

        // The CONTEXT structure is an in/out parameter therefore we have
        // to set the flags so Get/SetThreadContext knows what to set or get.
        ctx->ContextFlags = CONTEXT_DEBUG_REGISTERS;

        // Get the registers
        if (GetThreadContext(GetCurrentThread(), ctx)) {

            // Now we can check for hardware breakpoints, its not 
            // necessary to check Dr6 and Dr7, however feel free to
            if (ctx->Dr0 != 0 || ctx->Dr1 != 0 || ctx->Dr2 != 0 || ctx->Dr3 != 0)
                bResult = TRUE;
        }

        VirtualFree(ctx, 0, MEM_RELEASE);
    }

    return bResult;
}

bool Debugger_detect::Check_IsDebuggerPresentPEB()
{
    /*++
Routine Description:
    Checks if the BeingDebugged flag is set in the Process Environment Block (PEB).
    This is effectively the same code that IsDebuggerPresent() executes internally.
    The PEB pointer is fetched from DWORD FS:[0x30] on x86_32 and QWORD GS:[0x60] on x86_64.
Arguments:
    None
Return Value:
    TRUE - if debugger was detected
    FALSE - otherwise
--*/
    typedef struct _PEB {
        BYTE                          Reserved1[2];
        BYTE                          BeingDebugged;
        BYTE                          Reserved2[1];
        PVOID                         Reserved3[2];
        PPEB_LDR_DATA                 Ldr;
        PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
        PVOID                         Reserved4[3];
        PVOID                         AtlThunkSListPtr;
        PVOID                         Reserved5;
        ULONG                         Reserved6;
        PVOID                         Reserved7;
        ULONG                         Reserved8;
        ULONG                         AtlThunkSListPtr32;
        PVOID                         Reserved9[45];
        BYTE                          Reserved10[96];
        PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
        BYTE                          Reserved11[128];
        PVOID                         Reserved12[1];
        ULONG                         SessionId;
    } PEB, * PPEB;

//#if defined (ENV64BIT)
//    _PEB pPeb = (PPEB)__readgsqword(0x60);
//
//#elif defined(ENV32BIT)
//    _PEB pPeb = (PPEB)__readfsdword(0x30);
//
//#endif
    /*_PEB *pPeb = (PPEB)__readfsdword(0x30);*/
    
    /*
    * if run file in 64 bit you can run comment code.
    */

    _PEB* pPeb = (PPEB)__readfsdword(0x30);
        return pPeb->BeingDebugged == 1;
}

static LONG CALLBACK VectoredHandler(
    _In_ PEXCEPTION_POINTERS ExceptionInfo
)
{
    SwallowedException = FALSE;
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT)
    {
        //The Int 2D instruction already increased EIP/RIP so we don't do that (although it wouldnt hurt).
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

void int2D() {
    __asm {
        mov eax, 0
        ret
    }
}

bool Debugger_detect::Check_Interrupt_0x2d()
{
    PVOID Handle = AddVectoredExceptionHandler(1, VectoredHandler);
    SwallowedException = TRUE;
    int2D();
    RemoveVectoredExceptionHandler(Handle);
    return SwallowedException;
}

bool Debugger_detect::IsbeingDebug()
{
    PPEB pPeb = (PPEB)__readfsdword(0x30);


    return pPeb->BeingDebugged == 1;
}

bool Debugger_detect::Check_Remote_Debugger_Present_API()
{
    BOOL bIsDbgPresent = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &bIsDbgPresent);
    return bIsDbgPresent;
}

bool Debugger_detect::IsDebuggerPresentAPI()
{
    return IsDebuggerPresent();
}

