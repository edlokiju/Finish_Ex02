#pragma once
class Debugger_detect
{
public:
	bool Check_Debugger();
	
private:
	bool NtQueryInformationProcess_ProcessDebugFlags();
	bool NtQueryInformationProcess_ProcessDebugObject();
	bool NtQueryInformationProcess_ProcessDebugPort();
	bool NtQuerySystemInformation_SystemKernelDebuggerInformation();
	bool Check_Hardware_Breakpoint();
	bool Check_IsDebuggerPresentPEB();
	bool Check_Interrupt_0x2d();
	bool IsbeingDebug();
	bool Check_Remote_Debugger_Present_API();
	bool IsDebuggerPresentAPI();
};

