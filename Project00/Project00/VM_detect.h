#pragma once
#include "VM_detect.h"
#include <tchar.h>
#include<Windows.h>
#include <fstream>
#include <Iphlpapi.h>
#include <Shlwapi.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "shlwapi.lib")

class VM_detect
{
public:
	bool Check_VM();
	DWORD GetProcessIdFromName(LPCTSTR szProcessName);
	bool check_mac_addr(const TCHAR* szMac);
private:
	bool Check_Vmware_process();
	bool Check_VMware_devices();
	bool Check_VMware_files();
	bool CheckRegistryKey();
	bool Check_VMware_Mac();
	bool Check_TSC();
};

