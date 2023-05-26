#include "VM_detect.h"
#include <tchar.h>
#include<Windows.h>
#include <fstream>
#include <Iphlpapi.h>
#include <Shlwapi.h>
#include <TlHelp32.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "shlwapi.lib")





bool VM_detect::check_mac_addr(const TCHAR* szMac)
{
    bool bResult = false;
    PIP_ADAPTER_INFO pAdapterInfo = nullptr;
    PIP_ADAPTER_INFO pAdapterInfoPtr = nullptr;
    ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);

    pAdapterInfo = reinterpret_cast<PIP_ADAPTER_INFO>(malloc(ulOutBufLen));
    if (pAdapterInfo == nullptr)
    {
        return false;
    }

    DWORD dwResult = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen);

    if (dwResult == ERROR_BUFFER_OVERFLOW)
    {
        free(pAdapterInfo);
        pAdapterInfo = reinterpret_cast<PIP_ADAPTER_INFO>(malloc(ulOutBufLen));
        if (pAdapterInfo == nullptr)
        {
 
            return false;
        }

        dwResult = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen);
    }

    if (dwResult == ERROR_SUCCESS)
    {
        BYTE szMacMultiBytes[6];
        for (int i = 0; i < 6; i++)
        {
            szMacMultiBytes[i] = static_cast<BYTE>(szMac[i]);
        }

        pAdapterInfoPtr = pAdapterInfo;

        while (pAdapterInfoPtr)
        {
            if (pAdapterInfoPtr->AddressLength == 6 && memcmp(szMacMultiBytes, pAdapterInfoPtr->Address, 6) == 0)
            {
                bResult = true;
                break;
            }
            pAdapterInfoPtr = pAdapterInfoPtr->Next;
        }
    }

    free(pAdapterInfo);

    return bResult;
}

bool VM_detect::Check_Vmware_process()
{
    const TCHAR* szProcesses[] = {
        _T("vmtoolsd.exe"),
        _T("vmwaretray.exe"),
        _T("vmwareuser.exe"),
        _T("VGAuthService.exe"),
        _T("vmacthlp.exe"),
    };

    WORD iLength = sizeof(szProcesses) / sizeof(szProcesses[0]);
    for (int i = 0; i < iLength; i++)
    {
        if (GetProcessIdFromName(szProcesses[i]))
            return true;
            //print_results(TRUE, msg);
  
    }
    return false;
}

bool VM_detect::Check_VMware_devices()
{

        const TCHAR* devices[] = {
            _T("\\\\.\\HGFS"),
            _T("\\\\.\\vmci"),
        };

        WORD iLength = sizeof(devices) / sizeof(devices[0]);
        for (int i = 0; i < iLength; i++)
        {
            HANDLE hFile = CreateFile(devices[i], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            //TCHAR msg[256] = _T("");
            //_stprintf_s(msg, sizeof(msg) / sizeof(TCHAR), _T("Checking device %s "), devices[i]);

            if (hFile != INVALID_HANDLE_VALUE) {
                CloseHandle(hFile);
                return true;
            }
       
        }
        return false;
}

bool VM_detect::Check_VMware_files()
{
    WIN32_FIND_DATA FindFileData;
    HANDLE hFind;
    TCHAR szDir[MAX_PATH];

    // Lấy đường dẫn đến thư mục System32
    if (GetSystemDirectory(szDir, MAX_PATH) == 0)
    {
        return false;
    }

    // Thêm ký tự '\' vào cuối đường dẫn nếu cần thiết
    if (szDir[_tcslen(szDir) - 1] != '\\')
    {
        _tcscat_s(szDir, MAX_PATH, _T("\\"));
    }

    // Xây dựng mẫu tìm kiếm (vm*)
    TCHAR szPattern[MAX_PATH];
    _tcscpy_s(szPattern, MAX_PATH, szDir);
    _tcscat_s(szPattern, MAX_PATH, _T("vm*"));

    // Tìm kiếm các tệp tin phù hợp với mẫu
    hFind = FindFirstFile(szPattern, &FindFileData);
    if (hFind == INVALID_HANDLE_VALUE)
    {
        //std::cout << "No VM files found in System32 directory" << std::endl;
        return false;
    }

    bool hasVMFiles = false;

    do
    {
        // Kiểm tra nếu tệp tin không phải là thư mục và có tên chứa chuỗi "vm"
        if (!(FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
            _tcsstr(FindFileData.cFileName, _T("vm")) != nullptr)
        {
            //std::wcout << FindFileData.cFileName << std::endl;
            hasVMFiles = true;
        }
    } while (FindNextFile(hFind, &FindFileData) != 0);

    FindClose(hFind);

    return hasVMFiles;

}

bool VM_detect::CheckRegistryKey()
{

    HKEY hKey;
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, _T("SOFTWARE"), 0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS)
    {
        TCHAR szSubKey[MAX_PATH];
        DWORD dwIndex = 0;
        DWORD dwSize = MAX_PATH;
        while (RegEnumKeyEx(hKey, dwIndex, szSubKey, &dwSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS)
        {
            if (_tcsstr(szSubKey, _T("VMware")) != NULL)
            {
                RegCloseKey(hKey);
                return true;
            }
            dwIndex++;
            dwSize = MAX_PATH;
        }
        RegCloseKey(hKey);
    }
    return false;
}

bool VM_detect::Check_VMware_Mac()
{
    const TCHAR* szMac[][2] = {
        { _T("\x00\x05\x69"), _T("00:05:69") }, // VMWare, Inc.
        { _T("\x00\x0C\x29"), _T("00:0c:29") }, // VMWare, Inc.
        { _T("\x00\x1C\x14"), _T("00:1C:14") }, // VMWare, Inc.
        { _T("\x00\x50\x56"), _T("00:50:56") },	// VMWare, Inc.
    };

    WORD dwLength = sizeof(szMac) / sizeof(szMac[0]);

    for (int i = 0; i < dwLength; i++)
    {
        if (check_mac_addr(szMac[i][0]))
            return true;
    }
    return false;
}

bool VM_detect::Check_TSC()
{
        /*Every processor since pentium has a 64-bit register "Time Stamp Counter". 
        If the OS is being emulated the TSC will be much higher resulting in a detectable "flaw". 
        A non-virtualized OS has an average difference of 80-90 (but this value can be below as well) The return value on a virtualized OS will be a lot more higher than that value. (Usually above 500)
        */
    #if _WIN64 
            UINT64 time1 = rdtsc();
            UINT64 time2 = rdtsc();
            if (time2 - time1 > 500) {
                return 1;
            }
            return 0;
    #else 
            unsigned int time1 = 0;
            unsigned int time2 = 0;
            __asm
            {
                RDTSC
                MOV time1, EAX
                RDTSC
                MOV time2, EAX

            }
            if (time2 - time1 > 500) {
                return 1;
            }
            return 0;
    #endif
    }


bool VM_detect::Check_VM()
{
    if (this->CheckRegistryKey() ||
        this->Check_TSC() ||
        this->Check_VMware_devices() ||
        this->Check_VMware_files() ||
        this->Check_VMware_Mac() ||
        this->Check_Vmware_process()
        )
        return true;
    else
    return false;
}

DWORD VM_detect::GetProcessIdFromName(LPCTSTR szProcessName)
{
    PROCESSENTRY32 pe32;
    HANDLE hSnapshot = NULL;
    SecureZeroMemory(&pe32, sizeof(PROCESSENTRY32));

    // We want a snapshot of processes
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    // Check for a valid handle, in this case we need to check for
    // INVALID_HANDLE_VALUE instead of NULL
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        //print_last_error(_T("CreateToolhelp32Snapshot"));
        return 0;
    }

    // Now we can enumerate the running process, also 
    // we can't forget to set the PROCESSENTRY32.dwSize member
    // otherwise the following functions will fail
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe32) == FALSE)
    {
        // Cleanup the mess
        //print_last_error(_T("Process32First"));
        CloseHandle(hSnapshot);
        return 0;
    }

    while (Process32Next(hSnapshot, &pe32))
    {
        if (_tcsicmp(pe32.szExeFile, szProcessName) == 0)
        {
            CloseHandle(hSnapshot);
            return pe32.th32ProcessID;
        }
    }

    CloseHandle(hSnapshot);
    return 0;
}
