#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <tchar.h>
#include <psapi.h>
#define ARRAY_SIZE 1024
#define MAX_UNICODE_PATH	32767L

typedef NTSTATUS(NTAPI* _NtQueryInformationProcess)(
	HANDLE ProcessHandle,
	DWORD ProcessInformationClass,
	PVOID ProcessInformation,
	DWORD ProcessInformationLength,
	PDWORD ReturnLength
	);
// Used in PEB struct

PVOID GetPebAddress(HANDLE ProcessHandle)
{
	_NtQueryInformationProcess NtQueryInformationProcess =
		(_NtQueryInformationProcess)GetProcAddress(
			GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
	PROCESS_BASIC_INFORMATION pbi;

	NtQueryInformationProcess(ProcessHandle, 0, &pbi, sizeof(pbi), NULL);

	return pbi.PebBaseAddress;
}
int ListDrivers(void)
{
    LPVOID drivers[ARRAY_SIZE];
    DWORD cbNeeded;
    int cDrivers, i;

    if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded) && cbNeeded < sizeof(drivers))
    {
        TCHAR szDriver[ARRAY_SIZE];

        cDrivers = cbNeeded / sizeof(drivers[0]);

        _tprintf(TEXT("co %d drivers:\n"), cDrivers);
        for (i = 0; i < cDrivers; i++)
        {
            if (GetDeviceDriverBaseName(drivers[i], szDriver, sizeof(szDriver) / sizeof(szDriver[0])))
            {
                _tprintf(TEXT("%d: %s\n"), i + 1, szDriver);
            }
        }
    }
    else
    {
      
        return 1;
    }

    return 0;
}

void PrintProcessNameAndID(DWORD processID)
{
    TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");
	PVOID pebAddress;
	PVOID rtlUserProcParamsAddress;
	UNICODE_STRING commandLine;
	WCHAR* commandLineContents;
    // lay handle process.

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
        PROCESS_VM_READ,
        FALSE, processID);

    // lay ten process.

    if (NULL != hProcess)
    {
        HMODULE hMod;
        DWORD cbNeeded;

        if (EnumProcessModules(hProcess, &hMod, sizeof(hMod),
            &cbNeeded))
        {
            printf("Command line: ");
            GetModuleBaseName(hProcess, hMod, szProcessName,
                sizeof(szProcessName) / sizeof(TCHAR));
			pebAddress = GetPebAddress(hProcess);
			if (!ReadProcessMemory(hProcess,
                (PCHAR)pebAddress + 0x10,
				&rtlUserProcParamsAddress,
				sizeof(PVOID), NULL))
			{
				printf("Khong doc duoc dia chi ProcessParameters!\n");
				return GetLastError();
			}

			/* cau truc CommandLine UNICODE_STRING  */
			if (!ReadProcessMemory(hProcess,
                (PCHAR)rtlUserProcParamsAddress + 0x40,
				&commandLine, sizeof(commandLine), NULL))
			{
				printf("Khong doc duoc CommandLine!\n");
				return GetLastError();
			}

			commandLineContents = (WCHAR*)malloc(commandLine.Length);

			/*doc command line */
			if (!ReadProcessMemory(hProcess, commandLine.Buffer,
				commandLineContents, commandLine.Length, NULL))
			{
				printf("Khong doc duoc CommandLine\n");
				return GetLastError();
			}

			/* commandLine.Length la bytes */
			/* 1 WCHAR 2 byte*/
			printf("%.*S\n", commandLine.Length / 2, commandLineContents);
			free(commandLineContents);

        }


    }

    // in ten va id.

    _tprintf(TEXT("Process Name: %s  (PID: %u)\n"), szProcessName, processID);



    CloseHandle(hProcess);
}
int PrintModules(DWORD processID)
{
    HMODULE hMods[1024];
    HANDLE hProcess;
    DWORD cbNeeded;
    unsigned int i;

    printf("\nMore Information: \n");

    // lay handle process.

    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
        PROCESS_VM_READ,
        FALSE, processID);
    if (NULL == hProcess)
        return 1;

    // lay list modules cua process.

    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
    {
        for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
        {
            TCHAR szModName[MAX_PATH];

            // lay full path file

            if (GetModuleFileNameEx(hProcess, hMods[i], szModName,
                sizeof(szModName) / sizeof(TCHAR)))
            {
               

                _tprintf(TEXT("- %s (0x%08X)\n"), szModName, hMods[i]);
            }
        }
    }


    CloseHandle(hProcess);

    return 0;
}

int main(void)
{
    DWORD aProcesses[1024], cbNeeded, cProcesses;
    unsigned int i;
    if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
    {
        return 1;
    }

    cProcesses = cbNeeded / sizeof(DWORD);

    for (i = 0; i < cProcesses; i++)
    {
        if (aProcesses[i] != 0)
        {
            printf("\nProcess ID: %u\n", aProcesses[i]);
            PrintProcessNameAndID(aProcesses[i]);           
            PrintModules(aProcesses[i]);
            printf("==========================================\n");
        }
    }
    return 0;
}