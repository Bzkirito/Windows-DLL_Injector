/*
* DLL Injector and Uninjiector
* Written by LloydHuang (@LloydHuang)
*/

#include <stdio.h>
#include <Windows.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <wchar.h>
#include <map>
#include <string>

//  Forward declarations
HANDLE findProcess(WCHAR* processName);
BOOL loadRemoteDLL(HANDLE hProcess, const char* dllPath);
void printError(TCHAR* msg);
void listProcess();
void listProcessModule(HANDLE hProcess);
BOOL freeRemoteDLL(HANDLE hProcess, const WCHAR* dllName);

std::map<std::wstring, DWORD> procMap;

int wmain() 
{
	char dllName[MAX_PATH];
	WCHAR unloadDll[MAX_PATH];
	wchar_t procName[MAX_PATH];
	int select;
	HANDLE hProcess = NULL;
	//wcstombs(dllPath, argv[2], MAX_PATH);
	while (1)
	{
		_tprintf_s(L"****************************************************************\n");
		printf_s("*[1]¡¢DLL injector\n");
		printf_s("*[2]¡¢DLL Uninjector\n");
		printf_s("*[3]¡¢Exit\n");
		printf_s("****************************************************************\n");
		_tscanf_s(L"%d", &select);
		switch (select)
		{
		case 1:
			_tprintf_s(L"[*]Please Enter the Dll Path\n");
			scanf_s("%s", dllName, MAX_PATH);
			getchar();

			listProcess();
			_tprintf_s(L"[*]Please Enter the process name which you want to inject\n");
			wscanf_s(L"%s", procName, MAX_PATH);
			hProcess = findProcess(procName);
			// wprint to print WCHAR strings
			wprintf_s(L"[*]Victim process name	: %s\n", procName);
			printf_s("[*]DLL to inject		: %s\n", dllName);


			if (hProcess != NULL)
			{
				BOOL injectSuccessful = loadRemoteDLL(hProcess, dllName);
				if (injectSuccessful)
				{
					printf("[+] DLL injection successful! \n");
				}
				else
				{
					printf("[---] DLL injection failed. \n");
				}
			}
			break;
		case 2:
			listProcess();
			_tprintf_s(L"[*]Please Enter the process name which you want to inject\n");
			wscanf_s(L"%s", procName, MAX_PATH);
			hProcess = findProcess(procName);
			listProcessModule(hProcess);
			_tprintf_s(L"[*]Enter the Dll Name which you want to unload\n");
			_tscanf_s(L"%s", unloadDll, MAX_PATH);

			wprintf_s(L"[*]Victim process name	: %s\n", procName);
			wprintf_s(L"[*]DLL to Uninject		: %s\n", unloadDll);

			if (freeRemoteDLL(hProcess, unloadDll))
			{
				_tprintf_s(L"[+] Dll: %s  unload sucessful!\n", unloadDll);
			}
			else
			{
				_tprintf_s(L"[-------] Dll: %s unload faild\n", unloadDll);
			}
			
			break;
		case 3:
			_tprintf_s(L"Thank you for your use!\n");
			goto SIG;
			break;
		default:
			break;
		}
		
		_flushall();
		_tprintf_s(L"[R]Enter any key to continue\n");
		getchar();
		system("cls");
	}


SIG:
	return 0;
}

HANDLE findProcess(WCHAR* processName) 
{
	HANDLE hProcess;
	DWORD dwProcessId;

	if (procMap.end() != procMap.find(processName))
	{
		dwProcessId = procMap[processName];
	}
	else
	{
		wprintf(L"[---] %s has not been loaded into memory, aborting.\n", processName);
		return NULL;
	}

	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
	if (hProcess == NULL)
	{
		wprintf(L"[---] Failed to open process %s.\n", processName);
		return NULL;
	}

	return hProcess;
}

/* Load DLL into remote process
* Gets LoadLibraryA address from current process, which is guaranteed to be same for single boot session across processes
* Allocated memory in remote process for DLL path name
* CreateRemoteThread to run LoadLibraryA in remote process. Address of DLL path in remote memory as argument
*/
BOOL loadRemoteDLL(HANDLE hProcess, const char* dllPath) 
{
	BOOL bRet = TRUE;
	BOOL succeededWriting;
	LPVOID loadLibraryAddress;
	HANDLE remoteThread = NULL;
	HMODULE kernel32Dll = NULL;

	_flushall();
	printf("Enter any key to attempt DLL injection.");
	getchar();
	getchar();

	// Allocate memory for DLL's path name to remote process
	LPVOID dllPathAddressInRemoteMemory = VirtualAllocEx(hProcess, NULL, strlen(dllPath), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (dllPathAddressInRemoteMemory == NULL) 
	{
		printf("[---] VirtualAllocEx unsuccessful.\n");
		printError((TCHAR*)TEXT("VirtualAllocEx"));
		getchar();
		bRet = FALSE;
		goto SIGLOAD;
	}

	// Write DLL's path name to remote process
	succeededWriting = WriteProcessMemory(hProcess, dllPathAddressInRemoteMemory, dllPath, strlen(dllPath), NULL);

	if (!succeededWriting) 
	{
		printf("[---] WriteProcessMemory unsuccessful.\n");
		printError((TCHAR*)TEXT("WriteProcessMemory"));
		getchar();
		bRet = FALSE;
		goto SIGLOAD;
	}

	// Returns a pointer to the LoadLibrary address. This will be the same on the remote process as in our current process.
	kernel32Dll = GetModuleHandle(L"kernel32.dll");
	if(kernel32Dll == NULL || kernel32Dll == INVALID_HANDLE_VALUE)
	{
		bRet = FALSE;
		goto SIGLOAD;
	}

	loadLibraryAddress = (LPVOID)GetProcAddress(kernel32Dll, "LoadLibraryA");
	if (loadLibraryAddress == NULL) 
	{
		printf("[---] LoadLibrary not found in process.\n");
		printError((TCHAR*)TEXT("GetProcAddress"));
		getchar();
		bRet = FALSE;
		goto SIGLOAD;
	}

	remoteThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)loadLibraryAddress, dllPathAddressInRemoteMemory, NULL, NULL);
	if (remoteThread == NULL) 
	{
		printf("[---] CreateRemoteThread unsuccessful.\n");
		printError((TCHAR*)TEXT("CreateRemoteThread"));
		bRet = FALSE;
		goto SIGLOAD;
	}
	WaitForSingleObject(remoteThread, INFINITE);

	

SIGLOAD:
	if (hProcess != NULL && hProcess != INVALID_HANDLE_VALUE)
	{
		CloseHandle(hProcess);
	}
	if (remoteThread != NULL && remoteThread != INVALID_HANDLE_VALUE)
	{
		CloseHandle(remoteThread);
	}
	return TRUE;
}

/* Prints error message
* Taken from https://msdn.microsoft.com/en-us/library/windows/desktop/ms686701(v=vs.85).aspx
*/
void printError(TCHAR* msg) 
{
	DWORD eNum;
	TCHAR sysMsg[256];
	TCHAR* p;

	eNum = GetLastError();
	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, eNum,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
		sysMsg, 256, NULL);

	// Trim the end of the line and terminate it with a null
	p = sysMsg;
	while ((*p > 31) || (*p == 9))
		++p;
	do { *p-- = 0; } while ((p >= sysMsg) &&
		((*p == '.') || (*p < 33)));

	// Display the message
	_tprintf_s(L"[---] %s failed with error %d (%s) \n", msg, eNum, sysMsg);
}

/* Look for the process in memory or refresh the process map
* Walks through snapshot of processes in memory, compares with command line argument
* Modified from https://msdn.microsoft.com/en-us/library/windows/desktop/ms686701(v=vs.85).aspx
*/
void listProcess()
{
	int order = 1;
	PROCESSENTRY32 pe32;
	HANDLE processSnapshot = INVALID_HANDLE_VALUE;
	processSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	pe32.dwSize = sizeof(PROCESSENTRY32);
	if(!Process32First(processSnapshot,&pe32))
	{
		_tprintf_s(L"Create Process Snapshot failed\n");
		return;
	}

	do
	{
		_tprintf_s(L"*[%d]:  %s\n", order++, pe32.szExeFile);
		std::wstring strExeFile = pe32.szExeFile;
		if(procMap.find(strExeFile) == procMap.end())
		{
			procMap.insert(std::pair<std::wstring, DWORD>(strExeFile, pe32.th32ProcessID));
		}
		else
		{
			procMap[strExeFile] = pe32.th32ProcessID;
		}
	} while (Process32Next(processSnapshot, &pe32));
}

void listProcessModule(HANDLE hProcess)
{
	MODULEENTRY32 me32 = { 0 };
	DWORD dwProcessId = GetProcessId(hProcess);
	HANDLE moduleSnapshot;

	moduleSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwProcessId);
	me32.dwSize = sizeof(MODULEENTRY32);
	
	if (!Module32First(moduleSnapshot, &me32))
	{
		_tprintf_s(L"Create Process Snapshot failed\n");
		return;
	}
	
	do
	{
		_tprintf_s(L"%s\n", me32.szModule);
	} while (Module32Next(moduleSnapshot, &me32));
}

BOOL freeRemoteDLL(HANDLE hProcess, const WCHAR* dllName)
{
	LPVOID dllPathAddressInRemoteMemory;
	LPTHREAD_START_ROUTINE freeLibraryAddress;
	MODULEENTRY32 me32 = { 0 };
	DWORD dwProcessId;
	HANDLE moduleSnapshot = NULL;
	HANDLE hRemoteThread = NULL;
	HMODULE kernel32Dll = NULL;
	BOOL bFound = FALSE;
	BOOL bRet = TRUE;

	_flushall();
	printf("Enter any key to attempt DLL Uninjection.");
	getchar();
	getchar();

	dwProcessId = GetProcessId(hProcess);
	if (dwProcessId == 0)
	{
		_tprintf_s(L"Process ID Error\n");
		bRet = FALSE;
		goto SIGFREE;
	}
	moduleSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwProcessId);
	me32.dwSize = sizeof(MODULEENTRY32);

	if (!Module32First(moduleSnapshot, &me32))
	{
		_tprintf_s(L"Create Process Snapshot failed\n");
		bRet = FALSE;
		goto SIGFREE;
	}

	do
	{
		if (!_tcsicmp(dllName, me32.szModule))
		{
			bFound = TRUE;
			break;
		}
	} while (Module32Next(moduleSnapshot, &me32));

	if (!bFound)
	{
		_tprintf_s(L"Dll not found!\n");
		return FALSE;
	}

	dllPathAddressInRemoteMemory = VirtualAllocEx(hProcess, NULL, sizeof(me32.modBaseAddr) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	kernel32Dll = GetModuleHandle(L"kernel32.dll");
	if (kernel32Dll == NULL || kernel32Dll == INVALID_HANDLE_VALUE)
	{
		_tprintf(L"\n");
		bRet = FALSE;
		goto SIGFREE;
	}
	freeLibraryAddress = (LPTHREAD_START_ROUTINE)GetProcAddress(kernel32Dll, "FreeLibrary");

	hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, freeLibraryAddress, me32.modBaseAddr,0,NULL);
	if (hRemoteThread == NULL || hRemoteThread == INVALID_HANDLE_VALUE)
	{
		_tprintf_s(L"Remote Thread Create failed\n");
		bRet = FALSE;
		goto SIGFREE;
	}
	WaitForSingleObject(hRemoteThread, INFINITE);

SIGFREE:
	if (hProcess != NULL && hProcess != INVALID_HANDLE_VALUE)
	{
		CloseHandle(hProcess);
	}
	if (hRemoteThread != NULL && hRemoteThread != INVALID_HANDLE_VALUE)
	{
		CloseHandle(hRemoteThread);
	}
	return bRet;
}