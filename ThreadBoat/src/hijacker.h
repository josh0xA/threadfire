#pragma once

#ifndef __HIJACKER_H
#define __HIJACKER_H

#include "config.h" 

#define SHELLCODE_BASE_SIZE 0x1000

class System {

protected:
	DBG_STATE_BOUND dbgStatus;

private:
	TOKEN_PRIVILEGES m_localTokenPrivs;
	HANDLE m_hToken;
	OSVERSIONINFO m_systemVersionInfo;
	
/* PUBLIC MEMBER FUNCTIONS */
public:
	PCHAR returnVersionState();
	void setTokenPrivileges();
	DBG_STATE_BOUND returnPrivilegeEscalationState();
};

class Interceptor : public System {
/* PRIVATE MEMBER VARIABLES */
private:
	THREADENTRY32 m_threadEntry32;
	BOOL m_bThreadFound32 = false;

	LPCONTEXT m_lpContext;
/* PUBLIC MEMBER FUNCTIONS */
public:
	DWORD FindWin32ProcessId(char* m_win32ProcesName);
	DBG_STATE_BOUND ExecuteWin32Shellcode(DWORD m_processId);

};

typedef struct _SHELLCODE_INFO {

	DWORD dwSize;
	LPVOID m_lpShellcode;
	LPVOID m_lpCreateThreadAddr;
	// adding more shit...
} SHELLCODE_INFO, *PSHELLCODE_INFO;




#endif 
