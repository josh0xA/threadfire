# ThreadBoat
Program uses Thread Hijacking to Inject Native Shellcode into a Standard Win32 Application

## About 
I developed this small project to continue my experiences of different code injection methods.
With Thread Hijacking, it allows the hijacker.exe program to susepend a thread within the target.exe program
allowing us to write shellcode to a thread.

### Credits to Engame for Example GIF
![alt text](https://www.endgame.com/sites/default/files/threadexecution_.gif)

## Usage
```cpp
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
```

## Environment
- Windows Vista+ 
- Visual C++
#### Libs
- Winapi
  - user32.dll
  - kernel32.dll

- ntdll.dll
