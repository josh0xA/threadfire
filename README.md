# ThreadBoat
Program uses Thread Hijacking to Inject Native Shellcode into a Standard Win32 Application

## About 
I developed this small project to continue my experiences of different code injection methods.
With Thread hijacking, it allows the hijacker.exe program to susepend a thread within the target.exe program
allowing us to write shellcode to that target thread, and later be executed (via; WriteProcessMemory(), SetThreadContext(), ResumeThread(), CreateThread()).

### Example GIF (Credits To Endgame)
![alt text](https://1.bp.blogspot.com/-pQCXPk6NBB8/XZU5iLWXOFI/AAAAAAAAQf4/2YjvCImtlqAqyhPKL6_ea1GnXJYNiSIwACNcBGAsYHQ/s640/ThreadBoat_1.gif)

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
## For Further Information On Thread Execution Hijacking 
#### Click On The Link Below
https://capec.mitre.org/data/definitions/30.html

## Environment
- Windows Vista+ 
- Visual C++
#### Libs
- Winapi
  - user32.dll
  - kernel32.dll

- ntdll.dll

## Ethical Notice
This code was simply written to demonstrate an overlooked method to inject shellcode or a DLL into a Win32 program. This code is not to be used for malicous purposes. The author, Josh Schiavone, is not liable for misuse of this software. May God bless you all.

