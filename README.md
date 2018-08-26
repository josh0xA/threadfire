# ThreadBoat
Program uses Thread Hijacking to Inject Native Shellcode into a Standard Win32 Application

## About 
I developed this small project to continue my experiences of different code injection methods.
With Thread Hijacking, it allows the hijacker.exe program to susepend a thread within the target.exe program
allowing us to write shellcode to a thread.

### Credits to Engame for Example GIF
![alt text](https://www.endgame.com/sites/default/files/threadexecution_.gif)

## Environment
- Windows Vista+ 
- Visual C++
#### Libs
- Winapi
  - user32.dll
  - kernel32.dll

- ntdll.dll
