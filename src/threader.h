#pragma once

#ifndef __THREADER_H
#define __THREADER_H

#include "includes.h"
#include "config.h"
#include "hijacker.h"

class Threader : public Interceptor {
private:
	THREADENTRY32 m_threadEntry32;
	HANDLE m_hThreader;
	bool m_isThreadFound;

public:
	DWORD FindThreadWithinWin32Process(DWORD m_threaderProcessId);

};

#endif 