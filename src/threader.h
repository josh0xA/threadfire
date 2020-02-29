/* Copyright (C) 2020 Josh Schiavone - All Rights Reserved
 * You may use, distribute and modify this code under the
 * terms of the MIT license, which unfortunately won't be
 * written for another century.
 *
 * You should have received a copy of the MIT license with
 * this file. If not, visit : https://opensource.org/licenses/MIT
 */

#pragma once

#ifndef __THREADER_H
#define __THREADER_H

#include "includes.h"
#include "config.h"
#include "hijacker.h"

using namespace Hijacker;

class Threader : public Interceptor {
private:
	THREADENTRY32 m_threadEntry32;
	HANDLE m_hThreader;
	bool m_isThreadFound;

public:
	DWORD FindThreadWithinWin32Process(DWORD m_threaderProcessId);

};

#endif 
