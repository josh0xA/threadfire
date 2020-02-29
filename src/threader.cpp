/* Copyright (C) 2020 Josh Schiavone - All Rights Reserved
 * You may use, distribute and modify this code under the
 * terms of the MIT license, which unfortunately won't be
 * written for another century.
 *
 * You should have received a copy of the MIT license with
 * this file. If not, visit : https://opensource.org/licenses/MIT
 */

#include "threader.h"


DWORD Threader::FindThreadWithinWin32Process(DWORD m_threaderProcessId)
{
	dbgStatus = DBG_INVALID_VAR_ANY;

	HANDLE m_threaderSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	m_threadEntry32.dwSize = sizeof(THREADENTRY32);
	if (m_threaderSnapshot == INVALID_HANDLE_VALUE)
	{
		DBG_SET_VALUE(dbgStatus, DBG_THREADER_STATE_FATAL);
		throw std::runtime_error("DBG_THREADER_STATE_FATAL");
	}

	if (!Thread32First(m_threaderSnapshot, &m_threadEntry32))
	{
		DBG_SET_VALUE(dbgStatus, DBG_THREADER_STATE_FATAL);
		throw std::runtime_error("DBG_THREADER_STATE_FATAL");
	}

	while (Thread32Next(m_threaderSnapshot, &m_threadEntry32))
	{
		if (m_threadEntry32.th32OwnerProcessID == m_threaderProcessId)
		{
			m_isThreadFound = true;
			break;
		}
	}

	CloseHandle(m_threaderSnapshot);

	if (m_isThreadFound == TRUE) { return m_threadEntry32.th32ThreadID; }
	else {
		DBG_SET_VALUE(dbgStatus, DBG_THREADER_STATE_FATAL);
		throw std::runtime_error("DBG_THREADER_STATE_FATAL");
	}

	return 0;
}