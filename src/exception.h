/* Copyright (C) 2020 Josh Schiavone - All Rights Reserved
 * You may use, distribute and modify this code under the
 * terms of the MIT license, which unfortunately won't be
 * written for another century.
 *
 * You should have received a copy of the MIT license with
 * this file. If not, visit : https://opensource.org/licenses/MIT
 */

/*
	This class could be defined in any other file, this file serves a pretty universal purpose
	but I've decided just to add it for organizing purposes.
*/
#pragma once
#ifndef __EXCEPTION_H
#define __EXCEPTION_H

#include "logger.hpp"





class Exception {

private:
	LPVOID m_lpMessageBuffer;
	DWORD m_dwLastError = GetLastError();

public:

	DBG_STATE_BOUND TBLThrowError(char* m_errorText, DWORD m_dwReturnVal)
	{
		FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM
			| FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, m_dwLastError, LANG_ENGLISH, (LPTSTR)& m_lpMessageBuffer,
			0, NULL);

		std::cerr << m_errorText << " Error Code: " << "0x" << std::hex << m_dwLastError << '\n';

		return (DBG_STATE_BOUND)m_dwReturnVal;
	}

};


#endif 
