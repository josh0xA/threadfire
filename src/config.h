/* Copyright (C) 2020 Josh Schiavone - All Rights Reserved
 * You may use, distribute and modify this code under the
 * terms of the MIT license, which unfortunately won't be
 * written for another century.
 *
 * You should have received a copy of the MIT license with
 * this file. If not, visit : https://opensource.org/licenses/MIT
 */

#pragma once

#ifndef __CONFIG_H
#define __CONFIG_H

#include "includes.h"

#define DBG_SUCCESS_ON_RETURN_VALUE(s_val) ((s_val) == DBG_SUCCESS_STATE)     /* FOR RETURNING A SUCCESS CODE {0} */
#define DBG_ERROR_ON_RETURN_VALUE(s_val) (DBG_SUCCESS_STATE(s_val) == FALSE)) /* FOR RETURNING AN ERROR CODE {-1, ...} */
#define DBG_SET_VALUE(s_val, kVal) ((s_val) = (kVal))

#define NTVERSION_VISTA 6

typedef enum _DBG_STATE_BOUND
{
	/* universal debugging variable*/
	DBG_INVALID_VAR_ANY = -1,

	/* for setting at standard return state [0] */
	DBG_SUCCESS_STATE,

	/* for privilege escalation errors*/
	DBG_ESCALATION_ATTEMPT_FATAL,

	/* for getting windows version error */
	DBG_VERSION_STATE_GETTER_FATAL,

	/* for universal exceptions for THREADENTRY32 */
	DBG_THREADER_STATE_FATAL,

	/* for process state fatal exceptions */
	DBG_PROCESS_STATE_INVALID,

	/* for exceptions on thread suspense */
	DBG_THREAD_SUSPENSION_STATE_FATAL,

	/* for exceptions within a virtual address space */
	DBG_VIRTUAL_MEMORY_STATE_FATAL,

	/* for handling 64-bit exceptions */
	DBG_WRITE_X64_ADDRESS_STATE_FATAL,

	/* for handling 32-bit exceptions */
	DBG_WRITE_X86_ADDRESS_STATE_FATAL,

	/* for handling shellcode exceptions where it could not be written */
	DBG_WRITE_SHELLCODE_TO_THREAD_ADDR_FATAL,

	/* for handling exceptions within the CreateThread address space */
	DBG_WRITE_CREATE_THREAD_ADDR_FATAL,

} DBG_STATE_BOUND, * P_DBG_STATE_BOUND;

#endif 
