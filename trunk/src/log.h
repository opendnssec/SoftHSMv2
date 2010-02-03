/* $Id$ */

/*
 * Copyright (c) 2010 SURFnet bv
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*****************************************************************************
 log.h

 Implements logging functions. This file is based on the concepts from 
 SoftHSM v1 but extends the logging functions with support for a variable
 argument list as defined in stdarg (3).
 *****************************************************************************/

#ifndef _SOFTHSM_V2_LOG_H
#define _SOFTHSM_V2_LOG_H

#include <syslog.h>

#if defined(__cplusplus)
extern "C" {
#endif // __cplusplus

// For compilers that don't support the __FUNCTION__ directive
#ifndef __FUNCTION__
#define __FUNCTION__ "unknown"
#endif // !__FUNCTION__

// The log levels
#define SOFTERROR	1
#define SOFTWARNING	2
#define SOFTINFO	3
#define SOFTDEBUG	4

// Set the default loglevel if none is set
#ifndef SOFTLOGLEVEL
#define SOFTLOGLEVEL	SOFTERROR
#endif // !SOFTLOGLEVEL

// Unset this define if you don't want to log the source file name and line number
#define SOFTHSM_LOG_FILE_AND_LINE

// Set this define to log the function name
#undef SOFTHSM_LOG_FUNCTION_NAME

// Logging errors
#if SOFTLOGLEVEL >= SOFTERROR
#define ERROR_MSG(...) log(LOG_ERR, __FUNCTION__, __FILE__, __LINE__, __VA_ARGS__);
#else
#define ERROR_MSG(...)
#endif

// Logging warnings
#if SOFTLOGLEVEL >= SOFTWARNING
#define WARNING_MSG(...) log(LOG_WARNING, __FUNCTION__, __FILE__, __LINE__, __VA_ARGS__);
#else
#define WARNING_MSG(...)
#endif

// Logging information
#if SOFTLOGLEVEL >= SOFTINFO
#define INFO_MSG(...) log(LOG_INFO, __FUNCTION__, __FILE__, __LINE__, __VA_ARGS__);
#else
#define INFO_MSG(...)
#endif

// Logging debug information
#if SOFTLOGLEVEL >= SOFTDEBUG
#define DEBUG_MSG(...) log(LOG_DEBUG, __FUNCTION__, __FILE__, __LINE__, __VA_ARGS__);
#else
#define DEBUG_MSG(...)
#endif

// Function definitions
void log(const int loglevel, const char* functionName, const char* fileName, const int lineNo, ...);

#if defined(__cplusplus)
}
#endif

#endif // !_SOFTHSM_V2_LOG_H

