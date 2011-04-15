/* $Id: log.h 31 2010-03-05 12:51:02Z rb $ */

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
#include "config.h"

/* The log levels */
#define SOFTERROR	1
#define SOFTWARNING	2
#define SOFTINFO	3
#define SOFTDEBUG	4

/* Set the default loglevel if none is set */
#ifndef SOFTLOGLEVEL
#define SOFTLOGLEVEL	SOFTDEBUG
#endif /* !SOFTLOGLEVEL */

/* Unset this define if you don't want to log the source file name and line number */
#define SOFTHSM_LOG_FILE_AND_LINE

/* Set this define to log the function name */
/* #define SOFTHSM_LOG_FUNCTION_NAME */

/* Define this symbol (either here or in the build setup) to log to stderr */
/* #define DEBUG_LOG_STDERR */

/* Logging errors */
#if SOFTLOGLEVEL >= SOFTERROR
#define ERROR_MSG(...) softHSMLog(LOG_ERR, __func__, __FILE__, __LINE__, __VA_ARGS__);
#else
#define ERROR_MSG(...)
#endif

/* Logging warnings */
#if SOFTLOGLEVEL >= SOFTWARNING
#define WARNING_MSG(...) softHSMLog(LOG_WARNING, __func__, __FILE__, __LINE__, __VA_ARGS__);
#else
#define WARNING_MSG(...)
#endif

/* Logging information */
#if SOFTLOGLEVEL >= SOFTINFO
#define INFO_MSG(...) softHSMLog(LOG_INFO, __func__, __FILE__, __LINE__, __VA_ARGS__);
#else
#define INFO_MSG(...)
#endif

/* Logging debug information */
#if SOFTLOGLEVEL >= SOFTDEBUG
#define DEBUG_MSG(...) softHSMLog(LOG_DEBUG, __func__, __FILE__, __LINE__, __VA_ARGS__);
#else
#define DEBUG_MSG(...)
#endif

/* Function definitions */
void softHSMLog(const int loglevel, const char* functionName, const char* fileName, const int lineNo, const char* format, ...);

#endif /* !_SOFTHSM_V2_LOG_H */

