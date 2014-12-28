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
 log.cpp

 Implements logging functions. This file is based on the concepts from
 SoftHSM v1 but extends the logging functions with support for a variable
 argument list as defined in stdarg (3).
 *****************************************************************************/

#include "config.h"
#include <stdarg.h>
#include <syslog.h>
#include <stdio.h>
#include <sstream>
#include <vector>
#include "log.h"

int softLogLevel = LOG_DEBUG;

bool setLogLevel(const std::string &loglevel)
{
	if (loglevel == "ERROR")
	{
		softLogLevel = LOG_ERR;
	}
	else if (loglevel == "WARNING")
	{
		softLogLevel = LOG_WARNING;
	}
	else if (loglevel == "INFO")
	{
		softLogLevel = LOG_INFO;
	}
	else if (loglevel == "DEBUG")
	{
		softLogLevel = LOG_DEBUG;
	}
	else
	{
		ERROR_MSG("Unknown value (%s) for log.level in configuration", loglevel.c_str());
		return false;
	}

	return true;
}

void softHSMLog(const int loglevel, const char* functionName, const char* fileName, const int lineNo, const char* format, ...)
{
	if (loglevel > softLogLevel) return;

	std::stringstream prepend;

#ifdef SOFTHSM_LOG_FILE_AND_LINE
	prepend << fileName << "(" << lineNo << ")";
#ifndef SOFTHSM_LOG_FUNCTION_NAME
	(void) functionName;
	prepend << ":";
#endif // !SOFTHSM_LOG_FUNCTION_NAME
	prepend << " ";
#endif // SOFTHSM_LOG_FILE_AND_LINE

#ifdef SOFTHSM_LOG_FUNCTION_NAME
	prepend << functionName << ": ";
#endif // SOFTHSM_LOG_FUNCTION_NAME

	// Print the format to a log message
	std::vector<char> logMessage;
	va_list args;

	logMessage.resize(4096);

	va_start(args, format);
	vsnprintf(&logMessage[0], 4096, format, args);
	va_end(args);

	// And log it
	syslog(loglevel, "%s%s", prepend.str().c_str(), &logMessage[0]);

#ifdef DEBUG_LOG_STDERR
	fprintf(stderr, "%s%s\n", prepend.str().c_str(), &logMessage[0]);
	fflush(stderr);
#endif // DEBUG_LOG_STDERR
}

