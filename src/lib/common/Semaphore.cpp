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
 Semaphore.cpp

 This class implements an object version of POSIX semaphores
 *****************************************************************************/

#include "config.h"
#include "Semaphore.h"
#include <fcntl.h>
#include <sys/stat.h>
#include <algorithm>

// Search/replace for "/" to "_"
char replaceSlashByUnderscore(const char in)
{
#ifndef _WIN32
	return ((in == '/') ? '_' : in);
#else
	return ((in == '\\') ? '_' : in);
#endif
}

// Factory
Semaphore* Semaphore::create(int initialValue, const std::string name /* = "" */)
{
	std::string semName;

	if (!name.empty())
	{
		// Replace all occurences of "/" by "_" in the name
		semName.resize(name.size());
		std::transform(name.begin(), name.end(), semName.begin(), replaceSlashByUnderscore);

		semName = "/" + semName;
	}

#ifndef _WIN32
	sem_t* semaphore = sem_open(semName.empty() ? NULL : semName.c_str(), O_CREAT, S_IRWXU|S_IRWXG|S_IRWXO, initialValue);
#else
	HANDLE semaphore = CreateSemaphoreA(NULL, initialValue, initialValue + 1, semName.c_str());
#endif

	if (semaphore == NULL)
	{
		return NULL;
	}

	return new Semaphore(semaphore, semName);
}

// Constructor
#ifndef _WIN32
Semaphore::Semaphore(sem_t* semaphore, std::string name)
#else
Semaphore::Semaphore(HANDLE semaphore, std::string name)
#endif
{
	this->semaphore = semaphore;
	this->name = name;
#ifdef _WIN32
	InitializeCriticalSection(&cs);
#endif
}

// Destructor
Semaphore::~Semaphore()
{
#ifndef _WIN32
	// Close the semaphore
	sem_close(semaphore);

	// Destroy it (if necessary)
	if (!name.empty())
	{
		sem_unlink(name.c_str());
	}
#else
	CloseHandle(semaphore);
	DeleteCriticalSection(&cs);
#endif
}

// Increment (unlock) the semaphore
bool Semaphore::inc()
{
#ifndef _WIN32
	return (sem_post(semaphore) != -1);
#else
	return (ReleaseSemaphore(semaphore, 1, NULL) != 0);
#endif
}

// Decrement (lock) the semaphore
bool Semaphore::dec(bool wait /* = false */)
{
	if (wait)
	{
#ifndef _WIN32
		return (sem_wait(semaphore) != -1);
#else
		return (WaitForSingleObject(semaphore, INFINITE) != 0);
#endif
	}
	else
	{
#ifndef _WIN32
		return (sem_trywait(semaphore) != -1);
#else
		return (WaitForSingleObject(semaphore, 0) != 0);
#endif
	}
}

// Retrieve the value of the semaphore
int Semaphore::getValue()
{
	int value = -1;

#ifndef _WIN32
	if (sem_getvalue(semaphore, &value) == -1)
	{
		return -1;
	}
#else
	EnterCriticalSection(&cs);
	if (WaitForSingleObject(semaphore, 0) == 0)
	{
		LONG prev;
		ReleaseSemaphore(semaphore, 1, &prev);
		value = prev + 1;
	} else
		value = 0;
	LeaveCriticalSection(&cs);
#endif

	return value;
}

