/*
 * Copyright (c) 2008-2010 .SE (The Internet Infrastructure Foundation).
 * Copyright (c) 2010      SURFnet bv
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
 osmutex.cpp

 Contains OS-specific implementations of intraprocess mutex functions. This
 implementation is based on SoftHSM v1
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "osmutex.h"

#ifdef HAVE_PTHREAD_H

#include <stdlib.h>
#include <pthread.h>

CK_RV OSCreateMutex(CK_VOID_PTR_PTR newMutex)
{
	int rv;

	/* Allocate memory */
	pthread_mutex_t* pthreadMutex = (pthread_mutex_t*) malloc(sizeof(pthread_mutex_t));

	if (pthreadMutex == NULL)
	{
		ERROR_MSG("Failed to allocate memory for a new mutex");

		return CKR_HOST_MEMORY;
	}

	/* Initialise the mutex */
	if ((rv = pthread_mutex_init(pthreadMutex, NULL)) != 0)
	{
		free(pthreadMutex);

		ERROR_MSG("Failed to initialise POSIX mutex (0x%08X)", rv);

		return CKR_GENERAL_ERROR;
	}

	*newMutex = pthreadMutex;

	return CKR_OK;
}

CK_RV OSDestroyMutex(CK_VOID_PTR mutex)
{
	int rv;
	pthread_mutex_t* pthreadMutex = (pthread_mutex_t*) mutex;

	if (pthreadMutex == NULL)
	{
		ERROR_MSG("Cannot destroy NULL mutex");

		return CKR_ARGUMENTS_BAD;
	}

	if ((rv = pthread_mutex_destroy(pthreadMutex)) != 0)
	{
		ERROR_MSG("Failed to destroy POSIX mutex (0x%08X)", rv);

		return CKR_GENERAL_ERROR;
	}

	free(pthreadMutex);

	return CKR_OK;
}

CK_RV OSLockMutex(CK_VOID_PTR mutex)
{
	int rv;
	pthread_mutex_t* pthreadMutex = (pthread_mutex_t*) mutex;

	if (pthreadMutex == NULL)
	{
		ERROR_MSG("Cannot lock NULL mutex");

		return CKR_ARGUMENTS_BAD;
	}

	if ((rv = pthread_mutex_lock(pthreadMutex)) != 0)
	{
		ERROR_MSG("Failed to lock POSIX mutex 0x%08X (0x%08X)", pthreadMutex, rv);

		return CKR_GENERAL_ERROR;
	}

	return CKR_OK;
}

CK_RV OSUnlockMutex(CK_VOID_PTR mutex)
{
	int rv;
	pthread_mutex_t* pthreadMutex = (pthread_mutex_t*) mutex;

	if (pthreadMutex == NULL)
	{
		ERROR_MSG("Cannot unlock NULL mutex");

		return CKR_ARGUMENTS_BAD;
	}

	if ((rv = pthread_mutex_unlock(pthreadMutex)) != 0)
	{
		ERROR_MSG("Failed to unlock POSIX mutex 0x%08X (0x%08X)", pthreadMutex, rv);

		return CKR_GENERAL_ERROR;
	}

	return CKR_OK;
}

#elif _WIN32

CK_RV OSCreateMutex(CK_VOID_PTR_PTR newMutex)
{
	HANDLE hMutex;

	hMutex = CreateMutex(NULL, FALSE, NULL);
	if (hMutex == NULL)
	{
		DWORD rv = GetLastError();

		ERROR_MSG("Failed to initialise WIN32 mutex (0x%08X)", rv);

		return CKR_GENERAL_ERROR;
	}

	*newMutex = hMutex;

	return CKR_OK;
}

CK_RV OSDestroyMutex(CK_VOID_PTR mutex)
{
	HANDLE hMutex = (HANDLE) mutex;

	if (hMutex == NULL)
	{
		ERROR_MSG("Cannot destroy NULL mutex");

		return CKR_ARGUMENTS_BAD;
	}

	if (CloseHandle(hMutex) == 0)
	{
		DWORD rv = GetLastError();

		ERROR_MSG("Failed to destroy WIN32 mutex (0x%08X)", rv);

		return CKR_GENERAL_ERROR;
	}

	return CKR_OK;
}

CK_RV OSLockMutex(CK_VOID_PTR mutex)
{
	DWORD rv;
	HANDLE hMutex = (HANDLE) mutex;

	if (hMutex == NULL)
	{
		ERROR_MSG("Cannot lock NULL mutex");

		return CKR_ARGUMENTS_BAD;
	}

	rv = WaitForSingleObject(hMutex, INFINITE);
	if (rv != WAIT_OBJECT_0)
	{
		// WAIT_ABANDONED 0x00000080
		// WAIT_OBJECT_0  0x00000000
		// WAIT_TIMEOUT   0x00000102
		// WAIT_FAILED    0xFFFFFFFF

		if (rv == WAIT_FAILED)
			rv = GetLastError();

		ERROR_MSG("Failed to lock WIN32 mutex 0x%08X (0x%08X)", hMutex, rv);

		return CKR_GENERAL_ERROR;
	}

	return CKR_OK;
}

CK_RV OSUnlockMutex(CK_VOID_PTR mutex)
{
	HANDLE hMutex = (HANDLE) mutex;

	if (hMutex == NULL)
	{
		ERROR_MSG("Cannot unlock NULL mutex");

		return CKR_ARGUMENTS_BAD;
	}

	if (ReleaseMutex(hMutex) == 0)
	{
		DWORD rv = GetLastError();

		ERROR_MSG("Failed to unlock WIN32 mutex 0x%08X (0x%08X)", hMutex, rv);

		return CKR_GENERAL_ERROR;
	}

	return CKR_OK;
}

#else
#error "There are no mutex implementations for your operating system yet"
#endif

