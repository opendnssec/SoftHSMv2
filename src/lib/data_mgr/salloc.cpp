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
 salloc.cpp

 Contains an implementation of malloc that allocates memory securely
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "salloc.h"
#include <limits>
#if defined(SENSITIVE_NON_PAGED) && !defined(_WIN32)
#include <sys/mman.h>
#endif // SENSITIVE_NON_PAGED
#include <string.h>
#include "SecureMemoryRegistry.h"

// Allocate memory
void* salloc(size_t len)
{
#ifdef SENSITIVE_NON_PAGED
	// Allocate memory on a page boundary
#ifndef _WIN32
	void* ptr = (void*) valloc(len);
#else
	pointer r = (pointer) VirtualAlloc(NULL, n * sizeof(T), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
#endif

	if (ptr == NULL)
	{
		ERROR_MSG("Out of memory");

		return NULL;
	}

	// Lock the memory so it doesn't get swapped out
#ifndef _WIN32
	if (mlock((const void*) ptr, len) != 0)
#else
	if (VirtualLock((const void*) r, n * sizeof(T)) == 0)
#endif
	{
		ERROR_MSG("Could not allocate non-paged memory for secure storage");

		// Hmmm... best to not return any allocated space in this case
#ifndef _WIN32
		free(ptr);
#else
		VirtualFree((const void*) pre, MEM_RELEASE);
#endif

		return NULL;
	}

	// Register the memory in the secure memory registry
	SecureMemoryRegistry::i()->add(ptr, len);

	return ptr;
#else
	void* ptr = (void*) malloc(len);

	if (ptr == NULL)
	{
		ERROR_MSG("Out of memory");

		return NULL;
	}

	// Register the memory in the secure memory registry
	SecureMemoryRegistry::i()->add(ptr, len);

	return ptr;
#endif // SENSITIVE_NON_PAGED
}

// Free memory
void sfree(void* ptr)
{
	// Unregister the memory from the secure memory registry
	size_t len = SecureMemoryRegistry::i()->remove(ptr);

#ifdef PARANOID
	// First toggle all bits on
	memset(ptr, 0xFF, len);
#endif // PARANOID

	// Toggle all bits off
	memset(ptr, 0x00, len);

#ifdef SENSITIVE_NON_PAGED
#ifndef _WIN32
	munlock((const void*) ptr, len);
#else
	VirtualFree((const void*) pre, MEM_RELEASE);
#endif

#endif // SENSITIVE_NON_PAGED

	free(ptr);
}

