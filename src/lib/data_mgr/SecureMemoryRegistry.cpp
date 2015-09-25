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
 SecureMemoryRegistry.cpp

 Implements a singleton class that keeps track of all securely allocated
 memory. This registry can be used to wipe securely allocated memory in case
 of a fatal exception
 *****************************************************************************/

#include <stdlib.h>
#include <string.h>
#include "log.h"
#include "SecureMemoryRegistry.h"

// Constructor
SecureMemoryRegistry::SecureMemoryRegistry()
{
	SecMemRegistryMutex = MutexFactory::i()->getMutex();
}

// Destructor
SecureMemoryRegistry::~SecureMemoryRegistry()
{
	if (!registry.empty())
	{
		ERROR_MSG("SecureMemoryRegistry is not empty: leak!");
	}
	MutexFactory::i()->recycleMutex(SecMemRegistryMutex);
}

// Return the one-and-only instance
SecureMemoryRegistry* SecureMemoryRegistry::i()
{
	if (instance.get() == NULL)
	{
		instance.reset(new SecureMemoryRegistry());

		if (instance.get() == NULL)
		{
			// This is very bad!
			ERROR_MSG("failed to instantiate SecureMemoryRegistry");

		}
	}

	return instance.get();
}

// This will destroy the one-and-only instance.
void SecureMemoryRegistry::reset()
{
	instance.reset();
}

// Register a block of memory
void SecureMemoryRegistry::add(void* pointer, size_t blocksize)
{
	MutexLocker lock(SecMemRegistryMutex);

	registry[pointer] = blocksize;

	//DEBUG_MSG("Registered block of %d bytes at 0x%x", blocksize, pointer);
}

// Unregister a block of memory
size_t SecureMemoryRegistry::remove(void* pointer)
{
	//DEBUG_MSG("Unregistered block of %d bytes at 0x%x", registry[pointer], pointer);

	MutexLocker lock(SecMemRegistryMutex);

	size_t rv = registry[pointer];

	registry.erase(pointer);

	return rv;
}

// Wipe all registered blocks of memory
void SecureMemoryRegistry::wipe()
{
	MutexLocker lock(SecMemRegistryMutex);

	// Be very careful in this method to catch any weird exceptions that
	// may occur since if we're in this method it means something has already
	// gone pear shaped once before and we're exiting on a fatal exception
	try
	{
		for (std::map<void*, size_t>::iterator i = registry.begin(); i != registry.end(); i++)
		{
			try
			{
				DEBUG_MSG("Wiping block of %d bytes at 0x%x", i->second, i->first);
			}
			catch (...)
			{
			}
	
			try
			{
	#ifdef PARANOID
				memset(i->first, 0xFF, i->second);
	#endif // PARANOID
				memset(i->first, 0x00, i->second);
			}
			catch (...)
			{
				ERROR_MSG("Failed to wipe block of %d bytes at 0x%x", i->second, i->first);
			}
		}
	}
	catch (...)
	{
		ERROR_MSG("Failed to enumerate the secure memory registry");
	}
}

