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
 SecureMemoryRegistry.h

 Implements a singleton class that keeps track of all securely allocated
 memory. This registry can be used to wipe securely allocated memory in case
 of a fatal exception
 *****************************************************************************/

#ifndef _SOFTHSM_V2_SECUREMEMORYREGISTRY_H
#define _SOFTHSM_V2_SECUREMEMORYREGISTRY_H

#include <stdlib.h>
#include <map>
#include <memory>
#include "MutexFactory.h"

class SecureMemoryRegistry
{
public:
	SecureMemoryRegistry();

	virtual ~SecureMemoryRegistry();

	static SecureMemoryRegistry* i();

	static void reset();

	void add(void* pointer, size_t blocksize);

	size_t remove(void* pointer);

	void wipe();

private:
#ifdef HAVE_CXX11
	static std::unique_ptr<SecureMemoryRegistry> instance;
#else
	static std::auto_ptr<SecureMemoryRegistry> instance;
#endif

	std::map<void*, size_t> registry;

	Mutex* SecMemRegistryMutex;
};

#endif // !_SOFTHSM_V2_SECUREMEMORYREGISTRY_H

