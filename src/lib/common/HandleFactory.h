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
 HandleFactory.h

 This is a template class for handling handles ;-)
 *****************************************************************************/

#ifndef _SOFTHSM_V2_HANDLEFACTORY_H
#define _SOFTHSM_V2_HANDLEFACTORY_H

#include "config.h"
#include "log.h"
#include "MutexFactory.h"
#include <map>
#include <queue>

template <class hType, class oType> class HandleFactory
{
public:
	// Constructor
	HandleFactory() 
	{
		nextFree = (hType) 1;
		handleMutex = MutexFactory::i()->getMutex();
	}

	// Destructor
	virtual ~HandleFactory() 
	{
		MutexFactory::i()->recycleMutex(handleMutex);
	}

	// Get a new handle for the specified object
	hType getHandle(oType object)
	{
		MutexLocker lock(handleMutex);

		hType handle;

		if (!recycledHandles.empty())
		{
			handle = recycledHandles.front();
			recycledHandles.pop();
		}
		else
		{
			handle = nextFree++;
		}

		handleMap[handle] = object;

		return handle;
	}

	// Check whether the specified handle is valid
	bool isValid(hType handle)
	{
		MutexLocker lock(handleMutex);

		return (handleMap.find(handle) != handleMap.end());
	}

	// Return the object for the specified handle
	oType getObjectByHandle(hType handle)
	{
		MutexLocker lock(handleMutex);

		return handleMap[handle];
	}

	// Discard the specified handle
	void deleteHandle(hType handle)
	{
		MutexLocker lock(handleMutex);

		handleMap.erase(handle);

		recycledHandles.push(handle);
	}

private:
	// The handle map
	std::map<hType, oType> handleMap;

	// The set of recycled handles
	std::queue<hType> recycledHandles;

	// The next free handle
	hType nextFree;

	// Cross-thread synchronisation
	Mutex* handleMutex;
};

#endif // !_SOFTHSM_V2_HANDLEFACTORY_H

