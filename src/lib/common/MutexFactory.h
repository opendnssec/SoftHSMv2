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
 MutexFactory.h

 This factory produces OS specific mutex objects
 *****************************************************************************/

#ifndef _SOFTHSM_V2_MUTEXFACTORY_H
#define _SOFTHSM_V2_MUTEXFACTORY_H

#include "config.h"
#include "osmutex.h"
#include "cryptoki.h"
#include <memory>

class Mutex
{
public:
	// Constructor
	Mutex();

	// Destructor
	virtual ~Mutex();

	// Lock the mutex
	bool lock();

	// Unlock the mutex
	void unlock();

private:
	// The mutex handle
	CK_VOID_PTR handle;

	// Is the mutex valid?
	bool isValid;
};

class MutexLocker
{
public:
	// Constructor
	MutexLocker(Mutex* inMutex);

	// Destructor
	virtual ~MutexLocker();

private:
	// The mutex to lock
	Mutex* mutex;
};

class MutexFactory
{
public:
	// Return the one-and-only instance
	static MutexFactory* i();

	// Destructor
	virtual ~MutexFactory();

	// Get a mutex instance
	Mutex* getMutex();

	// Recycle a mutex instance
	void recycleMutex(Mutex* mutex);

	// Set the function pointers
	void setCreateMutex(CK_CREATEMUTEX inCreateMutex);
	void setDestroyMutex(CK_DESTROYMUTEX inDestroyMutex);
	void setLockMutex(CK_LOCKMUTEX inLockMutex);
	void setUnlockMutex(CK_UNLOCKMUTEX inUnlockMutex);

	// Enable/disable mutex handling
	void enable();
	void disable();

private:
	// Constructor
	MutexFactory();

	// Mutex operations
	friend class Mutex;

	CK_RV CreateMutex(CK_VOID_PTR_PTR newMutex);
	CK_RV DestroyMutex(CK_VOID_PTR mutex);
	CK_RV LockMutex(CK_VOID_PTR mutex);
	CK_RV UnlockMutex(CK_VOID_PTR mutex);

	// The one-and-only instance
#ifdef HAVE_CXX11
	static std::unique_ptr<MutexFactory> instance;
#else
	static std::auto_ptr<MutexFactory> instance;
#endif

	// The function pointers
	CK_CREATEMUTEX createMutex;
	CK_DESTROYMUTEX destroyMutex;
	CK_LOCKMUTEX lockMutex;
	CK_UNLOCKMUTEX unlockMutex;

	// Can we do mutex handling?
	bool enabled;
};

#endif // !_SOFTHSM_V2_MUTEXFACTORY_H

