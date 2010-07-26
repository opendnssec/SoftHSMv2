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
 MutexFactory.cpp

 This factory produces OS specific mutex objects
 *****************************************************************************/

#include "config.h"
#include "MutexFactory.h"
#include "osmutex.h"
#include <memory>


/*****************************************************************************
 Mutex implementation
 *****************************************************************************/

// Constructor
Mutex::Mutex()
{
	isValid = (MutexFactory::i()->createMutex(&handle) == CKR_OK);	
}

// Destructor
Mutex::~Mutex()
{
	if (isValid)
	{
		MutexFactory::i()->destroyMutex(handle);
	}
}

// Lock the mutex
bool Mutex::lock()
{
	return (isValid && (MutexFactory::i()->lockMutex(handle) == CKR_OK));
}
	 
// Unlock the mutex
void Mutex::unlock()
{
	if (isValid) 
	{
		MutexFactory::i()->unlockMutex(handle);
	}
}

/*****************************************************************************
 MutexLocker implementation
 *****************************************************************************/

// Constructor
MutexLocker::MutexLocker(Mutex* mutex)
{
	this->mutex = mutex;

	this->mutex->lock();
}

// Destructor
MutexLocker::~MutexLocker()
{
	this->mutex->unlock();
}

/*****************************************************************************
 MutexFactory implementation
 *****************************************************************************/

// Initialise the one-and-only instance
std::auto_ptr<MutexFactory> MutexFactory::instance(NULL);

// Constructor
MutexFactory::MutexFactory()
{
	createMutex = OSCreateMutex;
	destroyMutex = OSDestroyMutex;
	lockMutex = OSLockMutex;
	unlockMutex = OSUnlockMutex;
}

// Destructor
MutexFactory::~MutexFactory()
{
}

// Return the one-and-only instance
MutexFactory* MutexFactory::i()
{
	if (!instance.get())
	{
		instance = std::auto_ptr<MutexFactory>(new MutexFactory());
	}

	return instance.get();
}

// Get a mutex instance
Mutex* MutexFactory::getMutex()
{
	return new Mutex();
}

// Recycle a mutex instance
void MutexFactory::recycleMutex(Mutex* mutex)
{
	delete mutex;
}

// Set the function pointers
void MutexFactory::setCreateMutex(CK_CREATEMUTEX createMutex)
{
	this->createMutex = createMutex;
}

void MutexFactory::setDestroyMutex(CK_DESTROYMUTEX destroyMutex)
{
	this->destroyMutex = destroyMutex;
}

void MutexFactory::setLockMutex(CK_LOCKMUTEX lockMutex)
{
	this->lockMutex = lockMutex;
}

void MutexFactory::setUnlockMutex(CK_UNLOCKMUTEX unlockMutex)
{
	this->unlockMutex = unlockMutex;
}

CK_RV MutexFactory::CreateMutex(CK_VOID_PTR_PTR newMutex)
{
	return (this->createMutex)(newMutex);
}

CK_RV MutexFactory::DestroyMutex(CK_VOID_PTR mutex)
{
	return (this->destroyMutex)(mutex);
}

CK_RV MutexFactory::LockMutex(CK_VOID_PTR mutex)
{
	return (this->lockMutex)(mutex);
}

CK_RV MutexFactory::UnlockMutex(CK_VOID_PTR mutex)
{
	return (this->unlockMutex)(mutex);
}

