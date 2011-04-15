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
 IPCSignal.cpp

 This class implements rudimentary IPC signalling based on POSIX semaphores.

 N.B.: Because of the way this code works, SoftHSM v2 is not suitable for use
       in environments where it is both long lived as well as has a high
       object change ratio (either separately is not a problem). This is
       caused by the fact that the counter on a POSIX semaphore has a limit
       of INT_MAX.
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "IPCSignal.h"

// Factory
IPCSignal* IPCSignal::create(const std::string name)
{
	Semaphore* semaphore = Semaphore::create(0, name);

	if (semaphore == NULL)
	{
		ERROR_MSG("Failed to create a named semaphore (%s)", name.c_str());
			
		return NULL;
	}

	return new IPCSignal(semaphore);
}

// Destructor
IPCSignal::~IPCSignal()
{
	delete semaphore;
}

// Update the signal
void IPCSignal::trigger()
{
	if (!semaphore->inc())
	{
		if (semaphore->getValue() > 0)
		{
			// Decrement by 10; this is to prevent listeners from missing
			// the changed in case of a saturated semaphore. This is not 
			// ideal, however
			for (int i = 0; i < 10; i++) semaphore->dec();

			currentValue -= 10;
		}
		else
		{
			// Make sure this instance isn't triggered by its own action
			currentValue++;
		}
	}
}

// Has the signal been triggered?
bool IPCSignal::wasTriggered()
{
	int value = semaphore->getValue();

	if (value != currentValue)
	{
		currentValue = value;

		return true;
	}

	return false;
}

// Constructor
IPCSignal::IPCSignal(Semaphore* semaphore)
{
	this->semaphore = semaphore;
	currentValue = semaphore->getValue();
}

