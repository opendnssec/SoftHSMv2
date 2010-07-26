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
 Semaphore.h

 This class implements an object version of POSIX semaphores
 *****************************************************************************/

#ifndef _SOFTHSM_V2_SEMAPHORE_H
#define _SOFTHSM_V2_SEMAPHORE_H

#include "config.h"
#include <semaphore.h>
#include <string>

class Semaphore
{
public:
	// Factory
	static Semaphore* create(int initialValue, const std::string name = "");

	// Destructor
	virtual ~Semaphore();

	// Increment (unlock) the semaphore
	bool inc();

	// Decrement (lock) the semaphore
	bool dec(bool wait = false);

	// Retrieve the value of the semaphore
	int getValue();

private:
	// Constructor
	Semaphore(sem_t* semaphore, std::string name);

	// The actual POSIX semaphore
	sem_t* semaphore;

	// The name of the semaphore (needed to destroy it)
	std::string name;
};

#endif // !_SOFTHSM_V2_SEMAPHORE_H

