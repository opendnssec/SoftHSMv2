/*
 * Copyright (c) 2013 SURFnet bv
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
 Generation.h

 Helper for generation number handling.
 *****************************************************************************/

#ifndef _SOFTHSM_V2_GENERATION_H
#define _SOFTHSM_V2_GENERATION_H

#include "config.h"
#include <string>
#include "File.h"
#include "MutexFactory.h"

class Generation
{
public:
	// Factory
	static Generation* create(const std::string inPath, bool inIsToken = false);

	// Destructor
	virtual ~Generation();

	// Synchronize from locked disk file
	bool sync(File &objectfile);

	// Check if the target was updated
	bool wasUpdated();

	// Note pending update
	void update();

	// Commit (for the token case)
	void commit();

	// Set the current value when read from disk
	void set(unsigned long onDisk);

	// Return new value
	unsigned long get();

	// Rollback (called when the new value failed to be written)
	void rollback();

private:
	// Constructor
	Generation(const std::string path, bool isToken);

	// The file path
	std::string path;

	// isToken
	bool isToken;

	// Pending update
	bool pendingUpdate;

	// Current value
	unsigned long currentValue;

	// For thread safeness
	Mutex* genMutex;
};

#endif // !_SOFTHSM_V2_GENERATION_H

