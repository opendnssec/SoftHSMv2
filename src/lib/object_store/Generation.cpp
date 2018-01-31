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
 Generation.cpp

 Helper for generation number handling.
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "Generation.h"

// Factory
Generation* Generation::create(const std::string path, bool isToken /* = false */)
{
	Generation* gen = new Generation(path, isToken);
	if ((gen != NULL) && isToken && (gen->genMutex == NULL))
	{
		delete gen;

		return NULL;
	}
	return gen;
}

// Destructor
Generation::~Generation()
{
	if (isToken)
	{
		MutexFactory::i()->recycleMutex(genMutex);
	}
}

// Synchronize from locked disk file
bool Generation::sync(File &objectFile)
{
	if (isToken)
	{
		ERROR_MSG("Generation sync() called for a token");

		return false;
	}

	unsigned long onDisk;

	if (!objectFile.readULong(onDisk))
	{
		if (objectFile.isEOF())
		{
			onDisk = 0;
		}
		else
		{
			return false;
		}
	}

	currentValue = onDisk;

	return objectFile.seek(0L);
}

// Check if the target was updated
bool Generation::wasUpdated()
{
	if (isToken)
	{
		MutexLocker lock(genMutex);

		File genFile(path);

		if (!genFile.isValid())
		{
			return true;
		}

		genFile.lock();

		unsigned long onDisk;

		if (!genFile.readULong(onDisk))
		{
			return true;
		}

		if (onDisk != currentValue)
		{
			currentValue = onDisk;
			return true;
		}

		return false;
	}
	else
	{
		File objectFile(path);

		if (!objectFile.isValid())
		{
			return true;
		}

		objectFile.lock();

		unsigned long onDisk;

		if (!objectFile.readULong(onDisk))
		{
			return true;
		}

		return (onDisk != currentValue);
	}
}

// Update
void Generation::update()
{
	pendingUpdate = true;
}

// Commit
void Generation::commit()
{
	if (isToken)
	{
		MutexLocker lock(genMutex);

		File genFile(path, true, true, true, false);

		if (!genFile.isValid())
		{
			return;
		}

		genFile.lock();

		if (genFile.isEmpty())
		{
			currentValue++;

			if (currentValue == 0)
			{
				currentValue++;
			}

			pendingUpdate = false;

			(void) genFile.writeULong(currentValue);

			genFile.unlock();

			return;
		}

		unsigned long onDisk;

		bool bOK = true;

		bOK = bOK && genFile.readULong(onDisk);
		bOK = bOK && genFile.seek(0L);

		if (pendingUpdate)
		{
			onDisk++;

			if (onDisk == 0)
			{
				onDisk++;
			}
		}

		bOK = bOK && genFile.writeULong(onDisk);

		if (bOK)
		{
			currentValue = onDisk;

			pendingUpdate = false;
		}

		genFile.unlock();
	}
}

// Set the current value when read from disk
void Generation::set(unsigned long onDisk)
{
	currentValue = onDisk;
}

// Return new value
unsigned long Generation::get()
{
	pendingUpdate = false;

	currentValue++;

	if (currentValue == 0)
	{
		currentValue = 1;
	}

	return currentValue;
}

// Rollback (called when the new value failed to be written)
void Generation::rollback()
{
	pendingUpdate = true;

	if (currentValue != 1)
	{
		currentValue--;
	}
}

// Constructor
Generation::Generation(const std::string inPath, bool inIsToken)
{
	path = inPath;
	isToken = inIsToken;
	pendingUpdate = false;
	currentValue = 0;
	genMutex = NULL;

	if (isToken)
	{
		genMutex = MutexFactory::i()->getMutex();

		if (genMutex != NULL)
		{
			commit();
		}
	}
}
