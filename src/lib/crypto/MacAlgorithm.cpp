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
 MacAlgorithm.cpp

 Base class for MAC algorithm classes
 *****************************************************************************/

#include "MacAlgorithm.h"
#include <algorithm>
#include <string.h>

MacAlgorithm::MacAlgorithm()
{
	currentOperation = NONE;
	currentKey = NULL;
}

bool MacAlgorithm::signInit(const SymmetricKey* key)
{
	if ((key == NULL) || (currentOperation != NONE))
	{
		return false;
	}

	currentKey = key;
	currentOperation = SIGN;

	return true;
}

bool MacAlgorithm::signUpdate(const ByteString& /*dataToSign*/)
{
	if (currentOperation != SIGN)
	{
		return false;
	}

	return true;
}

bool MacAlgorithm::signFinal(ByteString& /*signature*/)
{
	if (currentOperation != SIGN)
	{
		return false;
	}

	currentOperation = NONE;
	currentKey = NULL;

	return true;
}

bool MacAlgorithm::verifyInit(const SymmetricKey* key)
{
	if ((key == NULL) || (currentOperation != NONE))
	{
		return false;
	}

	currentOperation = VERIFY;
	currentKey = key;

	return true;
}

bool MacAlgorithm::verifyUpdate(const ByteString& /*originalData*/)
{
	if (currentOperation != VERIFY)
	{
		return false;
	}

	return true;
}

bool MacAlgorithm::verifyFinal(ByteString& /*signature*/)
{
	if (currentOperation != VERIFY)
	{
		return false;
	}

	currentOperation = NONE;
	currentKey = NULL;

	return true;
}

unsigned long MacAlgorithm::getMinKeySize()
{
	return 0;
}

unsigned long MacAlgorithm::getMaxKeySize()
{
	return 0;
}

void MacAlgorithm::recycleKey(SymmetricKey* toRecycle)
{
	delete toRecycle;
}
