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
 OSToken.h

 The token class; a token is stored in a directory containing several files.
 Each object is stored in a separate file and a token object is present that
 has the token specific attributes
 *****************************************************************************/

#ifndef _SOFTHSM_V2_OSTOKEN_H
#define _SOFTHSM_V2_OSTOKEN_H

#include "config.h"
#include "OSAttribute.h"
#include "ObjectFile.h"
#include "File.h"
#include "Directory.h"
#include "UUID.h"
#include <string>
#include <vector>
#include <map>

class OSToken
{
public:
	// Constructor
	OSToken(std::string tokenPath);

	// Destructor
	virtual ~OSToken();

	// Checks if the token is consistent
	bool isValid();

private:
	// Index the token

	// Is the token consistent and valid?
	bool valid;

	// The objects of the token
	std::vector<ObjectFile*> objects;

	// The token object
	ObjectFile* tokenObject;

	// The token index
	std::map<ByteString, ObjectFile*> map_by_id;
	std::map<ByteString, ObjectFile*> map_by_label;
};

#endif // !_SOFTHSM_V2_OSTOKEN_H

