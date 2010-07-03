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
 ObjectFile.h

 This class represents object files
 *****************************************************************************/

#ifndef _SOFTHSM_V2_OBJECTFILE_H
#define _SOFTHSM_V2_OBJECTFILE_H

#include "config.h"
#include "File.h"
#include "ByteString.h"
#include "OSAttribute.h"
#include <string>
#include <map>
#include <time.h>
#include "cryptoki.h"

class ObjectFile
{
public:
	// Constructor
	ObjectFile(std::string path, bool isNew = false);

	// Destructor
	virtual ~ObjectFile();

	// Check if the specified attribute exists
	bool attributeExists(CK_ATTRIBUTE_TYPE type);

	// Retrieve the specified attribute
	OSAttribute* getAttribute(CK_ATTRIBUTE_TYPE type);

	// Set the specified attribute
	bool setAttribute(CK_ATTRIBUTE_TYPE type, const OSAttribute& attribute);

	// The validity state of the object
	bool isValid();

private:
	// Refresh the object if necessary
	void refresh();

	// Write the object to background storage
	void store();

	// Discard the cached attributes
	void discardAttributes();

	// The path to the file
	std::string path;

	// The last modification time of the file
	time_t lastModification;

	// The object's raw attributes
	std::map<CK_ATTRIBUTE_TYPE, OSAttribute*> attributes;

	// The object's validity state
	bool valid;
};

#endif // !_SOFTHSM_V2_OBJECTFILE_H

