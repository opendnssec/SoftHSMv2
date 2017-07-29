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
 File.h

 This class wraps standard C file I/O in a convenient way for the object store
 *****************************************************************************/

#ifndef _SOFTHSM_V2_FILE_H
#define _SOFTHSM_V2_FILE_H

#include "config.h"
#include "OSAttribute.h"
#include <stdio.h>
#include <string>

class File
{
public:
	// Constructor
	File(std::string inPath, bool forRead = true, bool forWrite = false, bool create = false, bool truncate = true);

	// Destructor
	virtual ~File();

	// Check if the file is valid
	bool isValid();

	// Check if the file is readable
	bool isRead();

	// Check if the file is writable
	bool isWrite();

	// Check if the file is empty
	bool isEmpty();

	// Check if the end-of-file was reached
	bool isEOF();

	// Read an unsigned long value; warning: not thread safe without locking!
	bool readULong(unsigned long& value);

	// Read a ByteString value; warning: not thread safe without locking!
	bool readByteString(ByteString& value);

	// Read a string value; warning: not thread safe without locking!
	bool readString(std::string& value);

	// Read a boolean value; warning: not thread safe without locking!
	bool readBool(bool& value);

	// Read a mechanism type set value; warning: not thread safe without locking!
	bool readMechanismTypeSet(std::set<CK_MECHANISM_TYPE>& value);

	// Read an array value; warning: not thread safe without locking!
	bool readAttributeMap(std::map<CK_ATTRIBUTE_TYPE,OSAttribute>& value);

	// Write an unsigned long value; warning: not thread safe without locking!
	bool writeULong(const unsigned long value);

	// Write a ByteString value; warning: not thread safe without locking!
	bool writeByteString(const ByteString& value);

	// Write a string value; warning: not thread safe without locking!
	bool writeString(const std::string& value);

	// Write a boolean value; warning: not thread safe without locking!
	bool writeBool(const bool value);

	// Write a mechanism type set value; warning: not thread safe without locking!
	bool writeMechanismTypeSet(const std::set<CK_MECHANISM_TYPE>& value);

	// Write an attribute map value; warning: not thread safe without locking!
	bool writeAttributeMap(const std::map<CK_ATTRIBUTE_TYPE,OSAttribute>& value);

	// Rewind the file
	bool rewind();

	// Truncate the file
	bool truncate();

	// Seek to the specified position relative to the start of the file; if no
	// argument is specified this operation seeks to the end of the file
	bool seek(long offset = -1);

	// Lock the file
	bool lock(bool block = true);

	// Unlock the file
	bool unlock();

	// Flush the buffered stream to background storage
	bool flush();

private:
	// The file path
	std::string path;

	// The status
	bool valid;
	bool locked;

	// Read, write or both?
	bool isReadable, isWritable;

	// The FILE stream
	FILE* stream;
};

#endif // !_SOFTHSM_V2_FILE_H

