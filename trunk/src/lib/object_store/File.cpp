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
 File.h

 This class wraps standard C file I/O in a convenient way for the object store
 *****************************************************************************/

#include "config.h"
#include "File.h"
#include "log.h"
#include <string>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>

// Constructor
//
// N.B.: the create flag only has a function when a file is opened read/write
File::File(std::string path, bool forRead /* = true */, bool forWrite /* = false */, bool create /* = false */)
{
	stream = NULL;

	isReadable = forRead;
	isWritable = forWrite;
	locked = false;

	this->path = path;

	if (forRead || forWrite)
	{
		std::string fileMode = "";

		if (forRead && !forWrite) fileMode = "r";
		if (!forRead && forWrite) fileMode = "w";
		if (forRead && forWrite && !create) fileMode = "r+";
		if (forRead && forWrite && create) fileMode = "w+";

		// Open the stream
		valid = ((stream = fopen(path.c_str(), fileMode.c_str())) != NULL);
	}
}

// Destructor
File::~File() 
{
	if (locked)
	{
		unlock();
	}

	if (stream != NULL)
	{
		fclose(stream);
	}
}

// Check if the file is valid
bool File::isValid()
{
	return valid;
}

// Check if the file is readable
bool File::isRead()
{
	return isReadable;
}

// Check if the file is writable
bool File::isWrite()
{
	return isWritable;
}

// Check if the end-of-file was reached
bool File::isEOF()
{
	return valid && feof(stream);
}

// Read an unsigned long value; warning: not thread safe without locking!
bool File::readULong(unsigned long& value)
{
	if (!valid) return false;

	ByteString ulongVal;

	ulongVal.resize(8);

	if (fread(&ulongVal[0], 1, 8, stream) != 8)
	{
		return false;
	}

	value = ulongVal.long_val();

	return true;
}

// Read a ByteString value; warning: not thread safe without locking!
bool File::readByteString(ByteString& value)
{
	if (!valid) return false;

	// Retrieve the length to read from the file
	unsigned long len;

	if (!readULong(len))
	{
		return false;
	}

	// Read the byte string from the file
	value.resize(len);

	if (fread(&value[0], 1, len, stream) != len)
	{
		return false;
	}

	return true;
}

// Read a boolean value; warning: not thread safe without locking!
bool File::readBool(bool& value)
{
	if (!valid) return false;

	// Read the boolean from the file
	unsigned char boolValue;

	if (fread(&boolValue, 1, 1, stream) != 1)
	{
		return false;
	}

	value = boolValue ? true : false;

	return true;
}

// Read a string value; warning: not thread safe without locking!
bool File::readString(std::string& value)
{
	if (!valid) return false;

	// Retrieve the length to read from the file
	unsigned long len;

	if (!readULong(len))
	{
		return false;
	}

	// Read the string from the file
	value.resize(len);

	if (fread(&value[0], 1, len, stream) != len)
	{
		return false;
	}

	return true;
}

// Write an unsigned long value; warning: not thread safe without locking!
bool File::writeULong(const unsigned long value)
{
	if (!valid) return false;

	ByteString toWrite(value);

	// Write the value to the file
	if (fwrite(toWrite.const_byte_str(), 1, toWrite.size(), stream) != toWrite.size())
	{
		return false;
	}

	return true;
}

// Write a ByteString value; warning: not thread safe without locking!
bool File::writeByteString(const ByteString& value)
{
	if (!valid) return false;

	ByteString toWrite = value.serialise();

	// Write the value to the file
	if (fwrite(toWrite.const_byte_str(), 1, toWrite.size(), stream) != toWrite.size())
	{
		return false;
	}

	return true;
}

// Write a string value; warning: not thread safe without locking!
bool File::writeString(const std::string& value)
{
	if (!valid) return false;

	ByteString toWrite((const unsigned long) value.size());

	// Write the value to the file
	if ((fwrite(toWrite.const_byte_str(), 1, toWrite.size(), stream) != toWrite.size()) ||
	    (fwrite(&value[0], 1, value.size(), stream) != value.size()))
	{
		return false;
	}

	return true;
}

// Write a boolean value; warning: not thread safe without locking!
bool File::writeBool(const bool value)
{
	if (!valid) return false;

	unsigned char toWrite = value ? 0xFF : 0x00;

	// Write the value to the file
	if (fwrite(&toWrite, 1, 1, stream) != 1)
	{
		return false;
	}

	return true;
}

// Rewind the file
bool File::rewind()
{
	if (!valid) return false;

	::rewind(stream);

	return true;
}

// Seek to the specified position relative to the start of the file; if no
// argument is specified this operation seeks to the end of the file
bool File::seek(long offset /* = -1 */)
{
	if (offset == -1)
	{
		return valid && (valid = !fseek(stream, 0, SEEK_END));
	}
	else
	{
		return valid && (valid = !fseek(stream, offset, SEEK_SET));
	}
}

// Lock the file
bool File::lock(bool block /* = true */)
{
	if (locked || !valid) return false;

	if (flock(fileno(stream), block ? LOCK_EX : LOCK_EX | LOCK_NB))
	{
		return false;
	}

	locked = true;

	return true;
}

// Unlock the file
bool File::unlock()
{
	if (!locked || !valid) return false;

	if (flock(fileno(stream), LOCK_UN))
	{
		valid = false;

		return false;
	}

	locked = false;

	return valid;
}

// Flush the buffered stream to background storage
bool File::flush()
{
	return valid && !fflush(stream);
}

