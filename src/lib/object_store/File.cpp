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
#ifndef _WIN32
#include <sys/file.h>
#include <unistd.h>
#else
#include <io.h>
#define F_SETLK		12
#define F_SETLKW	13
#define F_RDLCK		1
#define F_UNLCK		2
#define F_WRLCK		3
#endif
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

// Constructor
//
// N.B.: the create flag only has a function when a file is opened read/write
// N.B.: the truncate flag only has a function when the create one is true
File::File(std::string path, bool forRead /* = true */, bool forWrite /* = false */, bool create /* = false */, bool truncate /* = true */)
{
	stream = NULL;

	isReadable = forRead;
	isWritable = forWrite;
	locked = false;

	this->path = path;

	if (forRead || forWrite)
	{
		std::string fileMode = "";
		int flags, fd;

#ifndef _WIN32
		flags = 0;
		if (forRead && !forWrite) flags |= O_RDONLY;
		if (!forRead && forWrite) flags |= O_WRONLY | O_CREAT | O_TRUNC;
		if (forRead && forWrite) flags |= O_RDWR;
		if (forRead && forWrite && create) flags |= O_CREAT;
		if (forRead && forWrite && create && truncate) flags |= O_TRUNC;
		// Open the file
		fd = open(path.c_str(), flags, 0777);
		if (fd == -1)
		{
			valid = false;
			return;
		}

		if (forRead && !forWrite) fileMode = "r";
		if (!forRead && forWrite) fileMode = "w";
		if (forRead && forWrite && !create) fileMode = "r+";
		if (forRead && forWrite && create) fileMode = "w+";
		// Open the stream
		valid = ((stream = fdopen(fd, fileMode.c_str())) != NULL);
#else
		flags = _O_BINARY;
		if (forRead && !forWrite) flags |= _O_RDONLY;
		if (!forRead && forWrite) flags |= _O_WRONLY | _O_CREAT | _O_TRUNC;
		if (forRead && forWrite) flags |= _O_RDWR;
		if (forRead && forWrite && create) flags |= _O_CREAT;
		if (forRead && forWrite && create && truncate) flags |= _O_TRUNC;
		// Open the file
		fd = _open(path.c_str(), flags, _S_IREAD | _S_IWRITE);
		if (fd == -1)
		{
			valid = false;
			return;
		}

		if (forRead && !forWrite) fileMode = "rb";
		if (!forRead && forWrite) fileMode = "wb";
		if (forRead && forWrite && !create) fileMode = "rb+";
		if (forRead && forWrite && create) fileMode = "wb+";
		// Open the stream
		valid = ((stream = _fdopen(fd, fileMode.c_str())) != NULL);
#endif
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

// Check if the file is empty
bool File::isEmpty()
{
#ifndef _WIN32
	struct stat s;

	if (fstat(fileno(stream), &s) != 0)
	{
		valid = false;

		return false;
	}

	return (s.st_size == 0);
#else
	struct _stat s;

	if (_fstat(_fileno(stream), &s) != 0)
	{
		valid = false;

		return false;
	}

	return (s.st_size == 0);
#endif
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

	if (len == 0)
	{
		return true;
	}

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

// Truncate the file
bool File::truncate()
{
	if (!valid) return false;

#ifndef _WIN32
	return (::ftruncate(fileno(stream), 0) == 0);
#else
	return (_chsize(fileno(stream), 0) == 0);
#endif
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
#ifndef _WIN32
	struct flock fl;
	fl.l_type = isWrite() ? F_WRLCK : F_RDLCK;
	fl.l_whence = SEEK_SET;
	fl.l_start = 0;
	fl.l_len = 0;
	fl.l_pid = 0;

	if (locked || !valid) return false;

	if (fcntl(fileno(stream), block ? F_SETLKW : F_SETLK, &fl) != 0)
	{
		ERROR_MSG("Could not lock the file: %s", strerror(errno));
		return false;
	}
#else
	HANDLE hFile;
	DWORD flags = 0;
	OVERLAPPED o;

	if (isWrite()) flags |= LOCKFILE_EXCLUSIVE_LOCK;
	if (!block) flags |= LOCKFILE_FAIL_IMMEDIATELY;

	if (locked || !valid) return false;

	hFile = (HANDLE) _get_osfhandle(_fileno(stream));
	if (hFile == INVALID_HANDLE_VALUE)
	{
		ERROR_MSG("Invalid handle");
		return false;
	}

	memset(&o, 0, sizeof(o));
	if (!LockFileEx(hFile, flags, 0, 1, 0, &o))
	{
		DWORD rv = GetLastError();

		ERROR_MSG("Could not lock the file: 0x%08x", rv);
		return false;
	}
#endif

	locked = true;

	return true;
}

// Unlock the file
bool File::unlock()
{
#ifndef _WIN32
	struct flock fl;
	fl.l_type = F_UNLCK;
	fl.l_whence = SEEK_SET;
	fl.l_start = 0;
	fl.l_len = 0;
	fl.l_pid = 0;

	if (!locked || !valid) return false;

	if (fcntl(fileno(stream), F_SETLK, &fl) != 0)
	{
		valid = false;

		ERROR_MSG("Could not unlock the file: %s", strerror(errno));
		return false;
	}
#else
	HANDLE hFile;
	OVERLAPPED o;

	if (!locked || !valid) return false;

	hFile = (HANDLE) _get_osfhandle(_fileno(stream));
	if (hFile == INVALID_HANDLE_VALUE)
	{
		ERROR_MSG("Invalid handle");
		return false;
	}

	memset(&o, 0, sizeof(o));
	if (!UnlockFileEx(hFile, 0, 1, 0, &o))
	{
		DWORD rv = GetLastError();

		valid = false;

		ERROR_MSG("Could not unlock the file: 0x%08x", rv);
		return  false;
	}
#endif
			

	locked = false;

	return valid;
}

// Flush the buffered stream to background storage
bool File::flush()
{
	return valid && !fflush(stream);
}

