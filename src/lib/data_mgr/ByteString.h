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
 ByteString.h

 A string class for byte strings stored in securely allocated memory
 *****************************************************************************/

#ifndef _SOFTHSM_V2_BYTESTRING_H
#define _SOFTHSM_V2_BYTESTRING_H

#include <cstddef>
#include <vector>
#include <string>
#include <stdlib.h>
#include <limits.h>
#include "config.h"
#include "SecureAllocator.h"
#include "Serialisable.h"

#ifndef SIZE_T_MAX
#define SIZE_T_MAX ((size_t) -1)
#endif // !SIZE_T_MAX

class ByteString
{
public:
	// Constructors
	ByteString();

	ByteString(const unsigned char* bytes, const size_t bytesLen);

	ByteString(const char* hexString);

	ByteString(const unsigned long longValue);

	ByteString(const ByteString& in);

	// Destructor
	virtual ~ByteString() { }

	// Append data
	ByteString& operator+=(const ByteString& append);
	ByteString& operator+=(const unsigned char byte);

	// Return a substring
	ByteString substr(const size_t start, const size_t len = SIZE_T_MAX) const;

	// Array operator
	unsigned char& operator[](size_t pos);

	// Return the byte string
	unsigned char* byte_str();

	// Return the const byte string
	const unsigned char* const_byte_str() const;

	// Return a hexadecimal character representation of the string
	std::string hex_str() const;

	// Return the long value
	unsigned long long_val() const;

	// Cut of the first part of the string and convert it to a long value
	unsigned long firstLong();

	// Split of the specified part of the string as a separate byte string
	ByteString split(size_t len);

	// Return the size in bits
	size_t bits() const;

	// Return the size in bytes
	size_t size() const;

	// Resize
	void resize(const size_t newSize);

	// Wipe
	void wipe(const size_t newSize = 0);

	// Comparison
	bool operator==(const ByteString& compareTo) const;
	bool operator!=(const ByteString& compareTo) const;

	// XORing
	ByteString& operator^=(const ByteString& rhs);

	// Serialisation/deserialisation
	virtual ByteString serialise() const;

	static ByteString chainDeserialise(ByteString& serialised);

private:
	std::vector<unsigned char, SecureAllocator<unsigned char> > byteString;
};

// Add data
ByteString operator+(const ByteString& lhs, const ByteString& rhs);
ByteString operator+(const unsigned char lhs, const ByteString& rhs);
ByteString operator+(const ByteString& lhs, const unsigned char rhs);

// XOR data
ByteString operator^(const ByteString& lhs, const ByteString& rhs);

#endif // !_SOFTHSM_V2_BYTESTRING_H

