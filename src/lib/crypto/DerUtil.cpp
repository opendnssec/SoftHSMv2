/*
 * Copyright (c) 2018 SURFnet bv
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
 DerUtil.h

 DER encoding convenience functions
 *****************************************************************************/

#include "config.h"
#include "DerUtil.h"

// Convert a raw ByteString to a DER encoded octet string
ByteString DERUTIL::raw2Octet(const ByteString& byteString)
{
	ByteString header;
	size_t len = byteString.size();

	// Definite, short
	if (len < 0x80)
 	{
		header.resize(2);
		header[0] = (unsigned char)0x04;
		header[1] = (unsigned char)(len & 0x7F);
	}
	// Definite, long
	else
	{
		// Count significate bytes
		size_t bytes = sizeof(size_t);
		for(; bytes > 0; bytes--)
		{
			size_t value = len >> ((bytes - 1) * 8);
			if (value & 0xFF) break;
		}

		// Set header data
		header.resize(2 + bytes);
		header[0] = (unsigned char)0x04;
		header[1] = (unsigned char)(0x80 | bytes);
		for (size_t i = 1; i <= bytes; i++)
		{
			header[2+bytes-i] = (unsigned char) (len & 0xFF);
			len >>= 8;
		}
	}

	return header + byteString;
}

// Convert a DER encoded octet string to a raw ByteString
ByteString DERUTIL::octet2Raw(const ByteString& byteString)
{
	ByteString rv;
	ByteString repr = byteString;
	size_t len = repr.size();
	size_t controlOctets = 2;

	if (len < controlOctets)
	{
		ERROR_MSG("Undersized octet string");

		return rv;
	}

	if (repr[0] != 0x04)
	{
		ERROR_MSG("ByteString is not an octet string");

		return rv;
	}

	// Definite, short
	if (repr[1] < 0x80)
	{
		if (repr[1] != (len - controlOctets))
		{
			if (repr[1] < (len - controlOctets))
			{
				ERROR_MSG("Underrun octet string");
			}
			else
			{
				ERROR_MSG("Overrun octet string");
			}

			return rv;
		}
	}
	// Definite, long
	else
	{
		size_t lengthOctets = repr[1] & 0x7f;
		controlOctets += lengthOctets;

		if (controlOctets >= repr.size())
		{
			ERROR_MSG("Undersized octet string");

			return rv;
		}

		ByteString length(&repr[2], lengthOctets);

		if (length.long_val() != (len - controlOctets))
                {
			if (length.long_val() < (len - controlOctets))
			{
				ERROR_MSG("Underrun octet string");
			}
			else
			{
				ERROR_MSG("Overrun octet string");
			}

			return rv;
		}
	}

	return repr.substr(controlOctets, len - controlOctets);
}

