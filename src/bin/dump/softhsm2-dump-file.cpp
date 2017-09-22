/*
 * Copyright (c) 2013 .SE (The Internet Infrastructure Foundation)
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
 softhsm2-dump-file.cpp

 This program can be used for dumping SoftHSM v2 object files.
 *****************************************************************************/

#include <config.h>

#include "common.h"

// Attribute types on disk
#define BOOLEAN_ATTR		0x1
#define ULONG_ATTR		0x2
#define BYTES_ATTR		0x3
#define ATTRMAP_ATTR		0x4
#define MECHSET_ATTR		0x5

// Maximum byte string length (1Gib)
#define MAX_BYTES		0x3fffffff

typedef AttributeTK<uint64_t, uint64_t, uint64_t> Attribute;

// Attribute specialization
template<>
bool Attribute::isBoolean() const
{
	return kind == BOOLEAN_ATTR;
}

template<>
bool Attribute::isInteger() const
{
	return kind == ULONG_ATTR;
}

template<>
bool Attribute::isBinary() const
{
	return kind == BYTES_ATTR;
}

template<>
bool Attribute::isMechSet() const
{
	return kind == MECHSET_ATTR;
}

template<>
void Attribute::dumpType() const
{
	dumpULong(type, true);
}

template<>
void Attribute::dumpKind() const
{
	dumpULong(kind, true);
}

template<>
void Attribute::dumpBoolValue() const
{
	dumpBool(boolValue, true);
}

template<>
void Attribute::dumpULongValue(uint64_t value) const
{
	dumpULong(value, true);
}

// dumpMap specialization
typedef std::vector<Attribute> va_type;

void dumpMap(const va_type& value)
{
	for (va_type::const_iterator attr = value.begin(); attr != value.end(); ++attr)
		attr->dump();
}

// Read a boolean (in fact unsigned 8 bit long) value
bool readBool(FILE* stream, uint8_t& value)
{
	value = 0;
	fpos_t pos;
	if (fgetpos(stream, &pos) != 0)
	{
		return false;
	}
	uint8_t v;
	if (fread(&v, 1, 1, stream) != 1)
	{
		(void) fsetpos(stream, &pos);
		return false;
	}
	value = v;
	return true;
}

// Read an unsigned 64 bit long value
bool readULong(FILE* stream, uint64_t& value)
{
	value = 0;
	fpos_t pos;
	if (fgetpos(stream, &pos) != 0)
	{
		return false;
	}
	uint8_t v[8];
	if (fread(v, 1, 8, stream) != 8)
	{
		(void) fsetpos(stream, &pos);
		return false;
	}
	for (size_t i = 0; i < 8; i++)
	{
		value <<= 8;
		value += v[i];
	}
	return true;
}

// Read a byte string (aka uint8_t vector) value
bool readBytes(FILE* stream, std::vector<uint8_t>& value)
{
	size_t len = value.size();
	fpos_t pos;
	if (fgetpos(stream, &pos) != 0)
	{
		return false;
	}
	if (fread(&value[0], 1, len, stream) != len)
	{
		(void) fsetpos(stream, &pos);
		return false;
	}
	return true;
}

// Read a map (aka Attribute vector) value
bool readMap(FILE* stream, uint64_t len, std::vector<Attribute>& value)
{
	fpos_t pos;
	if (fgetpos(stream, &pos) != 0)
	{
		return false;
	}
	while (len != 0)
	{
		Attribute attr;

		if (len < 8)
		{
			(void) fsetpos(stream, &pos);
			return false;
		}
		if (!readULong(stream, attr.type))
		{
			(void) fsetpos(stream, &pos);
			return false;
		}
		len -= 8;

		if (len < 8)
		{
			(void) fsetpos(stream, &pos);
			return false;
		}
		if (!readULong(stream, attr.kind))
		{
			(void) fsetpos(stream, &pos);
			return false;
		}
		len -= 8;

		if (attr.kind == BOOLEAN_ATTR)
		{
			if (len < 1)
			{
				(void) fsetpos(stream, &pos);
				return false;
			}
			len -= 1;
			if (!readBool(stream, attr.boolValue))
			{
				(void) fsetpos(stream, &pos);
				return false;
			}
		}
		else if (attr.kind == ULONG_ATTR)
		{
			if (len < 8)
			{
				(void) fsetpos(stream, &pos);
				return false;
			}
			if (!readULong(stream, attr.ulongValue))
			{
				(void) fsetpos(stream, &pos);
				return false;
			}
			len -= 8;
		}
		else if (attr.kind == BYTES_ATTR)
		{
			uint64_t size;
			if (len < 8)
			{
				(void) fsetpos(stream, &pos);
				return false;
			}
			if (!readULong(stream, size))
			{
				(void) fsetpos(stream, &pos);
				return false;
			}
			len -= 8;

			if (len < size)
			{
				(void) fsetpos(stream, &pos);
				return false;
			}
			attr.bytestrValue.resize((size_t)size);
			if (!readBytes(stream, attr.bytestrValue))
			{
				(void) fsetpos(stream, &pos);
				return false;
			}
			len -= size;
		}
		else if (attr.kind == MECHSET_ATTR)
		{
			uint64_t size;
			if (len < 8)
			{
				(void) fsetpos(stream, &pos);
				return false;
			}
			if (!readULong(stream, size))
			{
				(void) fsetpos(stream, &pos);
				return false;
			}
			len -= 8;

			if (len < size * 8)
			{
				(void) fsetpos(stream, &pos);
				return false;
			}

			for (unsigned long i = 0; i < size; i++)
			{
				uint64_t mech;
				if (!readULong(stream, mech))
				{
					(void) fsetpos(stream, &pos);
					return false;
				}
				attr.mechSetValue.insert(mech);
			}
			len -= size * 8;
		}
		else
		{
			(void) fsetpos(stream, &pos);
			return false;
		}

		value.push_back(attr);
	}

	return true;
}

// Error case
void corrupt(FILE* stream)
{
	uint8_t v;
	for (size_t i = 0; i < 8; i++)
	{
		if (fread(&v, 1, 1, stream) != 1)
		{
			if (ferror(stream))
			{
				printf("get an error...\n");
			}
			return;
		}
		if (i != 0)
		{
			printf(" ");
		}
		printf("%02hhx", v);
	}
	if (fread(&v, 1, 1, stream) != 1)
	{
		if (ferror(stream))
		{
			printf("\nget an error...\n");
		}
		return;
	}
	printf("...\n");
}

// Core function
void dump(FILE* stream)
{
	uint64_t gen;
	if (!readULong(stream, gen))
	{
		if (feof(stream))
		{
			printf("empty file\n");
		}
		else
		{
			corrupt(stream);
		}
		return;
	}
	dumpULong(gen);
	printf("generation %lu\n", (unsigned long) gen);

	while (!feof(stream))
	{
		uint64_t p11type;
		if (!readULong(stream, p11type))
		{
			corrupt(stream);
			return;
		}
		dumpULong(p11type);
		if ((uint64_t)((uint32_t)p11type) != p11type)
		{
			printf("overflow attribute type\n");
		}
		else
		{
			dumpCKA((unsigned long) p11type, 48);
			printf("\n");
		}

		uint64_t disktype;
		if (!readULong(stream, disktype))
		{
			corrupt(stream);
			return;
		}
		dumpULong(disktype);
		switch (disktype)
		{
		case BOOLEAN_ATTR:
			printf("boolean attribute\n");
			break;
		case ULONG_ATTR:
			printf("unsigned long attribute\n");
			break;
		case BYTES_ATTR:
			printf("byte string attribute\n");
			break;
		case ATTRMAP_ATTR:
			printf("attribute map attribute\n");
			break;
		case MECHSET_ATTR:
			printf("mechanism set attribute\n");
			break;
		default:
			printf("unknown attribute format\n");
			break;
		}

		if (disktype == BOOLEAN_ATTR)
		{
			uint8_t value;
			if (!readBool(stream, value))
			{
				corrupt(stream);
				return;
			}
			dumpBool(value);
			printf("\n");
		}
		else if (disktype == ULONG_ATTR)
		{
			uint64_t value;
			if (!readULong(stream, value))
			{
				corrupt(stream);
				return;
			}
			dumpULong(value);
			dumpCKx(p11type, value, 48);
			printf("\n");
		}
		else if (disktype == BYTES_ATTR)
		{
			uint64_t len;
			if (!readULong(stream, len))
			{
				corrupt(stream);
				return;
			}
			dumpULong(len);
			if (len > MAX_BYTES)
			{
				printf("overflow length...\n");
				return;
			}
			printf("(length %lu)\n", (unsigned long) len);

			std::vector<uint8_t> value((size_t) len);
			if (!readBytes(stream, value))
			{
				corrupt(stream);
				return;
			}
			dumpBytes(value);
		}
		else if (disktype == ATTRMAP_ATTR)
		{
			uint64_t len;
			if (!readULong(stream, len))
			{
				corrupt(stream);
				return;
			}
			dumpULong(len);
			if (len > MAX_BYTES)
			{
				printf("overflow length...\n");
				return;
			}
			printf("(length %lu)\n", (unsigned long) len);

			std::vector<Attribute> value;
			if (!readMap(stream, len, value))
			{
				corrupt(stream);
				return;
			}
			dumpMap(value);
		}
		else if (disktype == MECHSET_ATTR)
		{
			uint64_t len;
			if (!readULong(stream, len))
			{
				corrupt(stream);
				return;
			}
			dumpULong(len);
			if (len > MAX_BYTES)
			{
				printf("overflow length...\n");
				return;
			}
			printf("(length %lu)\n", (unsigned long) len);

			for (unsigned long i = 0; i < len; i++)
			{
				uint64_t mech;
				if (!readULong(stream, mech))
				{
					corrupt(stream);
					return;
				}
				dumpULong(mech);
				dumpCKM(mech, 48);
				printf("\n");
			}
		}
		else
		{
			corrupt(stream);
			return;
		}
	}
}

// Display the usage
void usage()
{
	printf("SoftHSM dump tool. From SoftHSM v2 object file.\n");
	printf("Usage: softhsm2-dump-file path\n");
}

// The main function
int main(int argc, char* argv[])
{
	FILE* stream;

	if (argc != 2)
	{
		usage();
		exit(0);
	}

	stream = fopen(argv[1], "r");
	if (stream == NULL)
	{
		fprintf(stderr, "can't open object file %s\n", argv[1]);
		exit(0);
	}

	printf("Dump of object file \"%s\"\n", argv[1]);
	dump(stream);
	exit(1);
}
